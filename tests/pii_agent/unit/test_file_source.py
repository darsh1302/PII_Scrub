"""File source adapter — ingestion into the ContentStore.

The key property: loading returns a handle and metadata, never content
(guardrail G1). Metadata describes the file; it does not quote it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pii_agent.core.file_source import load_file, load_text, load_upload
from pii_agent.models.enums import SourceType
from pii_agent.session.context import get_session_context
from pii_agent.utils.config import Settings
from pii_agent.utils.paths import PathRefused

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def session(tmp_path):
    root = tmp_path / "scanroot"
    root.mkdir()
    settings = Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"salt",
        scan_roots=(root.resolve(),),
        audit_dir=tmp_path / "audit",
    )
    ctx = get_session_context("test-session", settings)
    return ctx, root


def _copy_fixture(name: str, root: Path) -> Path:
    target = root / name
    target.write_bytes((FIXTURES / name).read_bytes())
    return target


# ---------------------------------------------------------------------------
# Content containment
# ---------------------------------------------------------------------------


def test_load_returns_handle_not_content(session):
    ctx, root = session
    _copy_fixture("sample_log.txt", root)

    loaded = load_file(str(root / "sample_log.txt"), ctx)

    assert loaded.handle
    assert not hasattr(loaded, "content")
    # Content is retrievable only through the session's own store.
    assert "482-71-9053" in ctx.content_store.get(loaded.handle).content


def test_metadata_describes_the_file_without_quoting_it(session):
    """Metadata goes to the reasoning context, so it must carry no PII."""
    ctx, root = session
    _copy_fixture("sample_log.txt", root)

    loaded = load_file(str(root / "sample_log.txt"), ctx)
    rendered = str(loaded.to_metadata())

    assert "482-71-9053" not in rendered
    assert "alice.morgan@example.com" not in rendered
    assert loaded.to_metadata()["name"] == "sample_log.txt"
    assert loaded.to_metadata()["lines"] > 10


def test_handle_is_session_namespaced(session):
    ctx, root = session
    _copy_fixture("sample_log.txt", root)
    loaded = load_file(str(root / "sample_log.txt"), ctx)
    assert loaded.handle.startswith(ctx.content_store.namespace)


# ---------------------------------------------------------------------------
# Structured parsing integration
# ---------------------------------------------------------------------------


def test_json_is_parsed_into_field_paths(session):
    ctx, root = session
    _copy_fixture("sample_pii.json", root)

    loaded = load_file(str(root / "sample_pii.json"), ctx)

    assert loaded.structured is True
    assert loaded.parsed_field_count > 10
    stored = ctx.content_store.get(loaded.handle).content
    # Field paths become detection context.
    assert "user.ssn" in stored
    assert "config.api_key" in stored


def test_csv_is_parsed_with_header_context(session):
    ctx, root = session
    _copy_fixture("sample_healthcare.csv", root)

    loaded = load_file(str(root / "sample_healthcare.csv"), ctx)

    assert loaded.structured is True
    stored = ctx.content_store.get(loaded.handle).content
    assert "mrn" in stored


def test_unparseable_structured_file_falls_back_with_a_warning(session):
    """Losing field context is acceptable; losing coverage is not."""
    ctx, root = session
    broken = root / "broken.json"
    broken.write_text('{"ssn": "482-71-9053"', encoding="utf-8")

    loaded = load_file(str(broken), ctx)

    assert loaded.structured is False
    assert any("plain text" in w for w in loaded.warnings)
    assert "482-71-9053" in ctx.content_store.get(loaded.handle).content


def test_xxe_file_is_scanned_as_text_not_expanded(session):
    """Parsing is refused, but the literal text is still scanned."""
    ctx, root = session
    _copy_fixture("sample_xxe.xml", root)

    loaded = load_file(str(root / "sample_xxe.xml"), ctx)

    assert loaded.structured is False
    stored = ctx.content_store.get(loaded.handle).content
    assert "Jane Fairweather" in stored
    # The entity must not have been resolved.
    assert "OPENAI_API_KEY" not in stored


def test_plain_log_is_not_treated_as_structured(session):
    ctx, root = session
    _copy_fixture("sample_log.txt", root)
    loaded = load_file(str(root / "sample_log.txt"), ctx)
    assert loaded.structured is False
    assert loaded.warnings == []


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------


def test_invalid_utf8_is_decoded_with_substitutions_and_reported(session):
    """Damaged logs are exactly where accidental secrets end up."""
    ctx, root = session
    target = root / "mixed.log"
    target.write_bytes(b"valid line\n\xff\xfe broken bytes\nssn 482-71-9053\n")

    loaded = load_file(str(target), ctx)

    assert loaded.decode_substitutions > 0
    assert any("could not be decoded" in w for w in loaded.warnings)
    # Scanning continued over the rest.
    assert "482-71-9053" in ctx.content_store.get(loaded.handle).content


# ---------------------------------------------------------------------------
# Uploads and pasted text
# ---------------------------------------------------------------------------


def test_upload_bypasses_scan_roots_but_not_type_limits(session):
    """There is no filesystem to escape when the user supplies the bytes."""
    ctx, _ = session
    loaded = load_upload(b"ssn 482-71-9053\n", "notes.log", ctx)
    assert loaded.source_type is SourceType.FILE
    assert "482-71-9053" in ctx.content_store.get(loaded.handle).content


def test_upload_rejects_unsupported_type(session):
    ctx, _ = session
    with pytest.raises(PathRefused) as exc:
        load_upload(b"MZ\x90", "payload.exe", ctx)
    assert "unsupported file type" in str(exc.value)


def test_upload_rejects_oversize(session):
    ctx, _ = session
    from pii_agent.utils.config import MAX_FILE_SIZE_MB

    oversize = b"x" * (MAX_FILE_SIZE_MB * 1024 * 1024 + 1)
    with pytest.raises(PathRefused) as exc:
        load_upload(oversize, "big.log", ctx)
    assert "over the" in str(exc.value)


def test_pasted_text_is_stored_as_text_source(session):
    ctx, _ = session
    loaded = load_text("my ssn is 482-71-9053", ctx)
    assert loaded.source_type is SourceType.TEXT
    assert loaded.display_name == "pasted text"


def test_pasted_text_over_limit_is_refused(session):
    ctx, _ = session
    from pii_agent.utils.config import MAX_TEXT_LENGTH_CHARS

    with pytest.raises(PathRefused) as exc:
        load_text("x" * (MAX_TEXT_LENGTH_CHARS + 1), ctx)
    assert "over the" in str(exc.value)


# ---------------------------------------------------------------------------
# Sandbox integration
# ---------------------------------------------------------------------------


def test_load_file_refuses_path_outside_scan_root(session, tmp_path):
    ctx, _ = session
    outside = tmp_path / "elsewhere.log"
    outside.write_text("secret", encoding="utf-8")
    with pytest.raises(PathRefused):
        load_file(str(outside), ctx)


def test_load_file_refuses_denylisted_name(session):
    ctx, root = session
    target = root / ".env"
    target.write_text("OPENAI_API_KEY=sk-real", encoding="utf-8")
    with pytest.raises(PathRefused):
        load_file(str(target), ctx)


# ---------------------------------------------------------------------------
# Reaching an upload by name
# ---------------------------------------------------------------------------
# Regression: an uploaded file was unreachable from the agent. The upload itself
# worked, but the agent is told the display name rather than the opaque handle,
# and a name with no path inside a scan root fell through to the filesystem
# loader and was refused for being outside the sandbox. The user saw "not
# available in the configured scan roots" for a file they had just uploaded.
def test_upload_is_resolvable_by_its_display_name(session):
    ctx, _ = session
    loaded = load_upload(b"ssn 482-71-9053\n", "uploaded.log", ctx)

    found = ctx.content_store.find_by_label("uploaded.log")
    assert found is not None
    assert found.handle == loaded.handle


def test_label_lookup_is_case_insensitive(session):
    ctx, _ = session
    loaded = load_upload(b"ssn 482-71-9053\n", "Uploaded.LOG", ctx)
    found = ctx.content_store.find_by_label("uploaded.log")
    assert found is not None and found.handle == loaded.handle


def test_label_lookup_ignores_unknown_names(session):
    ctx, _ = session
    load_upload(b"ssn 482-71-9053\n", "uploaded.log", ctx)
    assert ctx.content_store.find_by_label("other.log") is None
    assert ctx.content_store.find_by_label("  ") is None


def test_pasted_text_is_resolvable_by_label(session):
    ctx, _ = session
    loaded = load_text("ssn 482-71-9053", ctx, label="pasted text")
    found = ctx.content_store.find_by_label("pasted text")
    assert found is not None and found.handle == loaded.handle


def test_most_recent_upload_of_a_name_wins(session):
    ctx, _ = session
    load_upload(b"first 482-71-9053\n", "same.log", ctx)
    second = load_upload(b"second 517-38-2094\n", "same.log", ctx)
    found = ctx.content_store.find_by_label("same.log")
    assert found is not None and found.handle == second.handle


def test_loaded_sources_lists_uploads(session):
    ctx, _ = session
    load_upload(b"a 482-71-9053\n", "one.log", ctx)
    load_upload(b"b 517-38-2094\n", "two.log", ctx)
    names = [
        r.metadata.get("display_name") for r in ctx.content_store.loaded_sources()
    ]
    assert names == ["one.log", "two.log"]



def test_label_lookup_skips_sanitized_output(session):
    """Scanning "x.log" means the original, not a cleaned copy derived from it."""
    ctx, _ = session
    loaded = load_upload(b"ssn 482-71-9053\n", "same.log", ctx)
    record = ctx.content_store.get(loaded.handle)

    sanitized = ctx.content_store.put_sanitized("ssn [US_SSN]\n", record)
    ctx.content_store.get(sanitized).metadata["display_name"] = "same.log"

    found = ctx.content_store.find_by_label("same.log")
    assert found is not None
    assert found.handle == loaded.handle
