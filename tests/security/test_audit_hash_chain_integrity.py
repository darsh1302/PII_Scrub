"""Guardrail G20, Property 13 — audit durability and tamper evidence.

The reviewed design kept audit records in st.session_state: an in-memory list
destroyed on browser refresh. These tests hold the sink to the stronger contract
in Requirement 41 — durable across process restart, hash-chained, and incapable
of carrying entity values.
"""

from __future__ import annotations

import json

import pytest

from session.audit_sink import GENESIS_HASH, AuditIntegrityError, AuditSink


def _record(request_id: str, **extra) -> dict:
    """A representative PII-free audit record."""
    base = {
        "request_id": request_id,
        "source_type": "FILE",
        "source_identifier_hash": "e91f" + "0" * 60,
        "profile": "DEFAULT_PII",
        "profile_version": "1.0.0",
        "entity_counts": {"US_SSN": 3, "PERSON": 11},
        "actions_applied": {"REDACT": 3, "REPLACE": 11},
        "coverage_complete": True,
        "verified_clean": True,
        "success": True,
    }
    base.update(extra)
    return base


def test_chain_links_records_in_order(tmp_path):
    sink = AuditSink(tmp_path / "audit")
    h1 = sink.append(_record("r1"))
    h2 = sink.append(_record("r2"))
    h3 = sink.append(_record("r3"))

    records = list(sink.read_all())
    assert [r["request_id"] for r in records] == ["r1", "r2", "r3"]
    assert records[0]["prev_hash"] == GENESIS_HASH
    assert records[1]["prev_hash"] == h1
    assert records[2]["prev_hash"] == h2
    assert records[2]["record_hash"] == h3

    ok, bad = sink.verify_chain()
    assert ok is True
    assert bad is None


def test_tampering_with_a_record_is_detected_and_localised(tmp_path):
    """Editing a historical record in place must be detectable."""
    audit_dir = tmp_path / "audit"
    sink = AuditSink(audit_dir)
    sink.append(_record("r1"))
    sink.append(_record("r2"))
    sink.append(_record("r3"))

    assert sink.verify_chain() == (True, None)

    # Rewrite r2 as if the scan had found nothing.
    path = next(audit_dir.glob("audit-*.jsonl"))
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    tampered = json.loads(lines[1])
    tampered["entity_counts"] = {}
    tampered["verified_clean"] = True
    lines[1] = json.dumps(tampered, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, bad = sink.verify_chain()
    assert ok is False
    assert bad == "r2"


def test_deleting_a_record_breaks_the_chain(tmp_path):
    """Removing a record must not go unnoticed."""
    audit_dir = tmp_path / "audit"
    sink = AuditSink(audit_dir)
    sink.append(_record("r1"))
    sink.append(_record("r2"))
    sink.append(_record("r3"))

    path = next(audit_dir.glob("audit-*.jsonl"))
    lines = path.read_text(encoding="utf-8").strip().split("\n")
    del lines[1]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok, bad = sink.verify_chain()
    assert ok is False
    assert bad == "r3"  # first record whose prev_hash no longer matches


def test_chain_survives_process_restart(tmp_path):
    """A new sink instance must continue the existing chain, not restart it."""
    audit_dir = tmp_path / "audit"

    first = AuditSink(audit_dir)
    h1 = first.append(_record("r1"))
    del first

    second = AuditSink(audit_dir)
    second.append(_record("r2"))

    records = list(second.read_all())
    assert len(records) == 2
    assert records[1]["prev_hash"] == h1
    assert second.verify_chain() == (True, None)


@pytest.mark.parametrize(
    "forbidden",
    [
        {"text": "123-45-6789"},
        {"content": "raw log content"},
        {"matched_text": "alice@example.com"},
        {"source_identifier": "C:/logs/app.log"},
        {"sanitized": "cleaned output"},
        {"excerpt": "ERROR user 123-45-6789"},
    ],
)
def test_records_carrying_sensitive_fields_are_rejected(tmp_path, forbidden):
    """Reject at write time — a silent leak here would be permanent."""
    sink = AuditSink(tmp_path / "audit")
    with pytest.raises(AuditIntegrityError):
        sink.append(_record("r1", **forbidden))


def test_nested_sensitive_fields_are_rejected(tmp_path):
    """The check must recurse — nesting is the obvious way to slip past it."""
    sink = AuditSink(tmp_path / "audit")
    with pytest.raises(AuditIntegrityError):
        sink.append(_record("r1", details={"entity": {"text": "123-45-6789"}}))

    with pytest.raises(AuditIntegrityError):
        sink.append(_record("r1", entities=[{"type": "US_SSN", "text": "1"}]))


def test_rejected_record_is_not_written(tmp_path):
    """A rejected record must leave no trace and must not advance the chain."""
    audit_dir = tmp_path / "audit"
    sink = AuditSink(audit_dir)
    sink.append(_record("good"))

    with pytest.raises(AuditIntegrityError):
        sink.append(_record("bad", text="123-45-6789"))

    assert sink.count() == 1
    assert sink.verify_chain() == (True, None)


def test_export_returns_full_trail(tmp_path):
    sink = AuditSink(tmp_path / "audit")
    sink.append(_record("r1"))
    sink.append(_record("r2"))

    exported = sink.export()
    assert exported.count("\n") == 1
    assert "r1" in exported and "r2" in exported
