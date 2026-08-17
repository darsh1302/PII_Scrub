"""Guardrails G6, G7, G19 — the three fail-closed gates.

Addresses review findings SEC-05, SEC-02, COR-01, COR-05.

The reviewed design produced sanitized output even when detection had degraded,
handing the user a file labelled clean that was never fully inspected. A scrubber
that silently under-detects is more dangerous than no scrubber, because it
manufactures confidence.

Every test here asserts the same shape: findings stay reportable, the artifact is
withheld, and the reason is explained.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.detector import DetectorUnavailable
from core.file_source import load_text
from core.pipeline import ScanOptions, scan, scan_and_scrub
from core.profile_resolver import resolve_profile
from models.enums import Destination, RefusalReason, ScrubAction
from session.context import get_session_context
from utils.config import Settings

FIXTURES = Path(__file__).parent.parent / "fixtures"


@pytest.fixture
def session(tmp_path):
    settings = Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"test-salt",
        scan_roots=(FIXTURES.resolve(),),
        audit_dir=tmp_path / "audit",
    )
    return get_session_context("fail-closed-test", settings)


FILE_DEST = ScanOptions(destination=Destination.FILE)


# ---------------------------------------------------------------------------
# GATE 1 — coverage completeness (G6)
# ---------------------------------------------------------------------------


def test_missing_required_detector_withholds_the_artifact(session, monkeypatch):
    """The exact case the original design let through."""
    def boom():
        raise DetectorUnavailable("spaCy model not installed")

    monkeypatch.setattr("core.detector.get_spacy", boom)

    loaded = load_text("patient Jane Fairweather ssn=482-71-9053", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is RefusalReason.DEGRADED_COVERAGE
    assert result.artifact_available is False
    assert result.sanitized_handle is None
    # Findings remain reportable.
    assert result.entity_count > 0
    assert result.unverified is True


def test_degraded_coverage_explains_why_withholding_protects_the_user(
    session, monkeypatch
):
    def boom():
        raise DetectorUnavailable("spaCy model not installed")

    monkeypatch.setattr("core.detector.get_spacy", boom)

    loaded = load_text("patient Jane Fairweather ssn=482-71-9053", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    detail = result.refusal_detail
    assert "UNVERIFIED" in detail
    assert "withheld" in detail
    assert "spacy" in detail


def test_recognizer_failure_withholds_the_artifact(session, monkeypatch):
    class Exploding:
        def analyze(self, **_kwargs):
            raise RuntimeError("recognizer exploded")

    monkeypatch.setattr("core.detector.get_analyzer", lambda: Exploding())

    loaded = load_text("ssn=482-71-9053", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is RefusalReason.DEGRADED_COVERAGE
    assert result.artifact_available is False


# Chunk size is floored relative to the profile's overlap (10240 for
# DEFAULT_PII, driven by the PEM recognizer), so chunks are 40960 bytes and a
# truncation budget only bites on content large enough to produce several.
#
# 1800 lines gives ~72,000 chars: comfortably above one chunk, comfortably below
# MAX_TEXT_LENGTH_CHARS (100,000). Both bounds matter — too small and no
# truncation occurs, too large and the refusal under test becomes the
# input-size limit rather than the coverage gate.
_MULTI_CHUNK_LINES = 1800

# The budget is checked *before* each chunk, so at least one chunk always runs
# and the processed total may overshoot. That is deliberate: a budget smaller
# than one chunk should still yield some coverage rather than none. It does mean
# the budget has to sit below one chunk size (40960) to trip at all — 45,000
# would let both chunks through and truncate nothing.
_TRUNCATION_BUDGET_BYTES = 20_000


def _multi_chunk_text() -> str:
    """Multi-chunk content with sparse PII.

    These tests need enough *bytes* to produce several chunks, not thousands of
    detections. Detection cost scales with entity count, and an SSN on every
    line made these three tests 110 of the suite's 136 seconds. One SSN per 100
    lines gives the same byte count, the same chunk count, and the same
    behaviour under test at a fraction of the cost.
    """
    lines = []
    for i in range(_MULTI_CHUNK_LINES):
        if i % 100 == 0:
            lines.append(f"line {i:05d} ERROR lookup failed ssn=482-71-9053")
        else:
            lines.append(f"line {i:05d} INFO request handled in {i % 90 + 4}ms")
    return "\n".join(lines)


def test_truncated_scan_without_approval_withholds_the_artifact(session):
    """COR-01 — a partial scan must never yield a 'clean' file."""
    loaded = load_text(_multi_chunk_text(), session)

    result = scan_and_scrub(
        loaded.handle,
        session,
        ScanOptions(
            destination=Destination.FILE, max_bytes=_TRUNCATION_BUDGET_BYTES
        ),
    )

    assert result.coverage.bytes_processed < result.coverage.bytes_total, (
        "test setup must actually truncate"
    )
    assert result.refusal is RefusalReason.DEGRADED_COVERAGE
    assert result.coverage.aborted is True
    assert result.artifact_available is False


def test_approved_truncation_reports_findings_but_still_withholds_the_artifact(
    session,
):
    """A partial scan can never yield a verified-clean artifact.

    Discovered during implementation: with a 45 KB budget over an 86 KB source,
    the applier scrubbed the inspected region and left 166 live SSNs in the
    uninspected tail. Verification caught it, but the coverage gate is the right
    place to refuse — relying on gate 3 to catch a gate 1 error is not a design.

    Approving truncation therefore changes the *explanation*, not the outcome:
    the scan was intentional rather than degraded, and findings remain
    reportable, but no cleaned copy is produced.
    """
    loaded = load_text(_multi_chunk_text(), session)

    result = scan_and_scrub(
        loaded.handle,
        session,
        ScanOptions(
            destination=Destination.FILE,
            max_bytes=_TRUNCATION_BUDGET_BYTES,
            truncation_approved=True,
        ),
    )

    assert result.coverage.aborted is False
    assert result.coverage.truncation_was_intentional is True
    assert result.refusal is RefusalReason.DEGRADED_COVERAGE
    assert result.artifact_available is False
    # Findings from the inspected region remain useful.
    assert result.entity_count > 0
    assert result.coverage.scan_is_reportable() is True


def test_approved_truncation_explains_why_no_artifact_is_possible(session):
    """The message must distinguish intent from failure."""
    loaded = load_text(_multi_chunk_text(), session)

    result = scan_and_scrub(
        loaded.handle,
        session,
        ScanOptions(
            destination=Destination.FILE,
            max_bytes=_TRUNCATION_BUDGET_BYTES,
            truncation_approved=True,
        ),
    )

    detail = result.refusal_detail
    assert "You asked me to scan only part" in detail
    assert "leave live values in the region I did not" in detail


def test_complete_coverage_permits_an_artifact(session):
    loaded = load_text("ssn=482-71-9053 and card 4532015112830366", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is None
    assert result.coverage.is_complete() is True
    assert result.artifact_available is True


# ---------------------------------------------------------------------------
# GATE 2 — BLOCK suppresses the artifact (G19)
# ---------------------------------------------------------------------------


def test_block_decision_produces_no_artifact(session, monkeypatch):
    """BLOCK must be observably different from REDACT."""
    from core.profile_resolver import EffectiveProfile

    original = EffectiveProfile.action_for

    def blocking(self, entity_type, destination=None):
        if entity_type.upper() == "US_SSN":
            return ScrubAction.BLOCK
        return original(self, entity_type, destination)

    monkeypatch.setattr(EffectiveProfile, "action_for", blocking)

    loaded = load_text("patient ssn=482-71-9053", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is RefusalReason.BLOCKED_ARTIFACT
    assert result.sanitized_handle is None
    assert "US_SSN" in result.refusal_detail
    # Findings still reported.
    assert result.entity_count > 0


def test_block_refusal_explains_the_policy_reason(session, monkeypatch):
    from core.profile_resolver import EffectiveProfile

    original = EffectiveProfile.action_for

    def blocking(self, entity_type, destination=None):
        if entity_type.upper() == "US_SSN":
            return ScrubAction.BLOCK
        return original(self, entity_type, destination)

    monkeypatch.setattr(EffectiveProfile, "action_for", blocking)

    loaded = load_text("patient ssn=482-71-9053", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert "must not be retained in any form" in result.refusal_detail


# ---------------------------------------------------------------------------
# GATE 3 — verification re-scan (G7)
# ---------------------------------------------------------------------------


def test_verification_catches_a_skipped_replacement(session, monkeypatch):
    """Simulates the SEC-02 failure: an entity the applier missed."""
    import core.applier as applier_module

    real_apply = applier_module.apply_decisions

    def sabotaged(content, decisions, vault):
        # Drop the first actionable decision, as a stale offset would.
        actionable = decisions.actionable()
        if actionable:
            decisions.decisions.remove(actionable[0])
        return real_apply(content, decisions, vault)

    monkeypatch.setattr("core.pipeline.apply_decisions", sabotaged)

    loaded = load_text("patient ssn=482-71-9053 end", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is RefusalReason.RESIDUAL_PII_DETECTED
    assert result.sanitized_handle is None
    assert result.verified_clean is False


def test_residual_refusal_is_described_as_a_pipeline_defect(session, monkeypatch):
    """The user did nothing wrong; the message should say so."""
    import core.applier as applier_module

    real_apply = applier_module.apply_decisions

    def sabotaged(content, decisions, vault):
        actionable = decisions.actionable()
        if actionable:
            decisions.decisions.remove(actionable[0])
        return real_apply(content, decisions, vault)

    monkeypatch.setattr("core.pipeline.apply_decisions", sabotaged)

    loaded = load_text("patient ssn=482-71-9053 end", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert "defect in the scrub pipeline" in result.refusal_detail
    assert "not a problem with your input" in result.refusal_detail


def test_policy_allowed_entities_do_not_count_as_residual(session):
    """Verification must not flag its own correct behaviour.

    An IP kept for internal SIEM correlation legitimately remains. Without the
    allowance, verification would refuse every artifact containing an ALLOW.
    """
    loaded = load_text("request from 203.0.113.42 handled", session)
    result = scan_and_scrub(
        loaded.handle,
        session,
        ScanOptions(destination=Destination.INTERNAL_SIEM),
    )

    assert result.refusal is None
    assert result.verified_clean is True
    output = session.content_store.get(result.sanitized_handle).content
    assert "203.0.113.42" in output


def test_exempt_log_timestamps_do_not_count_as_residual(session):
    """The same allowance, for field-context exemptions."""
    text = "\n".join(
        f"2026-08-16T09:{i:02d}:00Z INFO request {i} ok" for i in range(30)
    )
    loaded = load_text(text, session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is None
    output = session.content_store.get(result.sanitized_handle).content
    assert "2026-08-16T09:00:00Z" in output


def test_replacement_markers_do_not_count_as_residual(session):
    """[US_SSN] must not be re-detected as PII."""
    loaded = load_text(
        "ssn=482-71-9053 email alice@example.com card 4532015112830366", session
    )
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.verified_clean is True


# ---------------------------------------------------------------------------
# Refusal contract
# ---------------------------------------------------------------------------


def test_every_refusal_withholds_the_artifact_but_keeps_findings(
    session, monkeypatch
):
    """The invariant across all three gates."""
    def boom():
        raise DetectorUnavailable("model missing")

    monkeypatch.setattr("core.detector.get_spacy", boom)

    loaded = load_text("patient Jane ssn=482-71-9053", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.is_refusal is True
    assert result.artifact_available is False
    assert result.entity_count > 0
    assert result.status != "OK"


def test_refusal_reasons_are_mutually_distinguishable():
    """A UI cannot explain refusals it cannot tell apart."""
    values = [r.value for r in RefusalReason]
    assert len(values) == len(set(values))
    for reason in RefusalReason:
        assert len(reason.user_message) > 20


def test_dry_run_produces_no_artifact_but_full_decisions(session):
    """Requirement 68 — preview without modifying anything."""
    loaded = load_text("ssn=482-71-9053 ip 203.0.113.42", session)
    result = scan_and_scrub(
        loaded.handle, session, ScanOptions(dry_run=True)
    )

    assert result.sanitized_handle is None
    assert result.entity_count > 0
    assert len(result.decisions) > 0


# ---------------------------------------------------------------------------
# Audit integration (G20)
# ---------------------------------------------------------------------------


def test_every_run_writes_exactly_one_audit_record(session):
    before = session.audit_sink.count()
    loaded = load_text("ssn=482-71-9053", session)
    scan_and_scrub(loaded.handle, session, FILE_DEST)
    assert session.audit_sink.count() == before + 1


def test_refusals_are_audited_too(session, monkeypatch):
    def boom():
        raise DetectorUnavailable("model missing")

    monkeypatch.setattr("core.detector.get_spacy", boom)

    before = session.audit_sink.count()
    loaded = load_text("patient Jane ssn=482-71-9053", session)
    scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert session.audit_sink.count() == before + 1
    ok, bad = session.audit_sink.verify_chain()
    assert ok is True and bad is None


def test_audit_record_contains_no_entity_values(session):
    loaded = load_text("patient ssn=482-71-9053 card 4532015112830366", session)
    scan_and_scrub(loaded.handle, session, FILE_DEST)

    trail = session.audit_sink.export()
    assert "482-71-9053" not in trail
    assert "4532015112830366" not in trail
    # But the counts are there.
    assert "US_SSN" in trail


def test_audit_records_engine_and_profile_versions(session):
    """OPS-02 — a result must be reproducible later."""
    loaded = load_text("ssn=482-71-9053", session)
    scan_and_scrub(loaded.handle, session, FILE_DEST)

    latest = list(session.audit_sink.read_all())[-1]
    assert latest["profile_version"] == "1.0.0"
    assert latest["engine_versions"]["spacy_model"] == "3.8.0"
