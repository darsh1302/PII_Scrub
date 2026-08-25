"""PHASE 4 MILESTONE — the deterministic core is correct and safe with no LLM.

This is the hard gate from the revised implementation plan. Nothing in Phase 5
onward may be started until it passes.

The claim being tested is architectural, not behavioural: the scrub pipeline
must be *incapable* of depending on a language model. The reviewed design placed
the reasoning loop inside the data and policy path, which produced five of the
six blocker findings. Proving the core stands alone is what makes the agent an
interface over something trustworthy rather than a component the security model
depends on.

``sys.modules`` inspection is the assertion mechanism. A comment saying "no LLM
here" decays; an import check does not.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pii_agent.core.file_source import load_file, load_text
from pii_agent.core.pipeline import ScanOptions, scan, scan_and_scrub
from pii_agent.models.enums import Destination, RefusalReason, ScrubAction
from pii_agent.session.context import get_session_context
from pii_agent.utils.config import Settings

from tests.paths import REPO_ROOT

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Modules that would indicate an LLM in the call path.
LLM_MODULE_PREFIXES = (
    "langgraph",
    "langchain",
    "langchain_openai",
    "langchain_core",
    "openai",
    "tiktoken",
)


@pytest.fixture
def session(tmp_path):
    settings = Settings(
        openai_api_key="",  # deliberately absent — the core must not need it
        token_vault_salt=b"milestone-salt",
        scan_roots=(FIXTURES.resolve(),),
        audit_dir=tmp_path / "audit",
    )
    return get_session_context("milestone", settings)


FILE_DEST = ScanOptions(destination=Destination.FILE)


def _llm_modules_loaded() -> set[str]:
    return {
        name
        for name in sys.modules
        if any(
            name == prefix or name.startswith(prefix + ".")
            for prefix in LLM_MODULE_PREFIXES
        )
    }


# ---------------------------------------------------------------------------
# The architectural assertion
# ---------------------------------------------------------------------------


def test_core_modules_import_no_llm_dependency():
    """Importing the whole core must not pull in an LLM library.

    Run in a subprocess so earlier tests in the session cannot pollute the
    module table.
    """
    import subprocess
    import textwrap

    # One module per line, deliberately. A comma-separated import list is easy to
    # rename incompletely — during the pii_agent package move exactly that
    # happened, leaving the first module renamed and the rest not, so the test
    # failed loudly rather than silently asserting nothing. Keep it verbose.
    script = textwrap.dedent(
        """
        import sys
        import pii_agent.core.pipeline
        import pii_agent.core.policy
        import pii_agent.core.applier
        import pii_agent.core.verifier
        import pii_agent.core.detector
        import pii_agent.core.reconciler
        import pii_agent.core.chunker
        import pii_agent.core.file_source
        import pii_agent.core.profile_resolver
        import pii_agent.core.recognizers
        import pii_agent.core.injection_scan
        import pii_agent.core.financial_recognizers
        import pii_agent.core.ai_recognizers

        prefixes = ("langgraph", "langchain", "openai", "tiktoken")
        found = sorted(
            n for n in sys.modules
            if any(n == p or n.startswith(p + ".") for p in prefixes)
        )
        print("LEAKED:" + ",".join(found))
        """
    )
    completed = subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert completed.returncode == 0, completed.stderr
    leaked = [
        line for line in completed.stdout.splitlines() if line.startswith("LEAKED:")
    ][0][len("LEAKED:") :]
    assert leaked == "", f"core imported LLM modules: {leaked}"


def test_pipeline_runs_with_no_openai_key_configured(session):
    """The core must not require the credential the agent needs."""
    assert session.settings.openai_api_key == ""

    loaded = load_text("patient ssn=482-71-9053 card 4532015112830366", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.status == "OK"
    assert result.verified_clean is True


# ---------------------------------------------------------------------------
# End-to-end over every fixture
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture",
    [
        "sample_log.txt",
        "sample_clean.txt",
        "sample_pii.json",
        "sample_healthcare.csv",
        "sample_adversarial.txt",
        "sample_pem_straddle.txt",
    ],
)
def test_every_fixture_completes_without_error(session, fixture):
    """Whatever the outcome, the pipeline must reach a defined state."""
    loaded = load_file(str(FIXTURES / fixture), session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.status in {"OK", *[r.value for r in RefusalReason]}
    assert result.coverage.bytes_total > 0
    # Artifact and verification agree in every case.
    assert result.artifact_available == (
        result.verified_clean and result.sanitized_handle is not None
    )


def test_sample_log_is_scrubbed_and_verified(session):
    loaded = load_file(str(FIXTURES / "sample_log.txt"), session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.status == "OK"
    assert result.verified_clean is True

    output = session.content_store.get(result.sanitized_handle).content

    # PII gone.
    assert "482-71-9053" not in output
    assert "4532015112830366" not in output
    assert "alice.morgan@example.com" not in output
    assert "AKIAIOSFODNN7EXAMPLE" not in output
    assert "hunter2" not in output

    # Operational structure preserved — the point of COR-04.
    assert "2026-08-16T09:14:22Z" in output
    assert "request_id=a3f9c12e" in output
    assert "service=auth-api" in output


def test_clean_fixture_produces_no_credential_findings(session):
    loaded = load_file(str(FIXTURES / "sample_clean.txt"), session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    credential_types = {
        e.type for e in result.entities if e.is_base_security
    }
    assert credential_types == set(), f"false positives: {credential_types}"


def test_pem_key_is_scrubbed_across_the_chunk_boundary(session):
    """COR-02, end to end through the real pipeline."""
    loaded = load_file(str(FIXTURES / "sample_pem_straddle.txt"), session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert "PRIVATE_KEY" in {e.type for e in result.entities}

    if result.status == "OK":
        output = session.content_store.get(result.sanitized_handle).content
        assert "-----BEGIN RSA PRIVATE KEY-----" not in output


def test_adversarial_fixture_reports_injection_and_still_scrubs(session):
    """SEC-01 end to end: instructions in content change nothing."""
    loaded = load_file(str(FIXTURES / "sample_adversarial.txt"), session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.security_findings, "injection attempt should be reported"

    if result.status == "OK":
        output = session.content_store.get(result.sanitized_handle).content
        assert "482-71-9053" not in output


def test_structured_json_fields_are_scrubbed(session):
    loaded = load_file(str(FIXTURES / "sample_pii.json"), session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    if result.status == "OK":
        output = session.content_store.get(result.sanitized_handle).content
        assert "482-71-9053" not in output
        assert "sk-live-9fK2mQ7xR4tZ8vB1nH6jL0pW" not in output


# ---------------------------------------------------------------------------
# Determinism — the basis for golden-dataset regression
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["sample_log.txt", "sample_pii.json"])
def test_identical_input_yields_identical_output(session, fixture):
    loaded = load_file(str(FIXTURES / fixture), session)

    first = scan(loaded.handle, session, FILE_DEST)
    second = scan(loaded.handle, session, FILE_DEST)

    signature_a = sorted((e.type, e.start, e.end) for e in first.entities)
    signature_b = sorted((e.type, e.start, e.end) for e in second.entities)
    assert signature_a == signature_b

    actions_a = sorted(
        (d.entity.type, d.applied_action.value) for d in first.decisions
    )
    actions_b = sorted(
        (d.entity.type, d.applied_action.value) for d in second.decisions
    )
    assert actions_a == actions_b


def test_engine_versions_are_recorded_for_reproducibility(session):
    """OPS-02 — a compliance claim must be reproducible later."""
    loaded = load_file(str(FIXTURES / "sample_log.txt"), session)
    result = scan(loaded.handle, session, FILE_DEST)

    versions = result.engine_versions
    assert versions.presidio_analyzer == "2.2.364"
    assert versions.spacy == "3.8.15"
    # Names the model, not just its version: en_core_web_lg and en_core_web_sm are
    # both 3.8.0, and a result produced with the smaller model must be
    # distinguishable in the audit trail.
    assert versions.spacy_model == "en_core_web_lg@3.8.0"
    assert versions.profile_name == "DEFAULT_PII"
    assert versions.profile_version == "1.0.0"
    assert versions.fingerprint()


# ---------------------------------------------------------------------------
# All three gates, exercised through the real pipeline
# ---------------------------------------------------------------------------


def test_gate1_coverage_blocks_artifact(session, monkeypatch):
    from pii_agent.core.detector import DetectorUnavailable

    monkeypatch.setattr(
        "pii_agent.core.detector.get_spacy",
        lambda: (_ for _ in ()).throw(DetectorUnavailable("absent")),
    )
    loaded = load_text("patient Jane ssn=482-71-9053", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is RefusalReason.DEGRADED_COVERAGE
    assert result.artifact_available is False


def test_gate2_block_suppresses_artifact(session, monkeypatch):
    from pii_agent.core.profile_resolver import EffectiveProfile

    original = EffectiveProfile.action_for
    monkeypatch.setattr(
        EffectiveProfile,
        "action_for",
        lambda self, t, d=None: (
            ScrubAction.BLOCK if t.upper() == "US_SSN" else original(self, t, d)
        ),
    )
    loaded = load_text("ssn=482-71-9053", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is RefusalReason.BLOCKED_ARTIFACT
    assert result.artifact_available is False


def test_gate3_verification_blocks_artifact(session, monkeypatch):
    import pii_agent.core.applier as applier_module

    real = applier_module.apply_decisions

    def sabotaged(content, decisions, vault):
        actionable = decisions.actionable()
        if actionable:
            decisions.decisions.remove(actionable[0])
        return real(content, decisions, vault)

    monkeypatch.setattr("pii_agent.core.pipeline.apply_decisions", sabotaged)

    loaded = load_text("ssn=482-71-9053 end", session)
    result = scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert result.refusal is RefusalReason.RESIDUAL_PII_DETECTED
    assert result.artifact_available is False


# ---------------------------------------------------------------------------
# Audit trail integrity across a full session
# ---------------------------------------------------------------------------


def test_audit_chain_is_intact_after_many_runs(session):
    for fixture in ("sample_log.txt", "sample_clean.txt", "sample_pii.json"):
        loaded = load_file(str(FIXTURES / fixture), session)
        scan_and_scrub(loaded.handle, session, FILE_DEST)

    assert session.audit_sink.count() >= 3
    ok, bad = session.audit_sink.verify_chain()
    assert ok is True and bad is None


def test_audit_trail_contains_no_pii_after_full_run(session):
    loaded = load_file(str(FIXTURES / "sample_log.txt"), session)
    scan_and_scrub(loaded.handle, session, FILE_DEST)

    trail = session.audit_sink.export()
    for secret in (
        "482-71-9053",
        "4532015112830366",
        "alice.morgan@example.com",
        "AKIAIOSFODNN7EXAMPLE",
        "hunter2",
    ):
        assert secret not in trail, f"{secret} leaked into the audit trail"
