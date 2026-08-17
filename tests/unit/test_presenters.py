"""Presentation logic — refusals must read as protection, not failure.

Requirement 29, 36.5.

This is the UI's one genuinely important job. A user who reads
`DEGRADED_COVERAGE` as an error goes looking for an override; a user who
understands that a partial scan cannot yield a verifiable clean copy fixes the
cause instead. These tests pin that wording.
"""

from __future__ import annotations

import pytest

from models.coverage import CoverageLedger
from models.decision import Decision, DecisionSet
from models.entities import Entity
from models.enums import (
    ConfidenceSource,
    EntitySeverity,
    RefusalReason,
    ScrubAction,
)
from models.results import EngineVersions, ProcessingResult
from ui.presenters import (
    build_entity_rows,
    build_summary,
    describe_denied_requests,
    describe_refusal,
    describe_security_findings,
    format_state,
)


def _result(**kwargs) -> ProcessingResult:
    base = ProcessingResult(
        engine_versions=EngineVersions.detect("DEFAULT_PII", "1.0.0")
    )
    for key, value in kwargs.items():
        setattr(base, key, value)
    return base


def _entity(
    entity_type: str = "US_SSN",
    *,
    text: str = "482-71-9053",
    severity: EntitySeverity | None = None,
    source: ConfidenceSource = ConfidenceSource.CALIBRATED,
) -> Entity:
    return Entity(
        type=entity_type,
        start=0,
        end=len(text),
        confidence=0.9,
        text=text,
        severity=severity,
        detected_by=["presidio"],
        confidence_source=source,
    )


# ---------------------------------------------------------------------------
# Refusal wording
# ---------------------------------------------------------------------------


def test_no_notice_for_a_successful_result():
    assert describe_refusal(_result()) is None


def test_degraded_coverage_reads_as_protection_not_error():
    ledger = CoverageLedger(
        bytes_total=1000, required_detectors=frozenset({"presidio", "spacy"})
    )
    ledger.start_detector("presidio")
    ledger.record_detector_unavailable("spacy", "model not installed")
    ledger.advance_bytes(1000)

    notice = describe_refusal(
        _result(
            refusal=RefusalReason.DEGRADED_COVERAGE,
            refusal_detail=ledger.describe(),
            coverage=ledger,
        )
    )

    assert notice is not None
    assert notice.is_defect is False
    assert "look checked without being checked" in notice.explanation
    # The findings are still presented as useful.
    assert "worth acting on" in notice.explanation


def test_degraded_coverage_gives_the_spacy_install_command():
    """A next step the user can actually run."""
    ledger = CoverageLedger(
        bytes_total=100, required_detectors=frozenset({"presidio", "spacy"})
    )
    ledger.start_detector("presidio")
    ledger.record_detector_unavailable("spacy", "model not installed")
    ledger.advance_bytes(100)

    notice = describe_refusal(
        _result(refusal=RefusalReason.DEGRADED_COVERAGE, coverage=ledger)
    )
    assert any("spacy download" in step for step in notice.next_steps)


def test_intentional_truncation_suggests_a_full_rerun():
    ledger = CoverageLedger(
        bytes_total=10_000,
        required_detectors=frozenset({"presidio"}),
        truncation_approved_by_user=True,
    )
    ledger.start_detector("presidio")
    ledger.advance_bytes(2000)

    notice = describe_refusal(
        _result(refusal=RefusalReason.DEGRADED_COVERAGE, coverage=ledger)
    )
    assert any("without a size limit" in step for step in notice.next_steps)


def test_blocked_artifact_is_framed_as_policy_not_failure():
    notice = describe_refusal(
        _result(
            refusal=RefusalReason.BLOCKED_ARTIFACT,
            refusal_detail="Policy blocks this content because it contains: CVV.",
        )
    )
    assert notice.is_defect is False
    assert "not a detection failure" in notice.explanation
    assert "remove the blocked values at source" in " ".join(notice.next_steps)


def test_residual_pii_is_framed_as_a_tool_defect():
    """The user did nothing wrong and should be told so plainly."""
    notice = describe_refusal(
        _result(
            refusal=RefusalReason.RESIDUAL_PII_DETECTED,
            refusal_detail="Verification found 2 entities still present.",
            request_id="abc123",
        )
    )
    assert notice.is_defect is True
    assert "Your input is fine" in notice.explanation
    assert any("abc123" in step for step in notice.next_steps)


def test_residual_notice_explains_why_withholding_is_correct():
    notice = describe_refusal(
        _result(refusal=RefusalReason.RESIDUAL_PII_DETECTED)
    )
    assert "dangerous outcome" in notice.explanation


def test_needs_destination_explains_the_tradeoff_of_each_option():
    """The user must understand why the answer matters, not just be asked."""
    notice = describe_refusal(
        _result(
            refusal=RefusalReason.NEEDS_DESTINATION,
            refusal_detail="Handling depends on destination for: IP_ADDRESS.",
        )
    )
    joined = " ".join(notice.next_steps)
    assert "correlatable" in joined
    assert "EXTERNAL_LLM" in joined


def test_invalid_profile_explains_why_there_is_no_fallback():
    notice = describe_refusal(
        _result(
            refusal=RefusalReason.INVALID_PROFILE,
            refusal_detail="HEALTHCARE.yaml failed validation.",
        )
    )
    assert "nobody reviewed" in notice.explanation


def test_timeout_notes_that_coverage_is_incomplete():
    notice = describe_refusal(_result(refusal=RefusalReason.TIMEOUT))
    assert "no cleaned copy" in notice.explanation


@pytest.mark.parametrize("reason", list(RefusalReason))
def test_every_refusal_reason_produces_a_usable_notice(reason):
    """A reason with no wording would render as a bare enum value."""
    notice = describe_refusal(_result(refusal=reason))
    assert notice is not None
    assert len(notice.headline) > 8
    assert len(notice.explanation) > 20


# ---------------------------------------------------------------------------
# Findings table
# ---------------------------------------------------------------------------


def test_credential_previews_never_show_any_of_the_value():
    rows = build_entity_rows(
        _result(
            entities=[
                _entity(
                    "API_KEY",
                    text="sk-live-9fK2mQ7xR4tZ8vB1",
                    severity=EntitySeverity.HIGH,
                )
            ]
        )
    )
    assert rows[0].preview == "[API_KEY]"
    assert "sk-live" not in rows[0].preview


def test_non_credential_previews_are_masked_not_plain():
    rows = build_entity_rows(_result(entities=[_entity()]))
    assert rows[0].preview != "482-71-9053"
    assert rows[0].preview.startswith("48")
    assert rows[0].preview.endswith("53")


def test_heuristic_confidence_is_labelled_as_such():
    """spaCy emits a constant; presenting it as calibrated would mislead."""
    rows = build_entity_rows(
        _result(entities=[_entity("PERSON", text="Jane Fair", source=ConfidenceSource.HEURISTIC)])
    )
    assert "heuristic" in rows[0].confidence


def test_calibrated_confidence_is_not_labelled():
    rows = build_entity_rows(_result(entities=[_entity()]))
    assert "heuristic" not in rows[0].confidence


def test_rows_are_ordered_with_credentials_first():
    """The most urgent finding should not be buried."""
    result = _result(
        entities=[
            _entity("DATE_TIME", text="2026-08-16", severity=EntitySeverity.LOW),
            _entity("API_KEY", text="sk-live-abc123", severity=EntitySeverity.HIGH),
            _entity("US_SSN", severity=EntitySeverity.MEDIUM),
        ]
    )
    labels = [row.severity_label for row in build_entity_rows(result)]
    assert labels[0] == "Credential or secret"
    assert labels[-1] == "Indirect identifier"


def test_rows_show_the_applied_action():
    entity = _entity()
    result = _result(
        entities=[entity],
        decisions=DecisionSet(
            decisions=[
                Decision(
                    entity=entity,
                    profile_mandated_action=ScrubAction.REDACT,
                    applied_action=ScrubAction.REDACT,
                )
            ]
        ),
    )
    assert build_entity_rows(result)[0].action == "REDACT"


def test_rows_are_empty_when_nothing_was_found():
    assert build_entity_rows(_result()) == []


# ---------------------------------------------------------------------------
# Denied requests
# ---------------------------------------------------------------------------


def test_denied_request_is_explained_rather_than_silently_dropped():
    """A silently ignored request looks like a bug to the user."""
    entity = _entity()
    result = _result(
        decisions=DecisionSet(
            decisions=[
                Decision(
                    entity=entity,
                    profile_mandated_action=ScrubAction.REDACT,
                    applied_action=ScrubAction.REDACT,
                    requested_action=ScrubAction.ALLOW,
                    request_was_discarded=True,
                )
            ]
        )
    )
    message = describe_denied_requests(result)
    assert message is not None
    assert "US_SSN" in message
    assert "stricter but not looser" in message


def test_no_message_when_no_request_was_denied():
    assert describe_denied_requests(_result()) is None


# ---------------------------------------------------------------------------
# Security findings
# ---------------------------------------------------------------------------


def test_injection_finding_explains_that_it_had_no_effect():
    """Otherwise the user reasonably assumes the agent was compromised."""
    message = describe_security_findings(
        _result(security_findings=["bracketed directive block (x1)"])
    )
    assert message is not None
    assert "had no effect" in message
    assert "decided in code" in message


def test_no_security_message_when_content_is_clean():
    assert describe_security_findings(_result()) is None


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------


def test_summary_reports_artifact_availability_not_just_a_handle():
    """Property 11 — a handle alone must not imply exportability."""
    result = _result(sanitized_handle="h2", verified_clean=False)
    assert build_summary(result)["artifact_available"] is False

    result.verified_clean = True
    assert build_summary(result)["artifact_available"] is True


def test_summary_contains_no_entity_values():
    result = _result(entities=[_entity()])
    assert "482-71-9053" not in str(build_summary(result))


@pytest.mark.parametrize(
    "state",
    [
        "IDLE",
        "THINKING",
        "PLANNING",
        "EXECUTING",
        "ANALYZING",
        "REPORTING",
        "WAITING_FOR_INPUT",
    ],
)
def test_every_agent_state_has_an_icon(state):
    formatted = format_state(state)
    assert "⚪" not in formatted, f"{state} has no icon"


def test_unknown_state_degrades_gracefully():
    assert "⚪" in format_state("SOMETHING_NEW")
