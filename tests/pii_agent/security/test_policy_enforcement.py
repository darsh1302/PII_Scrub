"""Guardrails G4, G5, G19 — Policy Enforcement Point.

Addresses review finding SEC-04. In the reviewed design ``action`` was a
free-form LLM-supplied argument with nothing constraining it to the profile, so
a model could pass ALLOW for US_SSN. That is a complete policy bypass reachable
through ordinary model error or through injected log content.
"""

from __future__ import annotations

import pytest

from pii_agent.core.policy import DestinationRequired, PolicyContext, get_policy_engine
from pii_agent.core.profile_resolver import resolve_profile
from pii_agent.models.decision import DecisionSet, PolicyViolation
from pii_agent.models.entities import Entity
from pii_agent.models.enums import Destination, EntitySeverity, ScrubAction


@pytest.fixture
def profile():
    return resolve_profile("DEFAULT_PII")


@pytest.fixture
def engine():
    return get_policy_engine()


def _entity(
    entity_type: str,
    *,
    text: str = "x" * 11,
    base_security: bool = False,
    severity: EntitySeverity | None = None,
    start: int = 0,
) -> Entity:
    return Entity(
        type=entity_type,
        start=start,
        end=start + len(text),
        confidence=0.9,
        text=text,
        detected_by=["presidio"],
        is_base_security=base_security,
        severity=severity,
    )


# ---------------------------------------------------------------------------
# G4 — the ratchet
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("weak", [ScrubAction.ALLOW, ScrubAction.REPLACE, ScrubAction.MASK])
def test_weaker_request_is_discarded(engine, profile, weak):
    """US_SSN is REDACT in DEFAULT_PII. No request may lower that."""
    decision = engine.resolve_one(
        _entity("US_SSN"),
        PolicyContext(profile=profile, requested_action=weak),
    )
    assert decision.applied_action is ScrubAction.REDACT
    assert decision.request_was_discarded is True
    assert decision.deciding_rule == "request_discarded_weaker_than_profile"


def test_stronger_request_is_honoured(engine, profile):
    """The ratchet turns one way. Asking for more protection is allowed."""
    decision = engine.resolve_one(
        _entity("CREDIT_CARD"),  # MASK in DEFAULT_PII
        PolicyContext(profile=profile, requested_action=ScrubAction.REDACT),
    )
    assert decision.applied_action is ScrubAction.REDACT
    assert decision.was_escalated is True
    assert decision.request_was_discarded is False


def test_matching_request_is_not_flagged_as_discarded(engine, profile):
    decision = engine.resolve_one(
        _entity("US_SSN"),
        PolicyContext(profile=profile, requested_action=ScrubAction.REDACT),
    )
    assert decision.request_was_discarded is False
    assert decision.deciding_rule == "request_matched_profile"


def test_no_request_uses_the_profile_mandate(engine, profile):
    decision = engine.resolve_one(_entity("US_SSN"), PolicyContext(profile=profile))
    assert decision.applied_action is ScrubAction.REDACT
    assert decision.deciding_rule == "profile_mandate"


@pytest.mark.parametrize("requested", list(ScrubAction))
@pytest.mark.parametrize(
    "entity_type", ["US_SSN", "CREDIT_CARD", "EMAIL_ADDRESS", "PERSON", "API_KEY"]
)
def test_applied_is_never_weaker_than_mandated(
    engine, profile, entity_type, requested
):
    """Property 8, exhaustively over the action lattice."""
    mandated = profile.action_for(entity_type)
    decision = engine.resolve_one(
        _entity(entity_type),
        PolicyContext(profile=profile, requested_action=requested),
    )
    assert decision.applied_action.priority >= mandated.priority


def test_unknown_entity_type_defaults_to_redact(engine, profile):
    """Detecting something policy does not describe warrants caution."""
    decision = engine.resolve_one(
        _entity("SOME_FUTURE_TYPE"), PolicyContext(profile=profile)
    )
    assert decision.applied_action is ScrubAction.REDACT


# ---------------------------------------------------------------------------
# G5 — BASE_SECURITY is unconditional
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "credential",
    ["API_KEY", "PASSWORD", "PRIVATE_KEY", "JWT", "AWS_ACCESS_KEY", "CLIENT_SECRET"],
)
@pytest.mark.parametrize("requested", [ScrubAction.ALLOW, ScrubAction.REPLACE])
def test_base_security_ignores_requests_entirely(
    engine, profile, credential, requested
):
    decision = engine.resolve_one(
        _entity(credential, base_security=True),
        PolicyContext(profile=profile, requested_action=requested),
    )
    assert decision.applied_action is ScrubAction.REDACT
    assert decision.is_base_security is True
    assert decision.deciding_rule == "base_security_mandate"


def test_high_severity_custom_security_detection_is_treated_as_base_security(
    engine, profile
):
    """A new recognizer added without updating BASE_SECURITY_TYPES still gets
    unconditional handling."""
    entity = Entity(
        type="SOME_NEW_CREDENTIAL",
        start=0,
        end=20,
        confidence=0.9,
        text="x" * 20,
        detected_by=["custom_security"],
        severity=EntitySeverity.HIGH,
    )
    decision = engine.resolve_one(
        entity, PolicyContext(profile=profile, requested_action=ScrubAction.ALLOW)
    )
    assert decision.is_base_security is True
    assert decision.applied_action is ScrubAction.REDACT


def test_base_security_is_not_exempted_by_field_context(engine, profile):
    """A credential in a timestamp field is still a credential."""
    document = "@timestamp: api_key=sk-live-abcdefghij"
    entity = _entity(
        "API_KEY", text="sk-live-abcdefghij", base_security=True, start=12
    )
    decision = engine.resolve_one(
        entity, PolicyContext(profile=profile, document=document)
    )
    assert decision.applied_action is ScrubAction.REDACT


# ---------------------------------------------------------------------------
# Decision invariant
# ---------------------------------------------------------------------------


def test_decision_construction_rejects_a_weakened_action():
    """Second line of defence: even a bypass of resolve() fails loudly."""
    from pii_agent.models.decision import Decision

    with pytest.raises(PolicyViolation):
        Decision(
            entity=_entity("US_SSN"),
            profile_mandated_action=ScrubAction.REDACT,
            applied_action=ScrubAction.MASK,
        )


# ---------------------------------------------------------------------------
# Destination awareness (COR-04)
# ---------------------------------------------------------------------------


def test_ip_allowed_for_internal_siem(engine, profile):
    decision = engine.resolve_one(
        _entity("IP_ADDRESS", text="203.0.113.42"),
        PolicyContext(profile=profile, destination=Destination.INTERNAL_SIEM),
    )
    assert decision.applied_action is ScrubAction.ALLOW


def test_ip_redacted_for_external_destinations(engine, profile):
    for destination in (
        Destination.EXTERNAL_LLM,
        Destination.EXTERNAL_ANALYTICS,
        Destination.S3,
    ):
        decision = engine.resolve_one(
            _entity("IP_ADDRESS", text="203.0.113.42"),
            PolicyContext(profile=profile, destination=destination),
        )
        assert decision.applied_action is ScrubAction.REDACT


def test_missing_destination_raises_rather_than_guessing(engine, profile):
    """Requirement 19.9 — asking beats silently shredding operational data."""
    with pytest.raises(DestinationRequired) as exc:
        engine.resolve(
            [_entity("IP_ADDRESS", text="203.0.113.42")],
            PolicyContext(profile=profile),
        )
    assert "IP_ADDRESS" in exc.value.entity_types


def test_missing_destination_is_tolerated_when_not_strict(engine, profile):
    """Dry-run reporting produces no artifact, so no destination is needed."""
    decisions = engine.resolve(
        [_entity("IP_ADDRESS", text="203.0.113.42")],
        PolicyContext(profile=profile),
        strict_destination=False,
    )
    assert len(decisions) == 1


def test_destination_insensitive_types_do_not_require_a_destination(
    engine, profile
):
    decisions = engine.resolve(
        [_entity("US_SSN"), _entity("EMAIL_ADDRESS", text="a@b.com", start=20)],
        PolicyContext(profile=profile),
    )
    assert len(decisions) == 2


# ---------------------------------------------------------------------------
# Field-context exemption (COR-04)
# ---------------------------------------------------------------------------


def test_leading_log_timestamp_is_exempt(engine, profile):
    """Scrubbing every timestamp destroys the point of keeping logs."""
    document = "2026-08-16T09:15:44Z ERROR something failed"
    entity = _entity("DATE_TIME", text="2026-08-16T09:15:44Z", start=0)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is ScrubAction.ALLOW
    assert "field_context_exempt" in decision.deciding_rule


def test_date_in_message_body_is_not_exempt(engine, profile):
    """Only structural positions are exempt, not every date."""
    document = "ERROR patient date of birth 1984-03-11 lookup failed"
    entity = _entity("DATE_TIME", text="1984-03-11", start=28)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is not ScrubAction.ALLOW


def test_named_timestamp_field_is_exempt(engine, profile):
    document = '{"@timestamp": "2026-08-16T09:15:44Z", "msg": "ok"}'
    entity = _entity("DATE_TIME", text="2026-08-16T09:15:44Z", start=16)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is ScrubAction.ALLOW


# ---------------------------------------------------------------------------
# G19 — BLOCK suppresses the artifact
# ---------------------------------------------------------------------------


def test_decision_set_reports_artifact_suppression():
    from pii_agent.models.decision import Decision

    decisions = DecisionSet(
        decisions=[
            Decision(
                entity=_entity("CVV", text="123"),
                profile_mandated_action=ScrubAction.BLOCK,
                applied_action=ScrubAction.BLOCK,
            )
        ]
    )
    assert decisions.blocks_artifact is True
    assert decisions.blocking_types == ("CVV",)


def test_block_is_distinct_from_redact():
    """COR-05 — otherwise the strictest control quietly does not exist."""
    assert ScrubAction.BLOCK.suppresses_artifact is True
    assert ScrubAction.REDACT.suppresses_artifact is False


# ---------------------------------------------------------------------------
# Field-context exemption edge cases
#
# The exemption needs the surrounding document to decide whether an entity sits
# in a structural position. These cover the paths where that context is absent
# or unusual — each would otherwise mean an exemption applied (or failed to
# apply) for the wrong reason.
# ---------------------------------------------------------------------------


def test_no_exemption_without_document_context(engine, profile):
    """Without the document, a structural position cannot be established.

    Falling back to "not exempt" is the safe direction: the value gets scrubbed
    rather than silently preserved on a guess.
    """
    entity = _entity("DATE_TIME", text="2026-08-16T09:15:44Z")
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=""
        ),
    )
    assert decision.applied_action is not ScrubAction.ALLOW
    assert "field_context_exempt" not in decision.deciding_rule


def test_exemption_applies_on_the_final_line_without_a_trailing_newline(
    engine, profile
):
    """Log files frequently end mid-write, with no terminating newline."""
    document = "first line\n2026-08-16T09:15:44Z ERROR truncated"
    entity = _entity("DATE_TIME", text="2026-08-16T09:15:44Z", start=11)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is ScrubAction.ALLOW


def test_timestamp_not_at_line_start_is_not_exempt(engine, profile):
    """The exemption is positional. A timestamp mid-line is not structural."""
    document = "ERROR the deadline was 2026-08-16T09:15:44Z for this record"
    entity = _entity("DATE_TIME", text="2026-08-16T09:15:44Z", start=23)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is not ScrubAction.ALLOW


def test_leading_timestamp_tolerates_a_small_indent(engine, profile):
    """Indented continuation lines still carry a structural timestamp."""
    document = "  2026-08-16T09:15:44Z INFO indented entry"
    entity = _entity("DATE_TIME", text="2026-08-16T09:15:44Z", start=2)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is ScrubAction.ALLOW


def test_line_starting_with_a_non_timestamp_is_not_exempt(engine, profile):
    """Position alone is not enough — the line must open with a timestamp."""
    document = "INFO 2026 was the year"
    entity = _entity("DATE_TIME", text="2026", start=5)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is not ScrubAction.ALLOW


@pytest.mark.parametrize(
    "field_name", ["ts", "time", "timestamp", "created_at", "eventTime"]
)
def test_each_configured_timestamp_field_name_is_exempt(
    engine, profile, field_name
):
    document = f'{{"{field_name}": "2026-08-16T09:15:44Z"}}'
    start = document.index("2026")
    entity = _entity("DATE_TIME", text="2026-08-16T09:15:44Z", start=start)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is ScrubAction.ALLOW, (
        f"{field_name} should be exempt"
    )


def test_unconfigured_field_name_is_not_exempt(engine, profile):
    """Only the names the profile lists are structural."""
    document = '{"birth_date": "1984-03-11"}'
    entity = _entity("DATE_TIME", text="1984-03-11", start=16)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is not ScrubAction.ALLOW


def test_field_name_appearing_as_a_substring_does_not_exempt(engine, profile):
    """``ts`` must not match inside ``reports``.

    A loose match here would exempt dates from arbitrary fields whose names
    merely contain a configured token.
    """
    document = '{"reports": "1984-03-11"}'
    entity = _entity("DATE_TIME", text="1984-03-11", start=13)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is not ScrubAction.ALLOW


def test_entity_type_without_exemptions_skips_the_check(engine, profile):
    """Only rules declaring exemptions consult the document."""
    document = "@timestamp: 482-71-9053"
    entity = _entity("US_SSN", text="482-71-9053", start=12)
    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is ScrubAction.REDACT


def test_exemption_applies_on_an_interior_line(engine, profile):
    """A timestamp on a line that is followed by more lines.

    Complements the final-line case: the line-boundary search takes a different
    path depending on whether a trailing newline exists, and both must resolve
    the same line correctly.
    """
    document = (
        "2026-08-16T09:14:00Z INFO first\n"
        "2026-08-16T09:15:44Z ERROR second\n"
        "2026-08-16T09:16:00Z INFO third\n"
    )
    start = document.index("\n") + 1
    entity = _entity("DATE_TIME", text="2026-08-16T09:15:44Z", start=start)

    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is ScrubAction.ALLOW


def test_interior_line_position_is_evaluated_against_its_own_line(
    engine, profile
):
    """A mid-line date on an interior line must not inherit its line's opening.

    If the wrong line were extracted, a date buried in a message body would be
    exempted because some *other* line began with a timestamp.
    """
    document = (
        "2026-08-16T09:14:00Z INFO first\n"
        "ERROR patient dob 1984-03-11 lookup failed\n"
        "2026-08-16T09:16:00Z INFO third\n"
    )
    start = document.index("1984-03-11")
    entity = _entity("DATE_TIME", text="1984-03-11", start=start)

    decision = engine.resolve_one(
        entity,
        PolicyContext(
            profile=profile, destination=Destination.FILE, document=document
        ),
    )
    assert decision.applied_action is not ScrubAction.ALLOW
