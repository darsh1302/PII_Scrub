"""Property 8 — policy monotonicity. Guardrails G4, G5.

The invariant that contains the blast radius of every other weakness in this
system, including prompt injection:

    ACTION_PRIORITY[applied] >= ACTION_PRIORITY[profile_mandated]

If it holds for all inputs, then no amount of manipulation — of the user request,
of the reasoning loop, of scanned content — can produce a weaker scrub than the
profile mandates. Generative rather than example-based because the claim is
universal over the action lattice and every entity type.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from core.policy import PolicyContext, get_policy_engine
from core.profile_resolver import resolve_profile
from models.entities import Entity
from models.enums import Destination, EntitySeverity, ScrubAction
from profiles.schema import BASE_SECURITY_TYPES
from utils.config import ACTION_PRIORITY

PROFILE_NAMES = ["DEFAULT_PII", "BASE_SECURITY"]

SETTINGS = settings(
    max_examples=400,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _profile(name: str):
    return resolve_profile(name)


def _entity(
    entity_type: str,
    *,
    base_security: bool = False,
    severity: EntitySeverity | None = None,
    detector: str = "presidio",
) -> Entity:
    return Entity(
        type=entity_type,
        start=0,
        end=12,
        confidence=0.9,
        text="x" * 12,
        detected_by=[detector],
        is_base_security=base_security,
        severity=severity,
    )


ENTITY_TYPES = sorted(
    {
        "US_SSN",
        "CREDIT_CARD",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "PERSON",
        "LOCATION",
        "IP_ADDRESS",
        "DATE_TIME",
        "US_PASSPORT",
        "IBAN_CODE",
        "URL",
        "SOME_UNKNOWN_TYPE",
        *BASE_SECURITY_TYPES,
    }
)


# ---------------------------------------------------------------------------
# The central property
# ---------------------------------------------------------------------------


@given(
    entity_type=st.sampled_from(ENTITY_TYPES),
    profile_name=st.sampled_from(PROFILE_NAMES),
    requested=st.one_of(st.none(), st.sampled_from(list(ScrubAction))),
    destination=st.one_of(st.none(), st.sampled_from(list(Destination))),
)
@SETTINGS
def test_applied_action_is_never_weaker_than_mandated(
    entity_type, profile_name, requested, destination
):
    profile = _profile(profile_name)
    mandated = profile.action_for(entity_type, destination)

    decision = get_policy_engine().resolve_one(
        _entity(entity_type),
        PolicyContext(
            profile=profile,
            destination=destination,
            requested_action=requested,
        ),
    )

    assert (
        ACTION_PRIORITY[decision.applied_action.value]
        >= ACTION_PRIORITY[mandated.value]
    ), (
        f"{entity_type} under {profile_name}: mandated {mandated.value}, "
        f"requested {requested}, applied {decision.applied_action.value}"
    )


@given(
    entity_type=st.sampled_from(sorted(BASE_SECURITY_TYPES)),
    profile_name=st.sampled_from(PROFILE_NAMES),
    requested=st.sampled_from(list(ScrubAction)),
    destination=st.one_of(st.none(), st.sampled_from(list(Destination))),
)
@SETTINGS
def test_base_security_never_falls_below_redact(
    entity_type, profile_name, requested, destination
):
    """Credentials are non-negotiable regardless of request or destination."""
    decision = get_policy_engine().resolve_one(
        _entity(entity_type, base_security=True),
        PolicyContext(
            profile=_profile(profile_name),
            destination=destination,
            requested_action=requested,
        ),
    )
    assert (
        ACTION_PRIORITY[decision.applied_action.value]
        >= ACTION_PRIORITY[ScrubAction.REDACT.value]
    )
    assert decision.is_base_security is True


@given(
    entity_type=st.sampled_from(ENTITY_TYPES),
    profile_name=st.sampled_from(PROFILE_NAMES),
    requested=st.sampled_from(list(ScrubAction)),
)
@SETTINGS
def test_requesting_allow_never_yields_allow_for_a_mandated_type(
    entity_type, profile_name, requested
):
    """The specific bypass SEC-04 described."""
    profile = _profile(profile_name)
    mandated = profile.action_for(entity_type, Destination.FILE)

    decision = get_policy_engine().resolve_one(
        _entity(entity_type),
        PolicyContext(
            profile=profile,
            destination=Destination.FILE,
            requested_action=ScrubAction.ALLOW,
        ),
    )

    if mandated is not ScrubAction.ALLOW:
        assert decision.applied_action is not ScrubAction.ALLOW
    _ = requested


# ---------------------------------------------------------------------------
# Ratchet direction
# ---------------------------------------------------------------------------


@given(
    entity_type=st.sampled_from(ENTITY_TYPES),
    requested=st.sampled_from(list(ScrubAction)),
)
@SETTINGS
def test_request_is_honoured_exactly_when_it_is_more_restrictive(
    entity_type, requested
):
    profile = _profile("DEFAULT_PII")
    mandated = profile.action_for(entity_type, Destination.FILE)

    decision = get_policy_engine().resolve_one(
        _entity(entity_type),
        PolicyContext(
            profile=profile,
            destination=Destination.FILE,
            requested_action=requested,
        ),
    )

    if decision.is_base_security:
        # Requests are ignored entirely for credentials.
        assert decision.applied_action is mandated
        return

    expected = max(
        (mandated, requested), key=lambda a: ACTION_PRIORITY[a.value]
    )
    assert decision.applied_action is expected


@given(
    entity_type=st.sampled_from(ENTITY_TYPES),
    requested=st.sampled_from(list(ScrubAction)),
)
@SETTINGS
def test_discarded_flag_matches_whether_the_request_was_dropped(
    entity_type, requested
):
    """A denied request must be recorded so it can be explained."""
    profile = _profile("DEFAULT_PII")
    mandated = profile.action_for(entity_type, Destination.FILE)

    decision = get_policy_engine().resolve_one(
        _entity(entity_type),
        PolicyContext(
            profile=profile,
            destination=Destination.FILE,
            requested_action=requested,
        ),
    )

    if decision.is_base_security:
        assert decision.request_was_discarded == (requested != mandated)
    else:
        weaker = ACTION_PRIORITY[requested.value] < ACTION_PRIORITY[mandated.value]
        assert decision.request_was_discarded is weaker


# ---------------------------------------------------------------------------
# Set-level resolution
# ---------------------------------------------------------------------------


@given(
    entity_types=st.lists(
        st.sampled_from(ENTITY_TYPES), min_size=1, max_size=12
    ),
    requested=st.one_of(st.none(), st.sampled_from(list(ScrubAction))),
)
@SETTINGS
def test_every_decision_in_a_set_satisfies_the_invariant(
    entity_types, requested
):
    profile = _profile("DEFAULT_PII")
    entities = [
        _entity(t) for t in entity_types
    ]
    for index, entity in enumerate(entities):
        entity.start = index * 20
        entity.end = index * 20 + 12

    decisions = get_policy_engine().resolve(
        entities,
        PolicyContext(
            profile=profile,
            destination=Destination.FILE,
            requested_action=requested,
        ),
    )

    for decision in decisions:
        mandated = profile.action_for(decision.entity.type, Destination.FILE)
        assert (
            ACTION_PRIORITY[decision.applied_action.value]
            >= ACTION_PRIORITY[mandated.value]
        )
        # Constructor invariant holds too.
        decision.assert_monotonic()


@given(
    actions=st.lists(st.sampled_from(list(ScrubAction)), min_size=1, max_size=6)
)
@SETTINGS
def test_most_restrictive_is_associative_and_commutative(actions):
    """The merge used across inheritance and multi-profile combination.

    If order mattered, effective policy would depend on argument order.
    """
    forward = ScrubAction.most_restrictive(*actions)
    backward = ScrubAction.most_restrictive(*reversed(actions))
    assert forward is backward
    assert all(
        ACTION_PRIORITY[forward.value] >= ACTION_PRIORITY[a.value] for a in actions
    )
