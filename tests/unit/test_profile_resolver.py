"""Profile inheritance resolution — Property 1 (inheritance safety).

The central assertion: no inheritance path, multi-profile combination, or
destination override can produce a policy weaker than BASE_SECURITY mandates.
"""

from __future__ import annotations

import pytest

from core.profile_resolver import ProfileResolver, resolve_profile
from models.enums import Destination, ScrubAction
from profiles.schema import BASE_SECURITY_TYPES, ProfileValidationError
from utils.config import MIN_CHUNK_OVERLAP_CHARS


@pytest.fixture
def custom_dir(tmp_path):
    """A profiles dir seeded with the real BASE_SECURITY and DEFAULT_PII."""
    import shutil
    from pathlib import Path

    real = Path(__file__).parent.parent.parent / "profiles"
    for name in ("BASE_SECURITY.yaml", "DEFAULT_PII.yaml"):
        shutil.copy(real / name, tmp_path / name)
    return tmp_path


def _write(directory, name: str, body: str) -> None:
    (directory / f"{name}.yaml").write_text(body, encoding="utf-8")


# ---------------------------------------------------------------------------
# Baseline resolution
# ---------------------------------------------------------------------------


def test_default_profile_inherits_base_security():
    p = resolve_profile("DEFAULT_PII")
    assert "BASE_SECURITY" in p.applied_profiles
    assert p.action_for("API_KEY") is ScrubAction.REDACT


def test_base_security_applied_even_when_not_declared(custom_dir):
    """BASE_SECURITY is unconditional — never dependent on a declaration."""
    _write(
        custom_dir,
        "STANDALONE",
        "name: STANDALONE\nversion: '1.0.0'\ndescription: x\n"
        "inherits: []\n"
        "entities:\n  - type: PERSON\n    action: REPLACE\n",
    )
    p = ProfileResolver(custom_dir).resolve("STANDALONE")
    assert "BASE_SECURITY" in p.applied_profiles
    assert p.action_for("PRIVATE_KEY") is ScrubAction.REDACT


def test_unknown_entity_type_defaults_to_redact():
    """Detecting something the policy does not describe warrants caution."""
    p = resolve_profile("DEFAULT_PII")
    assert p.action_for("SOME_FUTURE_TYPE") is ScrubAction.REDACT


def test_unknown_profile_name_lists_available_options():
    with pytest.raises(ProfileValidationError) as exc:
        resolve_profile("NONEXISTENT_PROFILE")
    assert "Available:" in str(exc.value)


# ---------------------------------------------------------------------------
# Property 1 — inheritance cannot weaken
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entity_type", sorted(BASE_SECURITY_TYPES))
def test_no_inheritance_path_weakens_base_security(entity_type, custom_dir):
    """A child declaring a weak action is rejected at validation."""
    _write(
        custom_dir,
        "SLOPPY",
        "name: SLOPPY\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [DEFAULT_PII]\n"
        f"entities:\n  - type: {entity_type}\n    action: REPLACE\n",
    )
    with pytest.raises(ProfileValidationError):
        ProfileResolver(custom_dir).resolve("SLOPPY")


def test_merge_keeps_the_stricter_action(custom_dir):
    """CREDIT_CARD is MASK in DEFAULT_PII; a child raising it to REDACT wins."""
    _write(
        custom_dir,
        "STRICTER",
        "name: STRICTER\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [DEFAULT_PII]\n"
        "entities:\n  - type: CREDIT_CARD\n    action: REDACT\n",
    )
    p = ProfileResolver(custom_dir).resolve("STRICTER")
    assert p.action_for("CREDIT_CARD") is ScrubAction.REDACT


def test_merge_ignores_the_weaker_action(custom_dir):
    """US_SSN is REDACT in DEFAULT_PII; a child asking for MASK must not win."""
    _write(
        custom_dir,
        "LOOSER",
        "name: LOOSER\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [DEFAULT_PII]\n"
        "entities:\n  - type: US_SSN\n    action: MASK\n",
    )
    p = ProfileResolver(custom_dir).resolve("LOOSER")
    assert p.action_for("US_SSN") is ScrubAction.REDACT


def test_merge_keeps_the_lower_confidence_threshold(custom_dir):
    """Lower threshold means more sensitive detection — more protective."""
    _write(
        custom_dir,
        "SENSITIVE",
        "name: SENSITIVE\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [DEFAULT_PII]\n"
        "entities:\n  - type: PERSON\n    action: REPLACE\n"
        "    confidence_threshold: 0.2\n",
    )
    p = ProfileResolver(custom_dir).resolve("SENSITIVE")
    assert p.threshold_for("PERSON") == 0.2


# ---------------------------------------------------------------------------
# Multi-profile combination
# ---------------------------------------------------------------------------


def test_multiple_profiles_combine_with_stricter_action_winning(custom_dir):
    _write(
        custom_dir,
        "ALPHA",
        "name: ALPHA\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [DEFAULT_PII]\n"
        "entities:\n  - type: PHONE_NUMBER\n    action: MASK\n",
    )
    _write(
        custom_dir,
        "BETA",
        "name: BETA\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [DEFAULT_PII]\n"
        "entities:\n  - type: PHONE_NUMBER\n    action: REDACT\n",
    )
    p = ProfileResolver(custom_dir).resolve("ALPHA", "BETA")
    assert p.action_for("PHONE_NUMBER") is ScrubAction.REDACT
    assert "ALPHA" in p.applied_profiles and "BETA" in p.applied_profiles


def test_required_detectors_union_across_profiles(custom_dir):
    """A profile needing spaCy makes spaCy required for the combination."""
    p = ProfileResolver(custom_dir).resolve("DEFAULT_PII")
    assert "spacy" in p.required_detectors
    assert "presidio" in p.required_detectors


# ---------------------------------------------------------------------------
# Cycles and malformed chains
# ---------------------------------------------------------------------------


def test_circular_inheritance_is_detected(custom_dir):
    """Without detection this recurses until the stack gives out."""
    _write(
        custom_dir,
        "LOOP_A",
        "name: LOOP_A\nversion: '1.0.0'\ndescription: x\ninherits: [LOOP_B]\n",
    )
    _write(
        custom_dir,
        "LOOP_B",
        "name: LOOP_B\nversion: '1.0.0'\ndescription: x\ninherits: [LOOP_A]\n",
    )
    with pytest.raises(ProfileValidationError) as exc:
        ProfileResolver(custom_dir).resolve("LOOP_A")
    assert "circular" in str(exc.value)


def test_self_inheritance_is_detected(custom_dir):
    _write(
        custom_dir,
        "NARCISSUS",
        "name: NARCISSUS\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [NARCISSUS]\n",
    )
    with pytest.raises(ProfileValidationError) as exc:
        ProfileResolver(custom_dir).resolve("NARCISSUS")
    assert "circular" in str(exc.value)


# ---------------------------------------------------------------------------
# Destination-aware policy (COR-04)
# ---------------------------------------------------------------------------


def test_ip_address_permitted_for_internal_siem():
    """Scrubbing every IP destroys SIEM correlation (Requirement 40.2)."""
    p = resolve_profile("DEFAULT_PII")
    assert p.action_for("IP_ADDRESS", Destination.INTERNAL_SIEM) is ScrubAction.ALLOW


def test_ip_address_redacted_for_external_destinations():
    p = resolve_profile("DEFAULT_PII")
    for dest in (Destination.EXTERNAL_LLM, Destination.EXTERNAL_ANALYTICS, Destination.S3):
        assert p.action_for("IP_ADDRESS", dest) is ScrubAction.REDACT


def test_destination_sensitive_types_reported():
    p = resolve_profile("DEFAULT_PII")
    assert "IP_ADDRESS" in p.destination_sensitive_types
    assert "DATE_TIME" in p.destination_sensitive_types


def test_requires_destination_only_when_relevant():
    p = resolve_profile("DEFAULT_PII")
    assert p.requires_destination({"IP_ADDRESS"}) is True
    assert p.requires_destination({"PERSON", "EMAIL_ADDRESS"}) is False


def test_log_timestamps_are_exempt_from_date_scrubbing():
    """Otherwise every log line loses its timestamp (COR-04)."""
    p = resolve_profile("DEFAULT_PII")
    rule = p.rule_for("DATE_TIME")
    assert rule is not None
    assert "@timestamp" in rule.field_context_exempt
    assert "leading_iso_timestamp" in rule.field_context_exempt


# ---------------------------------------------------------------------------
# Chunk overlap derivation (G17 / COR-02)
# ---------------------------------------------------------------------------


def test_max_pattern_span_accommodates_pem_keys():
    """A 200-char overlap split PEM blocks and missed them in both halves."""
    p = resolve_profile("DEFAULT_PII")
    assert p.max_pattern_span >= 8192


def test_max_pattern_span_never_below_configured_floor():
    p = resolve_profile("BASE_SECURITY")
    assert p.max_pattern_span >= MIN_CHUNK_OVERLAP_CHARS


# ---------------------------------------------------------------------------
# Determinism and caching
# ---------------------------------------------------------------------------


def test_resolution_is_deterministic():
    """Golden-dataset regression depends on this."""
    first = resolve_profile("DEFAULT_PII")
    second = resolve_profile("DEFAULT_PII")
    assert first.enabled_types == second.enabled_types
    assert {t: first.action_for(t) for t in first.enabled_types} == {
        t: second.action_for(t) for t in second.enabled_types
    }


def test_profile_order_does_not_change_effective_policy(custom_dir):
    """Combination must be commutative, or results depend on argument order."""
    _write(
        custom_dir,
        "ALPHA",
        "name: ALPHA\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [DEFAULT_PII]\n"
        "entities:\n  - type: PHONE_NUMBER\n    action: MASK\n",
    )
    _write(
        custom_dir,
        "BETA",
        "name: BETA\nversion: '1.0.0'\ndescription: x\n"
        "inherits: [DEFAULT_PII]\n"
        "entities:\n  - type: PHONE_NUMBER\n    action: REDACT\n",
    )
    r = ProfileResolver(custom_dir)
    ab = r.resolve("ALPHA", "BETA")
    r.clear_cache()
    ba = r.resolve("BETA", "ALPHA")
    assert ab.action_for("PHONE_NUMBER") == ba.action_for("PHONE_NUMBER")


def test_versions_recorded_for_every_applied_profile():
    """Audit records must identify exactly which policy version was applied."""
    p = resolve_profile("DEFAULT_PII")
    assert p.profile_versions["BASE_SECURITY"] == "1.0.0"
    assert p.profile_versions["DEFAULT_PII"] == "1.0.0"


def test_shipped_profiles_all_validate():
    """Every profile in the repo must load cleanly."""
    resolver = ProfileResolver()
    for name in resolver.available_profiles():
        assert resolver.resolve(name) is not None
