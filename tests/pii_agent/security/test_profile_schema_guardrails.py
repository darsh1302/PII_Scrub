"""Guardrails G5 and G14 — profile schema rejects unsafe policy at load time.

These are load-time rejections rather than runtime checks because both failures
are invisible afterwards. A profile hashing SSNs looks protective and is not; a
profile allowing API keys silently disables the one unconditional control.
"""

from __future__ import annotations

import pytest

from pii_agent.models.enums import ScrubAction
from pii_agent.profiles.schema import (
    BASE_SECURITY_TYPES,
    ProfileValidationError,
    validate_profile_dict,
)
from pii_agent.session.token_vault import LOW_ENTROPY_TYPES


def _profile(entities: list[dict], **overrides) -> dict:
    base = {
        "name": "TEST_PROFILE",
        "version": "1.0.0",
        "description": "fixture",
        "entities": entities,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# G14 — HASH is pseudonymization, not anonymization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entity_type", sorted(LOW_ENTROPY_TYPES))
def test_hash_rejected_for_low_entropy_types(entity_type: str):
    """The SSN space is ~10^9 — a salted digest is exhaustible (SEC-12)."""
    with pytest.raises(ProfileValidationError) as exc:
        validate_profile_dict(
            _profile([{"type": entity_type, "action": "HASH"}])
        )
    assert "low-entropy" in str(exc.value)


@pytest.mark.parametrize("entity_type", sorted(LOW_ENTROPY_TYPES))
def test_allow_rejected_for_low_entropy_types(entity_type: str):
    with pytest.raises(ProfileValidationError):
        validate_profile_dict(
            _profile([{"type": entity_type, "action": "ALLOW"}])
        )


@pytest.mark.parametrize("action", ["TOKENIZE", "REDACT", "MASK", "BLOCK"])
def test_adequate_actions_accepted_for_low_entropy_types(action: str):
    """The rejection must not be so broad that no action is usable."""
    profile = validate_profile_dict(
        _profile([{"type": "US_SSN", "action": action}])
    )
    assert profile.entities["US_SSN"].action == ScrubAction(action)


def test_hash_permitted_for_high_entropy_types():
    """HASH stays available where the value space is large."""
    profile = validate_profile_dict(
        _profile([{"type": "EMAIL_ADDRESS", "action": "HASH"}])
    )
    assert profile.entities["EMAIL_ADDRESS"].action is ScrubAction.HASH


# ---------------------------------------------------------------------------
# G5 — BASE_SECURITY cannot be weakened
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entity_type", sorted(BASE_SECURITY_TYPES))
@pytest.mark.parametrize("weak_action", ["ALLOW", "REPLACE", "MASK"])
def test_base_security_entity_cannot_be_weakened(
    entity_type: str, weak_action: str
):
    """An operator picking the wrong profile must still not leak a credential."""
    with pytest.raises(ProfileValidationError) as exc:
        validate_profile_dict(
            _profile([{"type": entity_type, "action": weak_action}])
        )
    assert "BASE_SECURITY minimum" in str(exc.value)


def test_base_security_entity_may_be_strengthened():
    """BLOCK is stricter than REDACT — allowed."""
    profile = validate_profile_dict(
        _profile([{"type": "API_KEY", "action": "BLOCK"}])
    )
    assert profile.entities["API_KEY"].action is ScrubAction.BLOCK


def test_documented_security_exception_is_honoured():
    """An escape hatch exists but must be explicit and visible in the file."""
    profile = validate_profile_dict(
        _profile(
            [
                {
                    "type": "SESSION_COOKIE",
                    "action": "MASK",
                    "security_exception_approved": True,
                }
            ]
        )
    )
    assert profile.entities["SESSION_COOKIE"].action is ScrubAction.MASK


def test_destination_override_cannot_weaken_base_security():
    """A destination must not become a loophole around G5."""
    with pytest.raises(ProfileValidationError) as exc:
        validate_profile_dict(
            _profile(
                [
                    {
                        "type": "API_KEY",
                        "action": "REDACT",
                        "destination_actions": {"INTERNAL_SIEM": "ALLOW"},
                    }
                ]
            )
        )
    assert "weaker than the" in str(exc.value)


# ---------------------------------------------------------------------------
# Structural validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("missing", ["name", "version", "description"])
def test_missing_required_key_is_rejected(missing: str):
    data = _profile([{"type": "PERSON", "action": "REPLACE"}])
    del data[missing]
    with pytest.raises(ProfileValidationError) as exc:
        validate_profile_dict(data)
    assert missing in str(exc.value)


def test_unknown_action_is_rejected_with_valid_options():
    with pytest.raises(ProfileValidationError) as exc:
        validate_profile_dict(
            _profile([{"type": "PERSON", "action": "OBFUSCATE"}])
        )
    assert "REDACT" in str(exc.value)  # lists valid actions


def test_unknown_required_detector_is_rejected():
    with pytest.raises(ProfileValidationError) as exc:
        validate_profile_dict(
            _profile(
                [{"type": "PERSON", "action": "REPLACE"}],
                required_detectors=["presidio", "telepathy"],
            )
        )
    assert "telepathy" in str(exc.value)


def test_duplicate_entity_type_is_rejected():
    """Silent last-wins would make the effective policy ambiguous."""
    with pytest.raises(ProfileValidationError) as exc:
        validate_profile_dict(
            _profile(
                [
                    {"type": "PERSON", "action": "REPLACE"},
                    {"type": "PERSON", "action": "REDACT"},
                ]
            )
        )
    assert "duplicate" in str(exc.value)


@pytest.mark.parametrize("bad", [-0.1, 1.5, "high", None])
def test_out_of_range_confidence_threshold_is_rejected(bad):
    if bad is None:
        pytest.skip("None means 'use default', which is valid")
    with pytest.raises(ProfileValidationError):
        validate_profile_dict(
            _profile(
                [
                    {
                        "type": "PERSON",
                        "action": "REPLACE",
                        "confidence_threshold": bad,
                    }
                ]
            )
        )


def test_error_messages_name_the_offending_file(tmp_path):
    """An operator must be able to find the file that failed."""
    from pii_agent.profiles.schema import load_profile_file

    bad = tmp_path / "BROKEN.yaml"
    bad.write_text("name: BROKEN\nversion: '1.0'\n", encoding="utf-8")

    with pytest.raises(ProfileValidationError) as exc:
        load_profile_file(bad)
    assert "BROKEN.yaml" in str(exc.value)


def test_missing_profile_file_refuses_rather_than_defaulting(tmp_path):
    """No silent fallback to built-in rules (Requirement 19.10)."""
    from pii_agent.profiles.schema import load_profile_file

    with pytest.raises(ProfileValidationError) as exc:
        load_profile_file(tmp_path / "ABSENT.yaml")
    assert "not found" in str(exc.value)


def test_invalid_yaml_refuses_rather_than_defaulting(tmp_path):
    from pii_agent.profiles.schema import load_profile_file

    bad = tmp_path / "MALFORMED.yaml"
    bad.write_text("name: [unclosed\n", encoding="utf-8")

    with pytest.raises(ProfileValidationError) as exc:
        load_profile_file(bad)
    assert "invalid YAML" in str(exc.value)


def test_filename_must_match_profile_name(tmp_path):
    """A mismatch makes the active policy ambiguous in audit records."""
    from pii_agent.profiles.schema import load_profile_file

    path = tmp_path / "PRODUCTION.yaml"
    path.write_text(
        "name: STAGING\nversion: '1.0.0'\ndescription: x\n", encoding="utf-8"
    )

    with pytest.raises(ProfileValidationError) as exc:
        load_profile_file(path)
    assert "does not match" in str(exc.value)
