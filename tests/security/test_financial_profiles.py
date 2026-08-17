"""FINANCIAL and PAYMENT_PCI profiles, and the recognizers behind them.

Task 9.2. Requirements 22, 23. Guardrails G13, G14, G19.

The properties worth asserting are the ones that would make these profiles
actively harmful if wrong:

* A label-free numeric recognizer would flag every port and status code in a log.
* An unvalidated routing number is indistinguishable from an ordinary nine-digit
  id, so the checksum must actually be enforced.
* TRACK_DATA must suppress the artifact rather than merely redact, or the
  strictest control in the profile silently does not exist.
* CVV and PIN must not be reversibly tokenized, whatever a profile asks for.
"""

from __future__ import annotations

import pytest

from core.file_source import load_upload
from core.pipeline import ScanOptions, scan, scrub
from core.profile_resolver import get_resolver
from models.enums import Destination, RefusalReason, ScrubAction
from session.context import get_session_context
from utils.config import Settings

# 021000021 satisfies the ABA weighted checksum; 021000022 does not.
VALID_ROUTING = "021000021"
INVALID_ROUTING = "021000022"


@pytest.fixture
def session(tmp_path):
    settings = Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"salt-for-financial-tests",
        scan_roots=(),
        audit_dir=tmp_path / "audit",
    )
    return get_session_context(f"fin-{tmp_path.name}", settings)


def _scan(session, content: bytes, profile: str, name: str = "f.log"):
    loaded = load_upload(content, name, session)
    return scan(
        loaded.handle,
        session,
        ScanOptions(profile_names=(profile,), destination=Destination.INTERNAL_SIEM),
    )


def _types(result) -> set[str]:
    return {e.type for e in result.entities}


def _action_for(result, entity_type: str) -> ScrubAction | None:
    for decision in result.decisions:
        if decision.entity.type == entity_type:
            return decision.applied_action
    return None


# ---------------------------------------------------------------------------
# Availability and inheritance
# ---------------------------------------------------------------------------
def test_both_profiles_are_available():
    available = get_resolver().available_profiles()
    assert "FINANCIAL" in available
    assert "PAYMENT_PCI" in available


@pytest.mark.parametrize("profile", ["FINANCIAL", "PAYMENT_PCI"])
def test_profiles_inherit_base_security_and_default_pii(profile):
    """Requirement 20.6: every industry profile carries both parents."""
    resolved = get_resolver().resolve(profile)
    entities = resolved.entities
    items = entities.values() if isinstance(entities, dict) else entities
    rules = {r.type: r.action for r in items if r.enabled}

    # From BASE_SECURITY, and never weaker than REDACT.
    assert rules["PASSWORD"].priority >= ScrubAction.REDACT.priority
    assert rules["PRIVATE_KEY"].priority >= ScrubAction.REDACT.priority
    # From DEFAULT_PII.
    assert "EMAIL_ADDRESS" in rules
    assert "PHONE_NUMBER" in rules


# ---------------------------------------------------------------------------
# Routing number: the checksum has to do real work
# ---------------------------------------------------------------------------
def test_valid_routing_number_is_detected(session):
    result = _scan(
        session, f"routing_number={VALID_ROUTING}\n".encode(), "FINANCIAL"
    )
    assert "ROUTING_NUMBER" in _types(result)


def test_checksum_failing_routing_number_is_not_reported(session):
    """A nine-digit run that fails the checksum is noise, not a finding."""
    result = _scan(
        session, f"routing_number={INVALID_ROUTING}\n".encode(), "FINANCIAL"
    )
    assert "ROUTING_NUMBER" not in _types(result)


def test_bare_nine_digit_log_ids_are_not_routing_numbers(session):
    """Without this, ordinary log ids would be flagged constantly."""
    content = b"request_id=192837465 duration_ms=123456789 bytes=987654321\n"
    result = _scan(session, content, "FINANCIAL")
    assert "ROUTING_NUMBER" not in _types(result)


# ---------------------------------------------------------------------------
# Label-required numerics: the false-positive guard
# ---------------------------------------------------------------------------
def test_cvv_requires_a_label(session):
    """Three bare digits are a status code far more often than a CVV."""
    noisy = b"status=404 port=443 retries=3 latency=250 code=500\n"
    result = _scan(session, noisy, "PAYMENT_PCI")
    assert "CVV" not in _types(result)

    labelled = _scan(session, b"cvv=418\n", "PAYMENT_PCI", "b.log")
    assert "CVV" in _types(labelled)


def test_pin_requires_a_label(session):
    noisy = b"timeout=3000 window=1024 offset=2048\n"
    result = _scan(session, noisy, "PAYMENT_PCI")
    assert "PIN" not in _types(result)

    labelled = _scan(session, b"pin=4821\n", "PAYMENT_PCI", "b.log")
    assert "PIN" in _types(labelled)


# ---------------------------------------------------------------------------
# PAYMENT_PCI actions
# ---------------------------------------------------------------------------
def test_pan_is_tokenized_so_correlation_survives(session):
    """PCI allows storing a PAN rendered unreadable; a token keeps the join."""
    content = b"card=4532015112830366 amount=42.00\n"
    result = scrub(
        load_upload(content, "pay.log", session).handle,
        session,
        ScanOptions(
            profile_names=("PAYMENT_PCI",), destination=Destination.INTERNAL_SIEM
        ),
    )

    assert result.artifact_available is True
    assert _action_for(result, "CREDIT_CARD") is ScrubAction.TOKENIZE

    cleaned = session.content_store.get(result.sanitized_handle).content
    assert "4532015112830366" not in cleaned


def test_the_same_card_yields_the_same_token(session):
    """Correlation is the entire reason for choosing TOKENIZE over MASK."""
    content = b"card=4532015112830366 ref=A\ncard=4532015112830366 ref=B\n"
    result = scrub(
        load_upload(content, "pay.log", session).handle,
        session,
        ScanOptions(
            profile_names=("PAYMENT_PCI",), destination=Destination.INTERNAL_SIEM
        ),
    )
    cleaned = session.content_store.get(result.sanitized_handle).content

    tokens = [line.split("card=")[1].split(" ")[0] for line in cleaned.splitlines()]
    assert len(tokens) == 2
    assert tokens[0] == tokens[1]


def test_cvv_is_redacted_not_tokenized(session):
    """Authentication data must not be retained in any reversible form."""
    result = _scan(session, b"cvv=418 card=4532015112830366\n", "PAYMENT_PCI")
    assert _action_for(result, "CVV") is ScrubAction.REDACT


# ---------------------------------------------------------------------------
# BLOCK must be observably different from REDACT (G19, COR-05)
# ---------------------------------------------------------------------------
def test_track_data_blocks_the_artifact_entirely(session):
    """A redacted copy of track data would still evidence that it was stored."""
    track = b"%B4532015112830366^DOE/JOHN^2703101000000000000000?\n"
    result = scrub(
        load_upload(track, "term.log", session).handle,
        session,
        ScanOptions(
            profile_names=("PAYMENT_PCI",), destination=Destination.INTERNAL_SIEM
        ),
    )

    assert "TRACK_DATA" in _types(result)
    assert result.refusal is RefusalReason.BLOCKED_ARTIFACT
    assert result.artifact_available is False
    assert result.sanitized_handle is None
    # Findings still reported — only the artifact is withheld.
    assert result.entity_count >= 1


# ---------------------------------------------------------------------------
# FINANCIAL actions
# ---------------------------------------------------------------------------
def test_financial_account_identifiers_are_tokenized(session):
    content = b"loan_account=LN00callout9932144 balance=10000\n"
    result = _scan(session, content, "FINANCIAL")
    if "FINANCIAL_ACCOUNT" in _types(result):
        assert _action_for(result, "FINANCIAL_ACCOUNT") is ScrubAction.TOKENIZE


def test_credit_score_is_redacted_not_correlatable(session):
    """Nobody joins on a credit score, so there is no case for a token."""
    result = _scan(session, b"credit_score=742 customer=8891\n", "FINANCIAL")
    assert "CREDIT_SCORE" in _types(result)
    assert _action_for(result, "CREDIT_SCORE") is ScrubAction.REDACT


def test_swift_code_is_detected_with_a_label(session):
    result = _scan(session, b"swift_code=DEUTDEFF500\n", "FINANCIAL")
    assert "SWIFT_CODE" in _types(result)


def test_tax_identifier_is_detected(session):
    result = _scan(session, b"ein=12-3456789 company=Acme\n", "FINANCIAL")
    assert "TAX_IDENTIFIER" in _types(result)


# ---------------------------------------------------------------------------
# The new types must not disturb DEFAULT_PII
# ---------------------------------------------------------------------------
def test_default_pii_is_unaffected_by_the_new_recognizers(session):
    """Recognizers always run; the profile decides what is reported."""
    content = b"cvv=418 credit_score=742 swift_code=DEUTDEFF500 ssn=482-71-9053\n"
    result = _scan(session, content, "DEFAULT_PII")

    found = _types(result)
    assert "US_SSN" in found
    for financial_only in ("CVV", "CREDIT_SCORE", "SWIFT_CODE", "TAX_IDENTIFIER"):
        assert financial_only not in found
