"""Adversarial evasion suite.

Task 9.6. Requirement 33. Guardrails G2, G3.

The threat: content reaching this tool is attacker-writable. Anyone who can
trigger a log line can choose how the sensitive value is spelled. If a zero-width
space inside an SSN defeats the pattern, the scrub reports success and the SSN
ships.

So the tests below are not about tidy Unicode handling. Each one is an attack, and
the assertion is that the value still cannot survive a scrub.

Two of these document **known gaps** rather than defences. They are written as
explicit assertions of current behaviour, not skips, so that closing a gap makes a
test fail and someone updates it deliberately. A skipped test for an undefended
attack is how a gap becomes permanent.
"""

from __future__ import annotations

import base64

import pytest

from pii_agent.core.file_source import load_upload
from pii_agent.core.pipeline import ScanOptions, scan, scrub
from pii_agent.models.enums import Destination
from pii_agent.session.context import get_session_context
from pii_agent.utils.config import Settings
from pii_agent.utils.normalization import normalize

SSN = "482-71-9053"
CARD = "4532015112830366"


@pytest.fixture
def session(tmp_path):
    settings = Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"adversarial-salt",
        scan_roots=(),
        audit_dir=tmp_path / "audit",
    )
    return get_session_context(f"adv-{tmp_path.name}", settings)


def _scan(session, content: str, profile: str = "DEFAULT_PII"):
    loaded = load_upload(content.encode("utf-8"), "adv.log", session)
    return scan(
        loaded.handle,
        session,
        ScanOptions(profile_names=(profile,), destination=Destination.INTERNAL_SIEM),
    )


def _types(result) -> set[str]:
    return {e.type for e in result.entities}


def _scrub_text(session, content: str, profile: str = "DEFAULT_PII"):
    """Scrub and return the cleaned text, or None if no artifact was produced."""
    loaded = load_upload(content.encode("utf-8"), "adv.log", session)
    result = scrub(
        loaded.handle,
        session,
        ScanOptions(profile_names=(profile,), destination=Destination.INTERNAL_SIEM),
    )
    if not result.sanitized_handle:
        return None, result
    return session.content_store.get(result.sanitized_handle).content, result


# ---------------------------------------------------------------------------
# Zero-width and bidirectional control characters
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "invisible",
    [
        "\u200b",  # zero width space
        "\u200c",  # zero width non-joiner
        "\u200d",  # zero width joiner
        "\u2060",  # word joiner
        "\ufeff",  # BOM
        "\u00ad",  # soft hyphen
        "\u202e",  # right-to-left override
    ],
    ids=lambda c: f"U+{ord(c):04X}",
)
def test_invisible_character_inside_an_ssn_does_not_prevent_detection(
    session, invisible
):
    content = f"user record ssn={SSN[:6]}{invisible}{SSN[6:]} verified\n"
    assert "US_SSN" in _types(_scan(session, content))


def test_invisible_characters_are_reported_as_an_evasion_signal(session):
    """Their presence in otherwise-normal text is itself a finding (R33.6)."""
    content = f"ssn={SSN[:6]}\u200b{SSN[6:]}\n"
    result = _scan(session, content)
    assert any("zero-width" in w for w in result.warnings)


def test_an_evaded_ssn_is_actually_removed_from_the_artifact(session):
    """The offset map has to survive normalization or the scrub lands wrong.

    This is the assertion that matters: detection alone is worthless if the
    replacement misses because offsets shifted.
    """
    content = f"ssn={SSN[:6]}\u200b{SSN[6:]} card={CARD}\n"
    cleaned, result = _scrub_text(session, content)

    assert cleaned is not None, f"no artifact: {result.refusal}"
    # Neither the evaded form nor the plain form may survive.
    assert SSN not in cleaned
    assert f"{SSN[:6]}\u200b{SSN[6:]}" not in cleaned
    assert CARD not in cleaned


# ---------------------------------------------------------------------------
# Homoglyphs
# ---------------------------------------------------------------------------
def test_cyrillic_homoglyph_in_a_keyword_still_triggers_detection(session):
    """"pаssword" with a Cyrillic а renders identically to the Latin spelling."""
    content = "config load p\u0430ssword=Tr0ub4dor3xK9 host=db1\n"
    result = _scan(session, content, profile="BASE_SECURITY")
    assert "PASSWORD" in _types(result)


def test_fullwidth_digits_in_an_ssn_are_folded(session):
    content = "ssn=\uff14\uff18\uff12-71-9053 status=ok\n"
    assert "US_SSN" in _types(_scan(session, content))


def test_lookalike_dash_does_not_break_an_ssn(session):
    """An en-dash instead of a hyphen defeats a naive pattern."""
    content = f"ssn={SSN[:3]}\u2013{SSN[4:6]}\u2013{SSN[7:]} status=ok\n"
    assert "US_SSN" in _types(_scan(session, content))


def test_combining_marks_do_not_hide_an_email(session):
    content = "contact=dana@ex\u00e4mple.com role=admin\n"
    assert "EMAIL_ADDRESS" in _types(_scan(session, content))


def test_homoglyphs_are_reported_as_an_evasion_signal(session):
    content = "p\u0430ssword=Tr0ub4dor3xK9\n"
    result = _scan(session, content, profile="BASE_SECURITY")
    assert any("homoglyph" in w for w in result.warnings)


# ---------------------------------------------------------------------------
# Case alternation
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("spelling", ["PASSWORD", "PaSsWoRd", "password", "PassWord"])
def test_case_alternation_in_a_field_label_is_ignored(session, spelling):
    content = f"cfg {spelling}=Tr0ub4dor3xK9 host=db1\n"
    result = _scan(session, content, profile="BASE_SECURITY")
    assert "PASSWORD" in _types(result)


@pytest.mark.parametrize("spelling", ["cvv", "CVV", "Cvv", "cVv"])
def test_case_alternation_in_a_payment_label_is_ignored(session, spelling):
    content = f"txn {spelling}=418 amount=42.00\n"
    result = _scan(session, content, profile="PAYMENT_PCI")
    assert "CVV" in _types(result)


# ---------------------------------------------------------------------------
# Combined attack
# ---------------------------------------------------------------------------
def test_stacked_evasions_still_yield_a_verified_clean_artifact(session):
    """Homoglyph, zero-width and lookalike punctuation at once."""
    evaded_ssn = f"{SSN[:3]}\u2013{SSN[4:6]}\u200b\u2013{SSN[7:]}"
    content = (
        f"2026-03-04T08:00:00Z INFO p\u0430ssword=Tr0ub4dor3xK9 "
        f"ssn={evaded_ssn} card={CARD}\n"
    )
    cleaned, result = _scrub_text(session, content)

    assert cleaned is not None, f"no artifact: {result.refusal}"
    assert result.verified_clean is True
    assert CARD not in cleaned
    assert "Tr0ub4dor3xK9" not in cleaned
    # Timestamps survive — evasion handling must not destroy operational value.
    assert "2026-03-04T08:00:00Z" in cleaned


# ---------------------------------------------------------------------------
# Normalization must not corrupt clean text
# ---------------------------------------------------------------------------
def test_normalization_leaves_ordinary_text_untouched():
    """A defence that rewrites innocent text would corrupt every artifact."""
    text = "2026-03-04T08:00:00Z INFO svc=payments amount=42.00 ok\n"
    result = normalize(text)

    assert result.text == text
    assert result.was_modified is False
    assert result.index_map.is_identity
    assert result.evasion_signals == []


def test_normalization_never_grows_the_text():
    """One normalized character must have exactly one original source.

    If normalization could expand, an offset would map to several originals and
    the applier could not place a replacement.
    """
    for text in (
        "plain ascii",
        "p\u0430ssword=x",
        "\u200b\u200c\u200d",
        "caf\u00e9 na\u00efve",
        "\uff14\uff18\uff12",
    ):
        result = normalize(text)
        assert len(result.text) <= len(text)
        assert len(result.index_map.positions) == len(result.text)


# ---------------------------------------------------------------------------
# KNOWN GAPS — these assert current behaviour, not desired behaviour
# ---------------------------------------------------------------------------
# Written as passing assertions rather than skips. A skipped test for an
# undefended attack is how a gap becomes permanent; a passing assertion fails
# loudly the moment someone closes the gap, forcing a deliberate update.
# ---------------------------------------------------------------------------
# Spaced-character evasion — now defended
# ---------------------------------------------------------------------------
def test_spaced_ssn_is_detected(session):
    """``4 8 2 - 7 1 - 9 0 5 3`` was undetected until the second pass existed."""
    spaced = " ".join(SSN)
    assert "US_SSN" in _types(_scan(session, f"ssn={spaced} status=ok\n"))


def test_spaced_card_is_detected(session):
    spaced = " ".join(CARD)
    assert "CREDIT_CARD" in _types(_scan(session, f"card={spaced} amount=42\n"))


def test_spaced_evasion_is_reported_as_a_signal(session):
    spaced = " ".join(SSN)
    result = _scan(session, f"ssn={spaced}\n")
    assert any("spaces between characters" in w for w in result.warnings)


def test_a_spaced_ssn_is_actually_removed_from_the_artifact(session):
    """Offsets pass through two maps to get here, so this is the real check."""
    spaced = " ".join(SSN)
    cleaned, result = _scrub_text(session, f"ssn={spaced} port=443\n")

    assert cleaned is not None, f"no artifact: {result.refusal}"
    assert spaced not in cleaned
    # Unrelated fields are untouched.
    assert "port=443" in cleaned


def test_adjacent_numeric_fields_are_not_joined_into_a_false_finding(session):
    """The reason the pass is targeted rather than stripping all whitespace.

    Global stripping turns ``port=443 id=12 code=482 71 9053`` into one run and
    invents identifiers that were never in the source. Manufacturing an SSN is
    worse than missing a spaced one: it refuses correct artifacts and destroys
    real data.
    """
    content = "port=443 id=12 retries=3 code=48271 9053 status=ok\n"
    result = _scan(session, content)
    assert "US_SSN" not in _types(result)


def test_ordinary_log_lines_do_not_trigger_the_second_pass(session):
    content = (
        "2026-03-04T08:00:00Z INFO svc=payments amount=42.00 "
        "duration_ms=1841 status=ok\n"
    )
    result = _scan(session, content)
    assert not any("spaces between characters" in w for w in result.warnings)


def test_gap_base64_encoded_values_are_not_decoded(session):
    """KNOWN GAP. A base64-encoded SSN is not detected.

    Nothing in the pipeline decodes candidate blobs and re-scans. Doing so is a
    real design decision with a cost: every base64-shaped token would need
    decoding and a second detection pass, and log files are full of base64 that
    decodes to noise.

    Note this is an *evasion* gap, not an accidental-disclosure gap. Someone
    logging PII by mistake logs it in plaintext; base64 implies intent.
    """
    encoded = base64.b64encode(SSN.encode()).decode()
    result = _scan(session, f"payload={encoded} status=ok\n")
    assert "US_SSN" not in _types(result), (
        "base64 decoding is now implemented — update the docs and this test."
    )


def test_gap_hex_encoded_values_are_not_decoded(session):
    """KNOWN GAP. Same reasoning as base64."""
    encoded = SSN.encode().hex()
    result = _scan(session, f"payload={encoded} status=ok\n")
    assert "US_SSN" not in _types(result), (
        "hex decoding is now implemented — update the docs and this test."
    )


def test_gap_encoded_values_produce_no_warning(session):
    """KNOWN GAP. Encoded payloads are neither decoded nor flagged.

    Detection cannot catch everything, but a signal is cheap and this is where it
    is missing: a base64 blob adjacent to PII-ish field names is at least worth
    mentioning. Recorded so the absence stays deliberate and reviewable.
    """
    encoded = base64.b64encode(SSN.encode()).decode()
    result = _scan(session, f"ssn_b64={encoded}\n")
    assert result.warnings == []
