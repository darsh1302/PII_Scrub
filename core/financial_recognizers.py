"""Recognizers for the FINANCIAL and PAYMENT_PCI profiles.

Task 9.2. Guardrails G13, G14.

Kept separate from ``recognizers.py`` because those close the credential gap in
BASE_SECURITY and always run; these are only meaningful when a financial or
payment profile is active.

Two rules shape everything here.

**Bare digit runs are never matched.** A CVV is three digits and a PIN is four.
Matching those without a label would flag every port number, HTTP status, byte
count and millisecond timing in a log file. Every low-entropy numeric type below
requires an adjacent field label, which trades recall for a false-positive rate
that does not make the output unusable.

**Checksums are used where they exist.** A validated match is marked
CALIBRATED and wins reconciliation against a statistical guess; an unvalidated
one should not claim the same standing. ABA routing numbers have a checksum, so
it is enforced rather than treated as nine digits.

Patterns are linear-time: bounded repetition, no nested unbounded quantifiers.
"""

from __future__ import annotations

import re

from presidio_analyzer import Pattern, PatternRecognizer

# --------------------------------------------------------------------------
# Bank routing number (US ABA)
# --------------------------------------------------------------------------
ROUTING_NUMBER_PATTERNS = [
    Pattern(
        name="routing_number_labelled",
        regex=(
            r"(?i:\b(?:routing[_\- ]?(?:number|no|#)?|aba(?:[_\- ]?number)?|"
            r"rtn)\b)[ \t]{0,4}[:=]?[ \t]{0,4}(\d{9})\b"
        ),
        score=0.6,
    ),
    # No unlabelled fallback, deliberately. One in ten nine-digit numbers passes
    # the ABA checksum by chance, so an unlabelled match is overwhelmingly a
    # coincidence — and in a log full of ids and durations it matched constantly,
    # adding hundreds of candidates per chunk that reconciliation then had to
    # process. That volume pushed large inputs past the tool budget, which the
    # coverage gate correctly reported as incomplete. Recall here is not worth an
    # unverifiable finding plus a fail-closed refusal.
]


class RoutingNumberRecognizer(PatternRecognizer):
    """ABA routing number with checksum validation.

    The nine-digit space is dense — a bare nine-digit run appears constantly in
    logs as an id or a timestamp fragment. The checksum is what makes this
    reportable rather than noise, so an unvalidated match is actively rejected
    rather than merely scored low.
    """

    def __init__(self) -> None:
        super().__init__(
            supported_entity="ROUTING_NUMBER",
            name="ROUTING_NUMBER_recognizer",
            patterns=ROUTING_NUMBER_PATTERNS,
            context=["routing", "aba", "bank", "account", "wire", "transit"],
        )

    def validate_result(self, pattern_text: str) -> bool | None:
        digits = re.sub(r"\D", "", pattern_text)
        if len(digits) != 9:
            return False
        # ABA weighted checksum: 3-7-1 repeating, sum must be divisible by 10.
        weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
        total = sum(int(d) * w for d, w in zip(digits, weights))
        if total % 10 != 0:
            return False
        # 000000000 passes the checksum arithmetically but is not a real routing
        # number, and appears in test fixtures and zero-filled fields.
        if digits == "000000000":
            return False
        return True


# --------------------------------------------------------------------------
# SWIFT / BIC
# --------------------------------------------------------------------------
# 4 letters institution, 2 letters ISO country, 2 alphanumeric location,
# optionally 3 alphanumeric branch. No checksum exists, so this stays format-only
# and carries a moderate score.
SWIFT_CODE_PATTERNS = [
    Pattern(
        name="swift_bic_labelled",
        regex=(
            r"(?i:\b(?:swift(?:[_\- ]?code)?|bic(?:[_\- ]?code)?)\b)"
            r"[ \t]{0,4}[:=]?[ \t]{0,4}([A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?)\b"
        ),
        score=0.75,
    ),
    # No unlabelled fallback: an 8-to-11 character uppercase alphanumeric run is
    # also every request id, hostname fragment and enum value in a log.
]

# --------------------------------------------------------------------------
# Payment card security values
# --------------------------------------------------------------------------
# Label required. Three or four bare digits cannot be distinguished from a status
# code, a port, or a duration.
CVV_PATTERNS = [
    Pattern(
        name="cvv_labelled",
        regex=(
            r"(?i:\b(?:cvv2?|cvc2?|cid|csc|card[_\- ]?(?:security|verification)"
            r"[_\- ]?(?:code|value)|security[_\- ]?code)\b)"
            r"[ \t]{0,4}[:=][ \t]{0,4}[\"']?(\d{3,4})[\"']?"
        ),
        score=0.8,
    ),
]

PIN_PATTERNS = [
    Pattern(
        name="pin_labelled",
        regex=(
            r"(?i:\b(?:pin|pin[_\- ]?(?:code|number|block)|"
            r"personal[_\- ]?identification[_\- ]?number)\b)"
            r"[ \t]{0,4}[:=][ \t]{0,4}[\"']?(\d{4,12})[\"']?"
        ),
        score=0.75,
    ),
]

# Magnetic stripe data. Distinctive enough to match without a label: track 1
# begins %B and track 2 is delimited by ; and ?, both with an embedded PAN.
TRACK_DATA_PATTERNS = [
    Pattern(
        name="track1",
        regex=r"%B\d{12,19}\^[A-Z /\.]{2,26}\^\d{4}[0-9A-Za-z \?]{0,60}\?",
        score=0.9,
    ),
    Pattern(
        name="track2",
        regex=r";\d{12,19}=\d{4}[0-9]{0,50}\?",
        score=0.9,
    ),
]

CARD_EXPIRY_PATTERNS = [
    Pattern(
        name="card_expiry_labelled",
        regex=(
            r"(?i:\b(?:exp(?:iry|iration)?(?:[_\- ]?date)?|valid[_\- ]?thru|"
            r"exp[_\- ]?m?y?)\b)"
            r"[ \t]{0,4}[:=][ \t]{0,4}[\"']?"
            r"((?:0[1-9]|1[0-2])[/\-](?:\d{2}|\d{4}))[\"']?"
        ),
        score=0.6,
    ),
]

# --------------------------------------------------------------------------
# Financial account identifiers
# --------------------------------------------------------------------------
# All label-required: an account number has no intrinsic format, so the field
# name is the only reliable signal.
FINANCIAL_ACCOUNT_PATTERNS = [
    Pattern(
        name="financial_account_labelled",
        regex=(
            r"(?i:\b(?:loan|mortgage|brokerage|investment|retirement|ira|"
            r"portfolio|policy)[_\- ]?(?:account|number|no|id|#)?\b)"
            r"[ \t]{0,4}[:=][ \t]{0,4}[\"']?([A-Z0-9\-]{6,32})[\"']?"
        ),
        score=0.6,
    ),
]

TAX_IDENTIFIER_PATTERNS = [
    Pattern(
        name="ein_labelled",
        regex=(
            r"(?i:\b(?:ein|employer[_\- ]?identification[_\- ]?number|"
            r"tax[_\- ]?(?:id|identifier|number)|tin)\b)"
            r"[ \t]{0,4}[:=]?[ \t]{0,4}(\d{2}-\d{7})\b"
        ),
        score=0.75,
    ),
    # No unlabelled fallback: ``NN-NNNNNNN`` is a common shape for order numbers,
    # part numbers and split identifiers.
]

CREDIT_SCORE_PATTERNS = [
    Pattern(
        name="credit_score_labelled",
        regex=(
            r"(?i:\b(?:credit[_\- ]?score|fico(?:[_\- ]?score)?|"
            r"vantage(?:score)?)\b)"
            r"[ \t]{0,4}[:=][ \t]{0,4}(\d{3})\b"
        ),
        score=0.7,
    ),
]

WIRE_INSTRUCTION_PATTERNS = [
    Pattern(
        name="wire_instruction_labelled",
        regex=(
            r"(?i:\b(?:wire[_\- ]?(?:instructions?|reference|details)|"
            r"beneficiary[_\- ]?account|iban[_\- ]?beneficiary)\b)"
            r"[ \t]{0,4}[:=][ \t]{0,4}[\"']?([A-Z0-9 \-]{8,64})[\"']?"
        ),
        score=0.6,
    ),
]


_DEFINITIONS: list[tuple[str, list[Pattern], list[str]]] = [
    ("SWIFT_CODE", SWIFT_CODE_PATTERNS, ["swift", "bic", "bank", "wire", "iban"]),
    ("CVV", CVV_PATTERNS, ["cvv", "cvc", "card", "security", "code"]),
    ("PIN", PIN_PATTERNS, ["pin", "card", "atm", "debit"]),
    ("TRACK_DATA", TRACK_DATA_PATTERNS, ["track", "stripe", "magstripe", "swipe"]),
    (
        "CARD_EXPIRY",
        CARD_EXPIRY_PATTERNS,
        ["expiry", "expiration", "card", "valid"],
    ),
    (
        "FINANCIAL_ACCOUNT",
        FINANCIAL_ACCOUNT_PATTERNS,
        ["loan", "mortgage", "brokerage", "investment", "retirement", "account"],
    ),
    ("TAX_IDENTIFIER", TAX_IDENTIFIER_PATTERNS, ["ein", "tax", "tin", "employer"]),
    ("CREDIT_SCORE", CREDIT_SCORE_PATTERNS, ["credit", "score", "fico"]),
    (
        "WIRE_INSTRUCTIONS",
        WIRE_INSTRUCTION_PATTERNS,
        ["wire", "beneficiary", "transfer", "swift"],
    ),
]


def build_financial_recognizers() -> list[PatternRecognizer]:
    """Construct the FINANCIAL and PAYMENT_PCI recognizers.

    Registered unconditionally alongside the security recognizers. Detection is
    cheap; whether a type is *reported* is decided by the active profile, so a
    DEFAULT_PII scan is unaffected by their presence.
    """
    recognizers: list[PatternRecognizer] = [RoutingNumberRecognizer()]
    for entity, patterns, context in _DEFINITIONS:
        recognizers.append(
            PatternRecognizer(
                supported_entity=entity,
                name=f"{entity}_recognizer",
                patterns=patterns,
                context=context,
            )
        )
    return recognizers


def financial_entity_types() -> tuple[str, ...]:
    return ("ROUTING_NUMBER", *(entity for entity, _, _ in _DEFINITIONS))
