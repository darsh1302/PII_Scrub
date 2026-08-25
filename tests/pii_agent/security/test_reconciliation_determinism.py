"""Guardrail G18 — reconciliation must be deterministic.

Addresses review finding COR-03. The reviewed design said reconciliation should
"determine the more appropriate classification when overlap exists", which is not
implementable and produces different output across runs. That breaks
golden-dataset regression testing — the mechanism meant to catch detection drift.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from pii_agent.core.detector import detect_chunk
from pii_agent.core.profile_resolver import resolve_profile
from pii_agent.core.reconciler import reconcile
from pii_agent.models.entities import Entity
from pii_agent.models.enums import ConfidenceSource, DetectorName, EntitySeverity

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _signature(entities: list[Entity]) -> list[tuple]:
    """Comparable, order-independent representation."""
    return [
        (e.type, e.start, e.end, round(e.confidence, 4), tuple(e.detected_by))
        for e in entities
    ]


# ---------------------------------------------------------------------------
# Determinism
# ---------------------------------------------------------------------------


def test_identical_input_yields_identical_output_over_many_runs():
    text = (FIXTURES / "sample_log.txt").read_text(encoding="utf-8")
    outcome = detect_chunk(text, threshold=0.3)

    baseline, _ = reconcile(list(outcome.entities))
    expected = _signature(baseline)

    for _ in range(100):
        result, _ = reconcile(list(outcome.entities))
        assert _signature(result) == expected


def test_input_order_does_not_affect_output():
    """Detector output order must not leak into results.

    Without rule 5 of the precedence order, equally-ranked candidates would
    resolve by iteration order and shuffling the input would change the result.
    """
    text = (FIXTURES / "sample_log.txt").read_text(encoding="utf-8")
    entities = detect_chunk(text, threshold=0.3).entities

    baseline, _ = reconcile(list(entities))
    expected = _signature(baseline)

    rng = random.Random(20260816)
    for _ in range(30):
        shuffled = list(entities)
        rng.shuffle(shuffled)
        result, _ = reconcile(shuffled)
        assert _signature(result) == expected


def test_output_is_sorted_by_position():
    text = (FIXTURES / "sample_log.txt").read_text(encoding="utf-8")
    result, _ = reconcile(detect_chunk(text, threshold=0.3).entities)
    positions = [(e.start, e.end) for e in result]
    assert positions == sorted(positions)


# ---------------------------------------------------------------------------
# Precedence rules, individually
# ---------------------------------------------------------------------------


def _entity(
    entity_type: str,
    start: int,
    end: int,
    *,
    confidence: float = 0.8,
    detector: str = DetectorName.PRESIDIO.value,
    severity: EntitySeverity | None = None,
    source: ConfidenceSource = ConfidenceSource.CALIBRATED,
) -> Entity:
    return Entity(
        type=entity_type,
        start=start,
        end=end,
        confidence=confidence,
        text="x" * (end - start),
        detected_by=[detector],
        severity=severity,
        confidence_source=source,
    )


def test_rule1_longest_span_wins():
    """Applies to overlaps that are not permitted nesting.

    LOCATION/PERSON is deliberately excluded here — that pair is in the nesting
    allowlist and both are expected to survive (see the nesting tests below).
    """
    short = _entity("PERSON", 10, 15, severity=EntitySeverity.MEDIUM)
    long = _entity("PHONE_NUMBER", 10, 40, severity=EntitySeverity.MEDIUM)
    result, _ = reconcile([short, long])
    assert len(result) == 1
    assert result[0].type == "PHONE_NUMBER"


def test_severity_beats_length():
    """A credential is not displaced by a longer low-severity span.

    Length used to be the first question, which meant a wide DATE_TIME match
    could swallow an API_KEY inside it. Since the losing entity may then be
    filtered out by the profile, that silently lost the credential — the same
    failure mode as the IBAN/ORGANIZATION defect below.

    The loser's uncovered remainder survives as a trimmed entity, so the wider
    match is not discarded wholesale either.
    """
    long_low = _entity("DATE_TIME", 0, 60, severity=EntitySeverity.LOW)
    short_high = _entity("API_KEY", 10, 20, severity=EntitySeverity.HIGH)
    result, _ = reconcile([long_low, short_high])

    types = [e.type for e in result]
    assert "API_KEY" in types
    api_key = next(e for e in result if e.type == "API_KEY")
    assert api_key.span == (10, 20)
    # Any surviving DATE_TIME must be a trimmed remainder, not the full span.
    for entity in result:
        if entity.type == "DATE_TIME":
            assert entity.metadata.get("trimmed") is True
            assert not entity.overlaps(api_key)


def test_rule2_higher_severity_wins_on_equal_length():
    low = _entity("DATE_TIME", 0, 10, severity=EntitySeverity.LOW)
    high = _entity("API_KEY", 0, 10, severity=EntitySeverity.HIGH)
    result, _ = reconcile([low, high])
    assert len(result) == 1
    assert result[0].type == "API_KEY"


def test_rule3_validator_backed_wins_on_equal_length_and_severity():
    """A Luhn-checked card beats a bare bank-number guess over the same digits."""
    guess = _entity("US_BANK_NUMBER", 0, 16, severity=EntitySeverity.MEDIUM)
    validated = _entity("CREDIT_CARD", 0, 16, severity=EntitySeverity.MEDIUM)
    result, _ = reconcile([guess, validated])
    assert len(result) == 1
    assert result[0].type == "CREDIT_CARD"


def test_rule4_detector_precedence_breaks_remaining_ties():
    from_spacy = _entity(
        "ORGANIZATION", 0, 10, detector=DetectorName.SPACY.value,
        severity=EntitySeverity.LOW,
    )
    from_security = _entity(
        "API_KEY", 0, 10, detector=DetectorName.CUSTOM_SECURITY.value,
        severity=EntitySeverity.LOW,
    )
    result, _ = reconcile([from_spacy, from_security])
    assert len(result) == 1
    assert result[0].type == "API_KEY"


def test_rule5_guarantees_no_tie_survives():
    """Two otherwise-identical candidates must resolve deterministically."""
    a = _entity("AAA_TYPE", 0, 10, severity=EntitySeverity.MEDIUM)
    b = _entity("ZZZ_TYPE", 0, 10, severity=EntitySeverity.MEDIUM)
    first, _ = reconcile([a, b])
    second, _ = reconcile([b, a])
    assert len(first) == 1
    assert _signature(first) == _signature(second)


# ---------------------------------------------------------------------------
# Duplicates and corroboration
# ---------------------------------------------------------------------------


def test_exact_duplicates_are_merged_recording_both_detectors():
    presidio = _entity("PERSON", 0, 10, detector=DetectorName.PRESIDIO.value)
    spacy = _entity(
        "PERSON", 0, 10, detector=DetectorName.SPACY.value,
        source=ConfidenceSource.HEURISTIC,
    )
    result, stats = reconcile([presidio, spacy])
    assert len(result) == 1
    assert stats.duplicates_merged == 1
    assert set(result[0].detected_by) == {"presidio", "spacy"}


def test_heuristic_confidence_does_not_inflate_a_calibrated_score():
    """spaCy's constant must not be treated as a real probability."""
    calibrated = _entity("PERSON", 0, 10, confidence=0.55)
    heuristic = _entity(
        "PERSON", 0, 10, confidence=0.99, detector=DetectorName.SPACY.value,
        source=ConfidenceSource.HEURISTIC,
    )
    result, _ = reconcile([calibrated, heuristic])
    assert result[0].confidence == pytest.approx(0.55)
    assert result[0].confidence_source is ConfidenceSource.CALIBRATED


def test_calibrated_score_upgrades_a_heuristic_one():
    heuristic = _entity(
        "PERSON", 0, 10, confidence=0.6, detector=DetectorName.SPACY.value,
        source=ConfidenceSource.HEURISTIC,
    )
    calibrated = _entity("PERSON", 0, 10, confidence=0.85)
    result, _ = reconcile([heuristic, calibrated])
    assert result[0].confidence == pytest.approx(0.85)
    assert result[0].confidence_source is ConfidenceSource.CALIBRATED


def test_base_security_flag_survives_merging():
    """A credential must not lose its BASE_SECURITY status through a merge."""
    plain = _entity("API_KEY", 0, 10)
    security = _entity("API_KEY", 0, 10)
    security.is_base_security = True
    result, _ = reconcile([plain, security])
    assert result[0].is_base_security is True


# ---------------------------------------------------------------------------
# Nesting
# ---------------------------------------------------------------------------


def test_permitted_nesting_is_preserved():
    """A PERSON inside a LOCATION is genuinely two facts."""
    location = _entity("LOCATION", 0, 50, severity=EntitySeverity.LOW)
    person = _entity("PERSON", 10, 20, severity=EntitySeverity.MEDIUM)
    result, stats = reconcile([location, person])
    assert len(result) == 2
    assert stats.nested_preserved == 1


def test_jwt_inside_authorization_header_is_preserved():
    header = _entity("AUTHORIZATION_HEADER", 0, 200, severity=EntitySeverity.HIGH)
    jwt = _entity("JWT", 22, 190, severity=EntitySeverity.HIGH)
    result, _ = reconcile([header, jwt])
    assert {e.type for e in result} == {"AUTHORIZATION_HEADER", "JWT"}


def test_unpermitted_nesting_collapses_to_one_entity():
    outer = _entity("PERSON", 0, 50, severity=EntitySeverity.MEDIUM)
    inner = _entity("DATE_TIME", 10, 20, severity=EntitySeverity.LOW)
    result, _ = reconcile([outer, inner])
    assert len(result) == 1
    assert result[0].type == "PERSON"


# ---------------------------------------------------------------------------
# Structural invariants
# ---------------------------------------------------------------------------


def test_non_overlapping_entities_all_survive():
    entities = [_entity("PERSON", i * 20, i * 20 + 10) for i in range(10)]
    result, _ = reconcile(entities)
    assert len(result) == 10


def test_empty_input_yields_empty_output():
    result, stats = reconcile([])
    assert result == []
    assert stats.output_count == 0


def test_output_never_exceeds_input():
    text = (FIXTURES / "sample_log.txt").read_text(encoding="utf-8")
    entities = detect_chunk(text, threshold=0.3).entities
    result, stats = reconcile(entities)
    assert len(result) <= len(entities)
    assert stats.input_count == len(entities)
    assert stats.output_count == len(result)


def test_no_unpermitted_overlaps_remain_in_output():
    """Property 2 — entity position integrity."""
    text = (FIXTURES / "sample_log.txt").read_text(encoding="utf-8")
    result, _ = reconcile(detect_chunk(text, threshold=0.3).entities)

    from pii_agent.core.reconciler import _NESTING_PERMITTED

    for i, a in enumerate(result):
        for b in result[i + 1 :]:
            if not a.overlaps(b):
                continue
            pair = (a.type.upper(), b.type.upper())
            reverse = (b.type.upper(), a.type.upper())
            assert pair in _NESTING_PERMITTED or reverse in _NESTING_PERMITTED, (
                f"unpermitted overlap: {a.type}[{a.start},{a.end}) and "
                f"{b.type}[{b.start},{b.end})"
            )


# ---------------------------------------------------------------------------
# Credibility precedence
#
# Regression tests for a defect found by property-based testing: a wider but
# weaker detection displaced a checksum-validated one, and was then removed by
# profile filtering — so the validated entity vanished with no trace in the
# output.
# ---------------------------------------------------------------------------


def test_validator_backed_detection_beats_a_longer_guess():
    """A passed checksum is evidence; a statistical label is a guess.

    spaCy labels "IBAN GB82WEST12345698765432" an ORGANIZATION across 27
    characters. The genuine IBAN_CODE covers 22. Length alone would hand the
    overlap to the guess.
    """
    guess = _entity(
        "ORGANIZATION",
        0,
        27,
        detector=DetectorName.SPACY.value,
        severity=EntitySeverity.LOW,
        source=ConfidenceSource.HEURISTIC,
    )
    validated = _entity(
        "IBAN_CODE",
        5,
        27,
        confidence=1.0,
        detector=DetectorName.PRESIDIO.value,
        severity=EntitySeverity.MEDIUM,
    )

    result, _ = reconcile([guess, validated])
    assert [e.type for e in result] == ["IBAN_CODE"]


def test_calibrated_score_beats_a_longer_heuristic_span():
    """Applies even without a validator: a real score outranks a constant."""
    heuristic = _entity(
        "ORGANIZATION",
        0,
        40,
        detector=DetectorName.SPACY.value,
        severity=EntitySeverity.LOW,
        source=ConfidenceSource.HEURISTIC,
    )
    calibrated = _entity(
        "EMAIL_ADDRESS",
        5,
        30,
        confidence=0.95,
        severity=EntitySeverity.MEDIUM,
    )

    result, _ = reconcile([heuristic, calibrated])

    email = next(e for e in result if e.type == "EMAIL_ADDRESS")
    assert email.span == (5, 30)
    # The heuristic span may leave a trimmed remainder, but must not keep its
    # original claim over the email.
    for entity in result:
        if entity.type == "ORGANIZATION":
            assert entity.metadata.get("trimmed") is True
            assert not entity.overlaps(email)


def test_length_still_decides_between_equally_credible_detections():
    """Length remains a tie-break, just no longer the first question."""
    short = _entity("PHONE_NUMBER", 0, 10, severity=EntitySeverity.MEDIUM)
    long = _entity("PHONE_NUMBER", 0, 20, severity=EntitySeverity.MEDIUM)

    result, _ = reconcile([short, long])
    assert len(result) == 1
    assert result[0].length == 20


def test_duplicate_values_are_both_detected_and_both_survive():
    """The concrete failure: two identical IBANs, only one scrubbed."""
    text = "IBAN GB82WEST12345698765432\nIBAN GB82WEST12345698765432"

    from pii_agent.core.profile_resolver import resolve_profile
    from pii_agent.core.reconciler import filter_by_profile

    outcome = detect_chunk(text, threshold=0.3)
    profile = resolve_profile("DEFAULT_PII")

    # Filter first, as the pipeline does.
    relevant, _ = filter_by_profile(outcome.entities, profile)
    result, _ = reconcile(relevant)

    ibans = [e for e in result if e.type == "IBAN_CODE"]
    assert len(ibans) == 2, "both occurrences must survive"
    assert {e.start for e in ibans} == {5, 33}


def test_repeated_pii_across_many_lines_is_fully_detected():
    """Repeated values are the norm in real logs, not an edge case."""
    from pii_agent.core.profile_resolver import resolve_profile
    from pii_agent.core.reconciler import filter_by_profile

    text = "\n".join("user ssn=482-71-9053 failed" for _ in range(8))

    outcome = detect_chunk(text, threshold=0.3)
    profile = resolve_profile("DEFAULT_PII")
    relevant, _ = filter_by_profile(outcome.entities, profile)
    result, _ = reconcile(relevant)

    ssns = [e for e in result if e.type == "US_SSN"]
    assert len(ssns) == 8
