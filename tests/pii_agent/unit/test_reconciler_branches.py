"""Branch coverage for reconciliation and filtering helpers.

Guardrail G18. These paths decide which detections survive, so an untested
branch means a detection can be dropped or an overlap resolved differently than
the documented precedence order claims.
"""

from __future__ import annotations

import pytest

from pii_agent.core.profile_resolver import resolve_profile
from pii_agent.core.reconciler import (
    drop_allowlisted,
    filter_by_profile,
    reconcile,
)
from pii_agent.models.entities import Entity
from pii_agent.models.enums import ConfidenceSource, DetectorName, EntitySeverity
from pii_agent.session.allowlist import AllowlistStore


def _entity(
    entity_type: str,
    start: int = 0,
    end: int = 10,
    *,
    text: str | None = None,
    confidence: float = 0.9,
    detector: str = DetectorName.PRESIDIO.value,
    severity: EntitySeverity | None = None,
    source: ConfidenceSource = ConfidenceSource.CALIBRATED,
) -> Entity:
    return Entity(
        type=entity_type,
        start=start,
        end=end,
        confidence=confidence,
        text=text if text is not None else "x" * (end - start),
        detected_by=[detector],
        severity=severity,
        confidence_source=source,
    )


# ---------------------------------------------------------------------------
# Detector precedence with unknown detector names
# ---------------------------------------------------------------------------


def test_unknown_detector_name_gets_lowest_precedence():
    """A future detector must not accidentally outrank a security recognizer.

    Unrecognised names fall back to the lowest rank rather than raising, so
    adding a detector cannot silently change existing precedence.
    """
    known = _entity(
        "API_KEY", 0, 10, detector=DetectorName.CUSTOM_SECURITY.value,
        severity=EntitySeverity.LOW,
    )
    unknown = _entity(
        "SOMETHING", 0, 10, detector="experimental_v2",
        severity=EntitySeverity.LOW,
    )

    result, _ = reconcile([unknown, known])
    assert len(result) == 1
    assert result[0].type == "API_KEY"


def test_unknown_detector_still_produces_a_usable_entity():
    result, _ = reconcile([_entity("PERSON", detector="experimental_v2")])
    assert len(result) == 1
    assert result[0].detected_by == ["experimental_v2"]


# ---------------------------------------------------------------------------
# Losing candidate with an identical span
# ---------------------------------------------------------------------------


def test_losing_candidate_with_identical_span_contributes_corroboration():
    """A weaker type over the same span records its detector on the winner.

    Otherwise ``detected_by`` would understate how many engines agreed.
    """
    winner = _entity(
        "CREDIT_CARD", 0, 16, severity=EntitySeverity.MEDIUM,
        detector=DetectorName.PRESIDIO.value,
    )
    loser = _entity(
        "US_BANK_NUMBER", 0, 16, severity=EntitySeverity.MEDIUM,
        detector=DetectorName.SPACY.value,
    )

    result, stats = reconcile([winner, loser])
    assert len(result) == 1
    assert result[0].type == "CREDIT_CARD"
    assert set(result[0].detected_by) == {"presidio", "spacy"}
    assert stats.overlaps_resolved == 1


def test_losing_candidate_with_a_different_span_is_simply_dropped():
    """Partial overlap contributes nothing — the spans describe different text."""
    winner = _entity("PHONE_NUMBER", 0, 20, severity=EntitySeverity.MEDIUM)
    loser = _entity(
        "PERSON", 5, 12, severity=EntitySeverity.MEDIUM,
        detector=DetectorName.SPACY.value,
    )

    result, stats = reconcile([winner, loser])
    assert len(result) == 1
    assert result[0].detected_by == ["presidio"]
    assert stats.overlaps_resolved == 1


def test_multiple_conflicting_entities_are_all_removed_by_a_stronger_one():
    """A long span must displace every shorter one it covers."""
    short_a = _entity("PERSON", 0, 5, severity=EntitySeverity.MEDIUM)
    short_b = _entity("PERSON", 6, 11, severity=EntitySeverity.MEDIUM)
    long = _entity("PHONE_NUMBER", 0, 30, severity=EntitySeverity.MEDIUM)

    result, _ = reconcile([short_a, short_b, long])
    assert len(result) == 1
    assert result[0].type == "PHONE_NUMBER"


# ---------------------------------------------------------------------------
# Allowlist filtering
# ---------------------------------------------------------------------------


def test_drop_allowlisted_returns_input_when_allowlist_is_none():
    entities = [_entity("IP_ADDRESS", text="10.0.0.1")]
    kept, suppressed = drop_allowlisted(entities, None, "DEFAULT_PII")
    assert kept is entities
    assert suppressed == 0


def test_drop_allowlisted_returns_input_when_allowlist_is_empty():
    store = AllowlistStore("s")
    entities = [_entity("IP_ADDRESS", text="10.0.0.1")]
    kept, suppressed = drop_allowlisted(entities, store, "DEFAULT_PII")
    assert kept is entities
    assert suppressed == 0


def test_drop_allowlisted_removes_a_confirmed_safe_value():
    store = AllowlistStore("s")
    store.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")

    entities = [
        _entity("IP_ADDRESS", 0, 8, text="10.0.0.1"),
        _entity("IP_ADDRESS", 20, 32, text="203.0.113.42"),
    ]
    kept, suppressed = drop_allowlisted(entities, store, "DEFAULT_PII")

    assert suppressed == 1
    assert [e.text for e in kept] == ["203.0.113.42"]


def test_drop_allowlisted_is_scoped_to_the_profile():
    """An entry added under one profile must not suppress under another."""
    store = AllowlistStore("s")
    store.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")

    entities = [_entity("IP_ADDRESS", 0, 8, text="10.0.0.1")]
    kept, suppressed = drop_allowlisted(entities, store, "HEALTHCARE")

    assert suppressed == 0
    assert len(kept) == 1


def test_allowlist_ignores_entities_without_text():
    """Defensive: an entity with no text cannot be matched against a hash."""
    store = AllowlistStore("s")
    store.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")

    entity = _entity("IP_ADDRESS", 0, 8, text="10.0.0.1")
    entity.text = ""
    kept, suppressed = store.filter_entities([entity], "DEFAULT_PII")

    assert suppressed == 0
    assert len(kept) == 1


# ---------------------------------------------------------------------------
# Profile filtering
# ---------------------------------------------------------------------------


def test_filter_drops_types_the_profile_does_not_enable():
    profile = resolve_profile("BASE_SECURITY")
    # PERSON is not a BASE_SECURITY entity.
    entities = [_entity("PERSON", text="Jane Fair")]

    kept, dropped = filter_by_profile(entities, profile)
    assert kept == []
    assert dropped == 1


def test_filter_drops_entities_below_the_per_type_threshold():
    """Thresholds are per entity type, not one global figure."""
    profile = resolve_profile("DEFAULT_PII")
    threshold = profile.threshold_for("PERSON")

    entities = [
        _entity("PERSON", 0, 10, confidence=threshold - 0.05),
        _entity("PERSON", 20, 30, confidence=threshold + 0.05),
    ]
    kept, dropped = filter_by_profile(entities, profile)

    assert dropped == 1
    assert len(kept) == 1
    assert kept[0].start == 20


def test_filter_keeps_entities_exactly_at_the_threshold():
    """Boundary: the comparison is >=, so equal must be kept."""
    profile = resolve_profile("DEFAULT_PII")
    threshold = profile.threshold_for("US_SSN")

    kept, dropped = filter_by_profile(
        [_entity("US_SSN", confidence=threshold)], profile
    )
    assert len(kept) == 1
    assert dropped == 0


def test_filter_on_empty_input_returns_empty():
    profile = resolve_profile("DEFAULT_PII")
    kept, dropped = filter_by_profile([], profile)
    assert kept == []
    assert dropped == 0


def test_filter_counts_both_drop_reasons_together():
    profile = resolve_profile("DEFAULT_PII")
    entities = [
        _entity("SOME_DISABLED_TYPE", 0, 10),
        _entity("PERSON", 20, 30, confidence=0.05),
        _entity("US_SSN", 40, 51, confidence=0.95),
    ]
    kept, dropped = filter_by_profile(entities, profile)

    assert dropped == 2
    assert [e.type for e in kept] == ["US_SSN"]


# ---------------------------------------------------------------------------
# Stats reporting
# ---------------------------------------------------------------------------


def test_reconciliation_stats_metadata_reports_every_counter():
    """Surfaced in results, so every counter must be present and accurate."""
    duplicate_a = _entity("PERSON", 0, 10)
    duplicate_b = _entity("PERSON", 0, 10, detector=DetectorName.SPACY.value)
    outer = _entity("LOCATION", 30, 80, severity=EntitySeverity.LOW)
    nested = _entity("PERSON", 40, 50, severity=EntitySeverity.MEDIUM)

    _, stats = reconcile([duplicate_a, duplicate_b, outer, nested])
    metadata = stats.to_metadata()

    assert set(metadata) == {
        "input_count",
        "output_count",
        "duplicates_merged",
        "overlaps_resolved",
        "nested_preserved",
        "losers_trimmed",
    }
    assert metadata["input_count"] == 4
    assert metadata["duplicates_merged"] == 1
    assert metadata["nested_preserved"] == 1
    assert metadata["output_count"] == 3


def test_stats_metadata_on_empty_input():
    _, stats = reconcile([])
    assert stats.to_metadata()["input_count"] == 0
    assert stats.to_metadata()["output_count"] == 0
