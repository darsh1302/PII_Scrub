"""Entity reconciliation with a total precedence order.

Guardrail G18. Addresses review finding COR-03.

The reviewed design said reconciliation should "determine the more appropriate
classification when overlap exists". That is not implementable, and worse, it
produces different output across runs — which breaks golden-dataset regression
testing, the mechanism meant to catch detection drift.

Replaced with a **total** order, so ties are impossible and output is
byte-identical for identical input (Requirement 28.7):

1. Longest span wins — a broader match usually captures the whole identifier.
2. Higher severity wins — bias toward protection on genuine ambiguity.
3. Validator-backed wins — a Luhn-checked CREDIT_CARD beats a bare
   US_BANK_NUMBER guess over the same digits.
4. Detector precedence — purpose-built security recognizer > Presidio > spaCy.
5. Lexicographically smaller type name — arbitrary, but guarantees determinism.

Rule 5 exists only so no tie survives. Without it, two equally-ranked candidates
would resolve by dict iteration order and the golden files would be unstable.
"""

from __future__ import annotations

from dataclasses import dataclass

from pii_agent.models.entities import Entity
from pii_agent.models.enums import ConfidenceSource, DetectorName, EntitySeverity

# Entity types that are commonly nested inside another and should survive
# separately rather than being absorbed. A PERSON inside a LOCATION ("Fairweather
# Street, London") is genuinely two facts.
_NESTING_PERMITTED: frozenset[tuple[str, str]] = frozenset(
    {
        ("LOCATION", "PERSON"),
        ("LOCATION", "ORGANIZATION"),
        ("URL", "IP_ADDRESS"),
        ("URL", "EMAIL_ADDRESS"),
        ("CONNECTION_STRING", "PASSWORD"),
        ("CONNECTION_STRING", "IP_ADDRESS"),
        ("AUTHORIZATION_HEADER", "JWT"),
        ("AUTHORIZATION_HEADER", "ACCESS_TOKEN"),
        ("PRIVATE_KEY", "SSH_PRIVATE_KEY"),
    }
)


def _detector_rank(entity: Entity) -> int:
    """Highest-precedence detector that found this entity."""
    best = 0
    for name in entity.detected_by:
        try:
            best = max(best, DetectorName(name).precedence)
        except ValueError:
            best = max(best, 1)
    return best


def _precedence_key(entity: Entity) -> tuple:
    """Total ordering key. Higher tuple wins.

    Ordered by *credibility first*, with span length only breaking ties among
    equally-credible detections. The original order put length first, which
    produced a real defect: spaCy labels ``IBAN GB82WEST12345698765432`` an
    ORGANIZATION over 27 characters, the genuine IBAN_CODE covers 22, so the
    longer guess displaced the checksum-validated fact — and because
    ORGANIZATION is not an enabled type in DEFAULT_PII it was then filtered out,
    leaving the IBAN entirely unscrubbed.

    A passed checksum is evidence. A statistical label is a guess. Length is
    neither, so it cannot be the first thing we look at.

    Every component is deterministic and the final element breaks all remaining
    ties, so no two distinct entities compare equal (Requirement 28.7).
    """
    severity = entity.severity or EntitySeverity.MEDIUM
    calibrated = 1 if entity.confidence_source is ConfidenceSource.CALIBRATED else 0
    return (
        1 if entity.is_validator_backed else 0,  # 1. checksum beats guess
        calibrated,  # 2. real score beats heuristic constant
        severity.rank,  # 3. bias toward protection
        entity.length,  # 4. longest span among equals
        _detector_rank(entity),  # 5. detector precedence
        # 6. lexicographic, inverted so "smaller name wins" under max()
        tuple(-ord(c) for c in entity.type[:8].ljust(8)),
    )


def _nesting_allowed(outer: Entity, inner: Entity) -> bool:
    pair = (outer.type.upper(), inner.type.upper())
    return pair in _NESTING_PERMITTED


def _merge_duplicate(primary: Entity, other: Entity) -> Entity:
    """Fold an identical-span detection into the winner.

    Records the extra detector so ``detected_by`` reflects corroboration, and
    promotes confidence only when the corroborating score is calibrated —
    otherwise spaCy's heuristic constant would inflate a real Presidio score.
    """
    for name in other.detected_by:
        if name not in primary.detected_by:
            primary.detected_by.append(name)
    primary.detected_by.sort()

    if (
        other.confidence_source is ConfidenceSource.CALIBRATED
        and primary.confidence_source is ConfidenceSource.CALIBRATED
    ):
        primary.confidence = max(primary.confidence, other.confidence)
    elif primary.confidence_source is ConfidenceSource.HEURISTIC and (
        other.confidence_source is ConfidenceSource.CALIBRATED
    ):
        primary.confidence = other.confidence
        primary.confidence_source = ConfidenceSource.CALIBRATED

    primary.is_base_security = primary.is_base_security or other.is_base_security
    return primary


# A trimmed remainder must look like a value rather than a field label.
#
# Six characters is a pragmatic line. Over-extended spans typically pick up a
# short label — "IBAN ", "card=", "ssn=" — and keeping those as entities is
# noise. Real identifiers and names are longer: the case this exists for is
# "Priya Raghunathan ssn=417-82-6390", whose remainder after the SSN is
# seventeen characters of actual name.
_MIN_TRIM_LENGTH = 6


def _trim_around(loser: Entity, winners: list[Entity]) -> Entity | None:
    """Return the losing entity reduced to its largest unclaimed remainder.

    Detectors over-extend spans. When the loser reaches beyond every winner, the
    uncovered part may hold real data that no other entity accounts for, and
    discarding the whole span silently loses it.

    Only a contiguous leading or trailing remainder is considered — carving a
    span into several pieces would invent entities the detectors never reported.
    Returns None when nothing meaningful is left over.
    """
    covered_start = min(w.start for w in winners)
    covered_end = max(w.end for w in winners)

    leading = covered_start - loser.start
    trailing = loser.end - covered_end

    if leading >= trailing and leading >= _MIN_TRIM_LENGTH:
        start, end = loser.start, covered_start
    elif trailing >= _MIN_TRIM_LENGTH:
        start, end = covered_end, loser.end
    else:
        return None

    text = loser.text[start - loser.start : end - loser.start]

    # Drop trailing separators the over-extension picked up, so "Priya
    # Raghunathan ssn=" becomes "Priya Raghunathan".
    stripped = text.rstrip(" \t=:,;|/\\-\"'")
    if len(stripped) < _MIN_TRIM_LENGTH:
        return None
    if sum(1 for c in stripped if c.isalnum()) < _MIN_TRIM_LENGTH:
        return None
    end = start + len(stripped)

    return Entity(
        type=loser.type,
        start=start,
        end=end,
        confidence=loser.confidence,
        text=loser.text[start - loser.start : end - loser.start],
        confidence_source=loser.confidence_source,
        severity=loser.severity,
        detected_by=list(loser.detected_by),
        is_base_security=loser.is_base_security,
        metadata={**loser.metadata, "trimmed": True},
    )


@dataclass
class ReconciliationStats:
    input_count: int = 0
    output_count: int = 0
    duplicates_merged: int = 0
    overlaps_resolved: int = 0
    nested_preserved: int = 0
    losers_trimmed: int = 0

    def to_metadata(self) -> dict[str, int]:
        return {
            "input_count": self.input_count,
            "output_count": self.output_count,
            "duplicates_merged": self.duplicates_merged,
            "overlaps_resolved": self.overlaps_resolved,
            "nested_preserved": self.nested_preserved,
            "losers_trimmed": self.losers_trimmed,
        }


def reconcile(
    entities: list[Entity],
) -> tuple[list[Entity], ReconciliationStats]:
    """Deduplicate and resolve overlaps deterministically.

    Input entities must already be in whole-document coordinates. Chunk-local
    offsets here would produce spans that look valid and refer to the wrong text.
    """
    stats = ReconciliationStats(input_count=len(entities))
    if not entities:
        return [], stats

    # --- Collapse exact-span duplicates of the same type -------------------
    by_key: dict[tuple[int, int, str], Entity] = {}
    for entity in entities:
        key = (entity.start, entity.end, entity.type.upper())
        existing = by_key.get(key)
        if existing is None:
            by_key[key] = entity
        else:
            _merge_duplicate(existing, entity)
            stats.duplicates_merged += 1

    # Deterministic starting order — position, then reverse precedence so the
    # strongest candidate at a position is considered first.
    candidates = sorted(
        by_key.values(),
        key=lambda e: (e.start, -e.length, e.type),
    )

    # --- Resolve overlaps --------------------------------------------------
    kept: list[Entity] = []
    for candidate in candidates:
        conflicting: list[Entity] = [
            existing for existing in kept if existing.overlaps(candidate)
        ]

        if not conflicting:
            kept.append(candidate)
            continue

        # Permitted nesting survives as a separate fact.
        nestable = all(
            (
                existing.contains(candidate)
                and _nesting_allowed(existing, candidate)
            )
            or (
                candidate.contains(existing)
                and _nesting_allowed(candidate, existing)
            )
            for existing in conflicting
        )
        if nestable:
            kept.append(candidate)
            stats.nested_preserved += 1
            continue

        candidate_key = _precedence_key(candidate)
        strongest_existing = max(conflicting, key=_precedence_key)

        if candidate_key > _precedence_key(strongest_existing):
            for existing in conflicting:
                trimmed = _trim_around(existing, [candidate])
                if trimmed is not None:
                    kept.remove(existing)
                    kept.append(trimmed)
                    stats.losers_trimmed += 1
                else:
                    kept.remove(existing)
            kept.append(candidate)
            stats.overlaps_resolved += 1
        else:
            # Candidate loses, but corroboration is still recorded when the spans
            # match exactly under different type names.
            if (
                strongest_existing.start == candidate.start
                and strongest_existing.end == candidate.end
            ):
                _merge_duplicate(strongest_existing, candidate)
            else:
                # The loser may extend beyond the winner. Discarding it whole
                # loses that remainder, which is how a name vanished: Presidio
                # over-extends PERSON to "Priya Raghunathan ssn=417-82-6390",
                # the nested validator-backed US_SSN wins the overlap, and the
                # name is discarded with the span — the SSN gets redacted while
                # the name stays in the output.
                trimmed = _trim_around(candidate, conflicting)
                if trimmed is not None:
                    kept.append(trimmed)
                    stats.losers_trimmed += 1
            stats.overlaps_resolved += 1

    result = sorted(kept, key=lambda e: (e.start, e.end, e.type))
    stats.output_count = len(result)
    return result, stats


def drop_allowlisted(
    entities: list[Entity], allowlist, profile_name: str
) -> tuple[list[Entity], int]:
    """Remove user-confirmed false positives (Requirement 39.3)."""
    if allowlist is None or len(allowlist) == 0:
        return entities, 0
    return allowlist.filter_entities(entities, profile_name)


def filter_by_profile(
    entities: list[Entity], profile
) -> tuple[list[Entity], int]:
    """Keep only entity types the active profile enables, honouring thresholds.

    Threshold comparison uses the per-entity value from the profile rather than
    a single global figure, so a profile can be sensitive about SSNs while being
    conservative about dates.
    """
    kept: list[Entity] = []
    dropped = 0
    for entity in entities:
        if not profile.is_enabled(entity.type):
            dropped += 1
            continue
        if entity.confidence < profile.threshold_for(entity.type):
            dropped += 1
            continue
        kept.append(entity)
    return kept, dropped
