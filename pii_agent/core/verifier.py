"""Post-scrub verification.

Guardrail G7. Requirement 12.10, 12.11. Correctness Property 11.
Addresses review finding SEC-02.

The applier could be wrong. An offset could be stale, a replacement could be
skipped, a recognizer could match text the applier's span did not cover. None of
those failures are visible in the output — the file looks sanitized.

So the output is re-scanned with the same profile. Any residual detection means
the artifact is withheld and the condition is recorded as a defect. This is cheap
relative to its value: it converts a silent leak into a loud failure.

Replacement markers the applier itself inserts (``[US_SSN]``,
``[REDACTED:API_KEY]``, surrogate tokens) must not count as residual PII, or
verification would refuse every artifact it produced.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pii_agent.core.detector import detect_chunk
from pii_agent.core.profile_resolver import EffectiveProfile
from pii_agent.core.reconciler import filter_by_profile, reconcile
from pii_agent.models.entities import Entity

# Markers the applier emits. Excluded from residual detection.
_MARKER_PATTERNS = [
    re.compile(r"\[[A-Z][A-Z0-9_]{2,40}\]"),              # [US_SSN]
    re.compile(r"\[REDACTED:[A-Z][A-Z0-9_]{2,40}\]"),      # [REDACTED:API_KEY]
    re.compile(r"\[BLOCKED:[A-Z][A-Z0-9_]{2,40}\]"),       # [BLOCKED:CVV]
    re.compile(r"\[[A-Z][A-Z0-9_]{2,40}:[0-9a-f]{8,64}\]"),  # [EMAIL:abc123]
    re.compile(r"<[A-Z][A-Z0-9_]{2,40}:[0-9a-f]{8,64}>"),  # <EMAIL:surrogate>
    re.compile(r"\*{2,}"),                                  # masked runs
]


@dataclass
class VerificationResult:
    """Outcome of re-scanning sanitized output."""

    clean: bool = False
    residual: list[Entity] = field(default_factory=list, repr=False)
    marker_spans_ignored: int = 0
    permitted_remaining: int = 0
    out_of_scope_ignored: int = 0
    detail: str = ""

    @property
    def residual_count(self) -> int:
        return len(self.residual)

    def residual_breakdown(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for entity in self.residual:
            counts[entity.type] = counts.get(entity.type, 0) + 1
        return counts

    def to_metadata(self) -> dict[str, object]:
        """Audit-safe: counts and types, never residual values."""
        return {
            "verified_clean": self.clean,
            "residual_count": self.residual_count,
            "residual_types": self.residual_breakdown(),
            "markers_ignored": self.marker_spans_ignored,
            "policy_permitted_remaining": self.permitted_remaining,
            "out_of_scope_ignored": self.out_of_scope_ignored,
        }


def _marker_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pattern in _MARKER_PATTERNS:
        spans.extend((m.start(), m.end()) for m in pattern.finditer(text))
    return spans


# A residual span must carry real content. Values below are deliberately loose:
# the aim is to reject spans that are mostly blank, not to second-guess the
# detectors on genuine content.
_MIN_ALNUM_CHARS = 3
_MIN_DENSITY = 0.5


def _has_substance(text: str) -> bool:
    """True when a span carries enough content to be a real identifier.

    Guards against detector noise over masked regions. An SSN is 100% dense; a
    PERSON span of ``"ssn="`` plus eighteen spaces is 18% dense and is not a
    finding.
    """
    if not text:
        return False
    alnum = sum(1 for c in text if c.isalnum())
    if alnum < _MIN_ALNUM_CHARS:
        return False
    non_space = sum(1 for c in text if not c.isspace())
    return (non_space / len(text)) >= _MIN_DENSITY


def _touches_marker(
    entity: Entity, marker_spans: list[tuple[int, int]], text: str
) -> bool:
    """True when a span abuts a replaced region, separated only by whitespace.

    Replacement changes the text, and a detector reading right up against a
    replacement is describing the replacement, not surviving data. Masking a
    card number leaves ``card=`` against a run of asterisks, and spaCy labels
    that fragment a LOCATION.

    The tolerance is whitespace only, so real data near a mask is unaffected:
    ``card=**** ssn=417-82-6390`` keeps the SSN, because ``ssn=`` sits between
    it and the mask.
    """
    for start, end in marker_spans:
        # Entity immediately before the marker.
        if entity.end <= start and not text[entity.end : start].strip():
            return True
        # Entity immediately after the marker.
        if entity.start >= end and not text[end : entity.start].strip():
            return True
    return False


def _mask_markers(text: str) -> tuple[str, int]:
    """Blank out replacement markers before re-scanning.

    Post-filtering by containment is not enough: a detector can produce a span
    that *straddles* a marker boundary. In practice spaCy reads
    ``ssn=[REDACTED:US_SSN]`` and reports ``ssn=[REDACTED`` as a PERSON — a span
    that is neither inside the marker nor real PII, and which would refuse every
    artifact the pipeline correctly produced.

    Replacing markers with spaces removes the text from the detectors' view
    entirely while preserving every offset, so residual spans still refer to
    real positions in the output.
    """
    spans = _marker_spans(text)
    if not spans:
        return text, 0

    # Merge overlapping spans so nested markers are blanked once.
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))

    chars = list(text)
    for start, end in merged:
        for index in range(start, end):
            chars[index] = " "
    return "".join(chars), len(merged)


def _merged_marker_spans(text: str) -> list[tuple[int, int]]:
    """Marker spans, overlaps merged. Shared by masking and adjacency checks."""
    spans = _marker_spans(text)
    if not spans:
        return []
    spans.sort()
    merged: list[tuple[int, int]] = []
    for start, end in spans:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def verify_sanitized(
    sanitized: str,
    profile: EffectiveProfile,
    *,
    use_spacy: bool = True,
    permitted_counts: dict[str, int] | None = None,
    actioned_types: set[str] | None = None,
) -> VerificationResult:
    """Re-scan sanitized output for residual detections.

    Uses the same profile and thresholds as the original scan. Using looser
    settings here would make verification a formality.

    ``permitted_counts`` records how many entities of each type policy resolved
    to ALLOW. Those legitimately remain in the output — an exempt log timestamp,
    or an IP address kept for internal SIEM correlation. Without this allowance
    verification would flag its own correct behaviour as a defect and refuse
    every artifact containing an ALLOW decision.

    ``actioned_types`` restricts the check to types the original scan actually
    decided to remove. That is precisely this gate's remit: *did something we
    chose to remove survive?* Replacement changes the text, and detectors will
    find new things in it — masking a card number leaves ``card=`` stranded
    beside a run of asterisks, which spaCy reads as a LOCATION. That is not a
    scrub failure, and treating it as one refuses artifacts that are correct.
    Genuine detection gaps are a recall problem no verification pass can fix.

    The count check is per type rather than positional, because offsets shift as
    replacement lengths change. Finding *more* of an actioned type than policy
    permitted means something that should have been scrubbed was not.
    """
    if not sanitized.strip():
        return VerificationResult(clean=True, detail="output is empty")

    # Blank markers before detection rather than filtering after, so no detector
    # can produce a span that straddles a marker boundary.
    masked, ignored = _mask_markers(sanitized)
    marker_spans = _merged_marker_spans(sanitized)

    outcome = detect_chunk(masked, threshold=0.0, use_spacy=use_spacy)
    # Filter before reconciling, matching the scan pipeline. Reconciling first
    # lets a profile-irrelevant type win an overlap and then be dropped, which
    # would hide a residual entity from verification.
    relevant, _ = filter_by_profile(outcome.entities, profile)
    candidates, _ = reconcile(relevant)

    allowance = dict(permitted_counts or {})
    in_scope = (
        {t.upper() for t in actioned_types} if actioned_types is not None else None
    )
    residual: list[Entity] = []
    permitted = 0
    out_of_scope = 0

    for entity in candidates:
        if in_scope is not None and entity.type.upper() not in in_scope:
            # A type the original scan never decided to remove. New detections
            # in modified text are noise, not a leak.
            out_of_scope += 1
            continue

        # Masking leaves runs of whitespace, and spaCy's NER will occasionally
        # report a span covering a label fragment plus that whitespace — e.g.
        # "ssn=" followed by 18 blanks reported as a PERSON. No real identifier
        # is mostly empty, so a span without substance is noise rather than a
        # leak. Without this guard, verification refuses artifacts it correctly
        # produced.
        if not _has_substance(entity.text):
            continue

        if _touches_marker(entity, marker_spans, masked):
            # Describing our own replacement, not surviving data.
            out_of_scope += 1
            continue

        remaining = allowance.get(entity.type, 0)
        if remaining > 0:
            allowance[entity.type] = remaining - 1
            permitted += 1
            continue

        residual.append(entity)

    if residual:
        breakdown = ", ".join(
            f"{t} x{c}"
            for t, c in sorted(
                {
                    e.type: sum(1 for x in residual if x.type == e.type)
                    for e in residual
                }.items()
            )
        )
        return VerificationResult(
            clean=False,
            residual=residual,
            marker_spans_ignored=ignored,
            permitted_remaining=permitted,
            out_of_scope_ignored=out_of_scope,
            detail=(
                f"Verification found {len(residual)} entity/entities still "
                f"present after scrubbing that policy required to be removed "
                f"({breakdown}). The artifact was withheld. This is a defect in "
                f"the scrub pipeline, not a problem with your input."
            ),
        )

    return VerificationResult(
        clean=True,
        marker_spans_ignored=ignored,
        permitted_remaining=permitted,
        out_of_scope_ignored=out_of_scope,
        detail=(
            f"Re-scan found no entity that policy required to be removed "
            f"({ignored} marker(s) and {permitted} policy-permitted value(s) "
            f"accounted for)."
        ),
    )
