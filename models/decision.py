"""Policy decision record.

Guardrail G4, Property 8. Addresses review finding SEC-04.

In the reviewed design, ``action`` was a free-form argument the LLM supplied,
with nothing constraining it to the active profile. The model could pass ALLOW
for US_SSN — complete policy bypass through ordinary model error or through
injected content.

A ``Decision`` records all three values (mandated, requested, applied) so the
resolution is auditable, and ``assert_monotonic`` makes a weakened outcome a
loud failure rather than a silent leak. The invariant is checked at construction
because a violation here means PII reaches the output.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models.entities import Entity
from models.enums import ScrubAction


class PolicyViolation(RuntimeError):
    """Raised when an applied action is weaker than policy mandates.

    This is a bug, not a user error. It means a code path bypassed the ratchet.
    """


@dataclass
class Decision:
    """Resolved action for one entity, with provenance."""

    entity: Entity
    profile_mandated_action: ScrubAction
    applied_action: ScrubAction
    requested_action: ScrubAction | None = None
    deciding_rule: str = ""
    is_base_security: bool = False
    request_was_discarded: bool = False

    def __post_init__(self) -> None:
        self.assert_monotonic()

    def assert_monotonic(self) -> None:
        """Enforce Property 8: applied is never weaker than mandated."""
        if self.applied_action.priority < self.profile_mandated_action.priority:
            raise PolicyViolation(
                f"policy weakened for {self.entity.type}: mandated "
                f"{self.profile_mandated_action.value} "
                f"(priority {self.profile_mandated_action.priority}) but "
                f"applied {self.applied_action.value} "
                f"(priority {self.applied_action.priority})"
            )

    @property
    def was_escalated(self) -> bool:
        """True when a request made the action stricter than the profile."""
        return self.applied_action.priority > self.profile_mandated_action.priority

    @property
    def suppresses_artifact(self) -> bool:
        return self.applied_action.suppresses_artifact

    def to_metadata(self) -> dict[str, object]:
        """Auditable summary. No entity text, no offsets."""
        return {
            "entity_type": self.entity.type,
            "severity": (
                self.entity.severity.value if self.entity.severity else "MEDIUM"
            ),
            "profile_mandated": self.profile_mandated_action.value,
            "requested": (
                self.requested_action.value if self.requested_action else None
            ),
            "applied": self.applied_action.value,
            "deciding_rule": self.deciding_rule,
            "is_base_security": self.is_base_security,
            "request_discarded": self.request_was_discarded,
        }


@dataclass
class DecisionSet:
    """All decisions for one scan, plus derived summaries."""

    decisions: list[Decision] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.decisions)

    def __iter__(self):
        return iter(self.decisions)

    @property
    def blocks_artifact(self) -> bool:
        """True when any decision forbids producing an artifact (guardrail G19)."""
        return any(d.suppresses_artifact for d in self.decisions)

    @property
    def blocking_types(self) -> tuple[str, ...]:
        return tuple(
            sorted({d.entity.type for d in self.decisions if d.suppresses_artifact})
        )

    @property
    def discarded_requests(self) -> tuple[Decision, ...]:
        """Decisions where a weaker request was refused.

        Surfaced to the user so a denied request is explained rather than
        silently ignored.
        """
        return tuple(d for d in self.decisions if d.request_was_discarded)

    def action_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for d in self.decisions:
            key = d.applied_action.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def actionable(self) -> list[Decision]:
        """Decisions that modify content, ordered for safe application.

        Descending by start offset so that replacing a span never invalidates
        the offsets of spans not yet processed (Requirement 12.8).
        """
        return sorted(
            (d for d in self.decisions if d.applied_action is not ScrubAction.ALLOW),
            key=lambda d: d.entity.start,
            reverse=True,
        )

    def to_metadata(self) -> list[dict[str, object]]:
        return [d.to_metadata() for d in self.decisions]
