"""Applies resolved scrub actions to content.

Requirement 12. Guardrail G19.

Two properties this module must not get wrong:

**Right-to-left application.** Replacements change length, so applying
left-to-right invalidates every offset after the first edit. Processed in
descending order of start offset, unprocessed offsets stay valid throughout
(Requirement 12.8).

**Positions come from the scan record only.** Entity offsets are never accepted
from an LLM tool argument (Requirement 12.9). A model transcribing integers gets
them wrong occasionally, and a wrong offset means the scrub lands on the wrong
span while the PII stays in place — silently, and only on large inputs.

MASK deliberately does not preserve length for high-severity entities: a masked
SSN of exactly nine characters still discloses format and narrows the value.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pii_agent.models.decision import Decision, DecisionSet
from pii_agent.models.enums import EntitySeverity, RefusalReason, ScrubAction
from pii_agent.session.token_vault import TokenizationRefused, TokenVault

# Fixed-width mask for high-severity entities, so length is not disclosed.
_FIXED_MASK_WIDTH = 8


@dataclass
class ApplyResult:
    """Outcome of applying a DecisionSet to content."""

    text: str = field(repr=False, default="")
    applied_count: int = 0
    action_counts: dict[str, int] = field(default_factory=dict)
    refusal: RefusalReason | None = None
    refusal_detail: str = ""
    warnings: list[str] = field(default_factory=list)

    @property
    def is_refusal(self) -> bool:
        return self.refusal is not None


def _replacement_for(
    decision: Decision, vault: TokenVault, warnings: list[str]
) -> str | None:
    """Compute the replacement text for one decision.

    Returns None when the span should be left untouched.
    """
    entity = decision.entity
    action = decision.applied_action

    if action is ScrubAction.ALLOW:
        return None

    if action is ScrubAction.REPLACE:
        return f"[{entity.type}]"

    if action is ScrubAction.MASK:
        # High-severity values get a fixed width so length is not leaked.
        if entity.severity is EntitySeverity.HIGH:
            return "*" * _FIXED_MASK_WIDTH
        return "*" * max(1, entity.length)

    if action is ScrubAction.REDACT:
        # Removed entirely, leaving a marker so the reader knows something was
        # there. An empty string would silently change record structure.
        return f"[REDACTED:{entity.type}]"

    if action is ScrubAction.HASH:
        try:
            digest = vault.hash_value(entity.text, entity.type)
        except TokenizationRefused as exc:
            # Schema validation should have prevented this. Reaching here means
            # a profile bypassed validation, so fall back to the stricter action
            # rather than emitting a reversible digest.
            warnings.append(
                f"HASH refused for {entity.type} ({exc}); applied REDACT instead"
            )
            return f"[REDACTED:{entity.type}]"
        return f"[{entity.type}:{digest[:16]}]"

    if action is ScrubAction.TOKENIZE:
        try:
            return vault.tokenize(entity.text, entity.type)
        except TokenizationRefused as exc:
            warnings.append(
                f"TOKENIZE refused for {entity.type} ({exc}); "
                "applied REDACT instead"
            )
            return f"[REDACTED:{entity.type}]"

    if action is ScrubAction.BLOCK:
        # Never reached: BLOCK is handled at pipeline level before application.
        # Present so an added action cannot fall through silently.
        return f"[BLOCKED:{entity.type}]"

    raise ValueError(f"unhandled scrub action: {action}")


def apply_decisions(
    content: str,
    decisions: DecisionSet,
    vault: TokenVault,
) -> ApplyResult:
    """Apply a DecisionSet to content.

    Refuses outright when any decision is BLOCK: the artifact is suppressed
    entirely rather than partially sanitized (guardrail G19, COR-05). BLOCK must
    be observably different from REDACT, or the strictest control in the system
    quietly does not exist.
    """
    if decisions.blocks_artifact:
        blocking = ", ".join(decisions.blocking_types)
        return ApplyResult(
            refusal=RefusalReason.BLOCKED_ARTIFACT,
            refusal_detail=(
                f"Policy blocks producing any cleaned copy of this content "
                f"because it contains: {blocking}. These categories must not be "
                f"retained in any form, even redacted."
            ),
            action_counts=decisions.action_counts(),
        )

    warnings: list[str] = []
    counts: dict[str, int] = {}
    applied = 0

    # Descending start offset: earlier offsets stay valid as lengths change.
    out = content
    for decision in decisions.actionable():
        entity = decision.entity

        if entity.end > len(out) or entity.start < 0:
            warnings.append(
                f"skipped {entity.type}: span [{entity.start},{entity.end}) "
                f"is outside the content"
            )
            continue

        replacement = _replacement_for(decision, vault, warnings)
        if replacement is None:
            continue

        out = out[: entity.start] + replacement + out[entity.end :]
        applied += 1
        key = decision.applied_action.value
        counts[key] = counts.get(key, 0) + 1

    # Record ALLOW decisions in the counts so the summary accounts for every
    # detected entity, not only the modified ones.
    for decision in decisions:
        if decision.applied_action is ScrubAction.ALLOW:
            counts["ALLOW"] = counts.get("ALLOW", 0) + 1

    return ApplyResult(
        text=out,
        applied_count=applied,
        action_counts=counts,
        warnings=warnings,
    )
