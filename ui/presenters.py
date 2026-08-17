"""Presentation logic, kept free of Streamlit so it can be tested.

Requirements 29, 36.5. Guardrails G6, G7.

The UI has one genuinely important job: make a refusal read as protection rather
than as a failure. A user who thinks `DEGRADED_COVERAGE` is an error will go
looking for an override; a user who understands that a partial scan cannot yield
a verifiable clean copy will fix the underlying cause instead.

So refusals get the same visual weight as success, an explanation of what was
protected, and a concrete next step.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models.enums import EntitySeverity, RefusalReason
from models.results import ProcessingResult

# Severity presentation. HIGH never shows a preview of the value.
SEVERITY_STYLE = {
    EntitySeverity.HIGH: ("🔴", "Credential or secret"),
    EntitySeverity.MEDIUM: ("🟠", "Direct identifier"),
    EntitySeverity.LOW: ("🟡", "Indirect identifier"),
}

STATE_ICONS = {
    "IDLE": "🟢",
    "THINKING": "🧠",
    "PLANNING": "📋",
    "EXECUTING": "⚡",
    "ANALYZING": "🔍",
    "REPORTING": "📊",
    "WAITING_FOR_INPUT": "⏳",
}


@dataclass
class RefusalNotice:
    """A refusal rendered for a human.

    ``tone`` is "protective" when withholding was the correct outcome, and
    "defect" only when the tool itself misbehaved. The distinction matters: one
    asks the user to change something, the other tells them to report a bug.
    """

    headline: str
    explanation: str
    next_steps: list[str] = field(default_factory=list)
    tone: str = "protective"

    @property
    def is_defect(self) -> bool:
        return self.tone == "defect"


def describe_refusal(result: ProcessingResult) -> RefusalNotice | None:
    """Turn a refusal into something actionable."""
    if not result.is_refusal or result.refusal is None:
        return None

    reason = result.refusal
    detail = result.refusal_detail or reason.user_message

    if reason is RefusalReason.DEGRADED_COVERAGE:
        return RefusalNotice(
            headline="No cleaned copy — part of this source was not inspected",
            explanation=(
                f"{detail}\n\n"
                "The findings below are real and worth acting on. They are "
                "marked unverified because a cleaned copy built from a partial "
                "scan would look checked without being checked."
            ),
            next_steps=_coverage_next_steps(result),
        )

    if reason is RefusalReason.BLOCKED_ARTIFACT:
        return RefusalNotice(
            headline="No cleaned copy — policy forbids one for this content",
            explanation=(
                f"{detail}\n\n"
                "This is not a detection failure. The active profile treats "
                "these categories as ones that must not be retained in any "
                "form, including redacted."
            ),
            next_steps=[
                "Review the findings below to see what triggered the block.",
                "If this content genuinely needs to be shared, remove the "
                "blocked values at source rather than scrubbing them here.",
            ],
        )

    if reason is RefusalReason.RESIDUAL_PII_DETECTED:
        return RefusalNotice(
            headline="Cleaned copy withheld — verification found leftovers",
            explanation=(
                f"{detail}\n\n"
                "Your input is fine. The scrub pass missed something and the "
                "verification pass caught it, which is exactly what it is for. "
                "Handing you the file anyway would be the dangerous outcome."
            ),
            next_steps=[
                "This is a bug in the tool — please report it with the "
                f"request id {result.request_id}.",
                "The audit record for this run is already on disk.",
            ],
            tone="defect",
        )

    if reason is RefusalReason.NEEDS_DESTINATION:
        return RefusalNotice(
            headline="Where is this data going?",
            explanation=detail,
            next_steps=[
                "INTERNAL_SIEM — keeps IPs and hostnames so events stay "
                "correlatable.",
                "EXTERNAL_ANALYTICS or EXTERNAL_LLM — removes operational "
                "identifiers as well as personal data.",
                "FILE — a middle setting for a local cleaned copy.",
            ],
        )

    if reason is RefusalReason.TIMEOUT:
        return RefusalNotice(
            headline="Stopped at the time limit",
            explanation=(
                f"{detail}\n\n"
                "Coverage is incomplete, so no cleaned copy was produced."
            ),
            next_steps=[
                "Scan a smaller extract, or raise the per-step budget if the "
                "host can afford it."
            ],
        )

    if reason is RefusalReason.INVALID_PROFILE:
        return RefusalNotice(
            headline="That profile could not be loaded",
            explanation=(
                f"{detail}\n\n"
                "Nothing was scanned. A profile that fails validation is not "
                "quietly replaced with a default — that would apply a policy "
                "nobody reviewed."
            ),
            next_steps=["Fix the named profile file, then try again."],
        )

    return RefusalNotice(
        headline=f"Refused: {reason.value}",
        explanation=detail,
        next_steps=[],
    )


def _coverage_next_steps(result: ProcessingResult) -> list[str]:
    steps: list[str] = []
    coverage = result.coverage

    for name in coverage.missing_required_detectors:
        if name == "spacy":
            steps.append(
                "Install the language model: "
                "python -m spacy download en_core_web_lg"
            )
        else:
            steps.append(f"Restore the '{name}' detector, then re-run.")

    if not coverage.bytes_complete:
        if coverage.truncation_was_intentional:
            steps.append(
                "Re-run without a size limit to get a cleaned copy of the "
                "whole source."
            )
        else:
            steps.append(
                f"Only {coverage.coverage_percent}% was inspected — check the "
                f"size and time limits."
            )

    return steps or ["Re-run once the cause above is resolved."]


@dataclass
class EntityRow:
    """One row of the findings table. Never carries a raw value."""

    severity_icon: str
    severity_label: str
    entity_type: str
    preview: str
    confidence: str
    detected_by: str
    action: str


def build_entity_rows(result: ProcessingResult) -> list[EntityRow]:
    """Findings table rows, ordered by severity then type.

    Previews come from ``Entity.masked_preview``, which returns a type label
    rather than any part of the value for HIGH-severity entities.
    """
    actions = {
        id(decision.entity): decision.applied_action.value
        for decision in result.decisions
    }

    rows: list[EntityRow] = []
    for entity in result.entities:
        severity = entity.severity or EntitySeverity.MEDIUM
        icon, label = SEVERITY_STYLE[severity]

        confidence = f"{entity.confidence:.2f}"
        if entity.confidence_source.value == "HEURISTIC":
            # Marking this matters: spaCy emits a constant, not a probability,
            # and presenting it as calibrated would mislead.
            confidence += " (heuristic)"

        rows.append(
            EntityRow(
                severity_icon=icon,
                severity_label=label,
                entity_type=entity.type,
                preview=entity.masked_preview(),
                confidence=confidence,
                detected_by=", ".join(entity.detected_by),
                action=actions.get(id(entity), "—"),
            )
        )

    rows.sort(
        key=lambda r: (
            -SEVERITY_ORDER.get(r.severity_label, 0),
            r.entity_type,
        )
    )
    return rows


SEVERITY_ORDER = {
    "Credential or secret": 3,
    "Direct identifier": 2,
    "Indirect identifier": 1,
}


def build_summary(result: ProcessingResult) -> dict[str, object]:
    """Headline figures for the summary panel."""
    return {
        "entities": result.entity_count,
        "types": len(result.entity_breakdown()),
        "coverage_percent": result.coverage.coverage_percent,
        "coverage_complete": result.coverage.is_complete(),
        "verified_clean": result.verified_clean,
        "unverified": result.unverified,
        "artifact_available": result.artifact_available,
        "status": result.status,
        "actions": result.decisions.action_counts(),
        "severity": result.severity_breakdown(),
        "profile": result.engine_versions.profile_name,
        "suppressed_by_allowlist": result.allowlist_suppressed,
        "request_id": result.request_id,
    }


def describe_denied_requests(result: ProcessingResult) -> str | None:
    """Explain any request the policy engine discarded.

    A silently ignored request looks like a bug to the user, so the denial is
    surfaced along with the reason it cannot be honoured.
    """
    denied = result.decisions.discarded_requests
    if not denied:
        return None

    types = sorted({d.entity.type for d in denied})
    return (
        f"You asked for weaker handling of {', '.join(types)}, and I applied the "
        f"profile's setting instead. Requests can make handling stricter but not "
        f"looser — otherwise the profile would not mean anything."
    )


def describe_security_findings(result: ProcessingResult) -> str | None:
    """Surface injection attempts found in the scanned content."""
    if not result.security_findings:
        return None

    lines = [
        "This content contains text that looks designed to manipulate an AI "
        "agent. It had no effect — scrub actions are decided in code, not by "
        "the model — but someone wrote it deliberately, so it is worth finding "
        "out how it got there."
    ]
    lines.extend(f"- {finding}" for finding in result.security_findings)
    return "\n".join(lines)


def format_state(state: str) -> str:
    return f"{STATE_ICONS.get(state, '⚪')} {state.replace('_', ' ').title()}"



# ---------------------------------------------------------------------------
# Capability catalogue and prompt examples
# ---------------------------------------------------------------------------
# Users cannot ask for what they cannot see. Without this the only way to learn
# that PAYMENT_PCI tokenizes a card while DEFAULT_PII masks it was to run both and
# compare, or read the YAML.
#
# Read live from the resolved profiles rather than written out here. A hardcoded
# list would drift the first time a profile changed, and a capability list that
# overstates what is detected is worse than none — someone would rely on it.

# Kept in sync by construction: examples reference only built profiles, and a test
# asserts that.
PROMPT_EXAMPLES: list[tuple[str, str]] = [
    (
        "Scan and clean, one step",
        "scrub sample.txt with DEFAULT_PII for INTERNAL_SIEM",
    ),
    ("Report only, no cleaned copy", "scan sample.txt for INTERNAL_SIEM"),
    ("See what is available", "what can you scan?"),
    ("Understand a profile", "what does PAYMENT_PCI cover?"),
    (
        "Compare destinations",
        "scrub sample.txt for EXTERNAL_LLM",
    ),
    ("Ask for stricter handling", "scrub sample.txt and redact everything"),
    ("Stop repeating yourself", "remember that my destination is INTERNAL_SIEM"),
    ("Correct a false positive", "that hostname is not a person, ignore it"),
]

DESTINATION_NOTES: list[tuple[str, str]] = [
    ("INTERNAL_SIEM", "Staying inside your infrastructure. Keeps IPs and timestamps."),
    ("FILE", "A local copy you are keeping. Replaces IPs."),
    ("EXTERNAL_ANALYTICS", "Third-party platform. Redacts operational identifiers."),
    ("EXTERNAL_LLM", "Pasting into a hosted model. Redacts operational identifiers."),
    ("S3", "Object storage, treated as external."),
]


@dataclass
class CatalogEntry:
    """One entity type as the active profile handles it."""

    entity_type: str
    action: str
    severity_icon: str
    severity_label: str
    description: str


def build_profile_catalog(profile_name: str) -> list[CatalogEntry]:
    """Entity types a profile detects, with the action it resolves to.

    Raises nothing on an unknown profile — returns empty, so a UI panel cannot
    take the page down over a display concern.
    """
    from core.profile_resolver import get_resolver
    from models.entities import severity_for

    try:
        profile = get_resolver().resolve(profile_name)
    except Exception:
        return []

    entities = profile.entities
    items = entities.values() if isinstance(entities, dict) else entities

    catalog: list[CatalogEntry] = []
    for rule in items:
        if not rule.enabled:
            continue
        # The profile may state a severity; otherwise fall back to the type's
        # default so the column is never blank.
        if rule.severity in {s.value for s in EntitySeverity}:
            severity = EntitySeverity(rule.severity)
        else:
            severity = severity_for(rule.type)
        icon, label = SEVERITY_STYLE[severity]

        # A destination-sensitive rule has no single answer, so say so rather
        # than showing the base action as if it were final.
        action = rule.action.value
        if rule.destination_actions:
            action = f"{action} (varies by destination)"

        catalog.append(
            CatalogEntry(
                entity_type=rule.type,
                action=action,
                severity_icon=icon,
                severity_label=label,
                description=rule.description or "",
            )
        )

    catalog.sort(key=lambda e: (-SEVERITY_ORDER.get(e.severity_label, 0), e.entity_type))
    return catalog


def available_profile_names() -> list[str]:
    """Built profiles, for a picker. Never raises."""
    from core.profile_resolver import get_resolver

    try:
        return list(get_resolver().available_profiles())
    except Exception:
        return ["DEFAULT_PII"]
