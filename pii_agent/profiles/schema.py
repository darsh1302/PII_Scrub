"""Profile schema validation.

Guardrails G5 and G14. Addresses review findings SEC-12 and the
invalid-profile-fallback problem in COR-04.

Validation happens at load time, before any content is processed, because these
are the failures you cannot detect afterwards:

* A profile setting ``HASH`` on ``US_SSN`` looks protective and is not — the
  value space is ~10^9, so a salted digest is brute-forceable in minutes.
* A profile setting ``ALLOW`` on an API key silently disables the one control
  that is supposed to be unconditional.

The reviewed design also fell back to "DEFAULT_PII hardcoded rules" when a
profile file was missing or invalid. That silently applies a policy nobody
authored or reviewed, so it is replaced here with a hard refusal naming the file.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from pii_agent.models.enums import Destination, ScrubAction
from pii_agent.session.token_vault import LOW_ENTROPY_TYPES

# Actions that are never adequate for a low-entropy high-severity identifier.
# HASH is pseudonymization: reversible by exhaustion. ALLOW and REPLACE leave or
# label the value without protecting it.
_INSUFFICIENT_FOR_LOW_ENTROPY = frozenset({"ALLOW", "HASH"})

# Entity types belonging to BASE_SECURITY. A derived profile may make these
# stricter, never weaker (Requirement 20.3).
BASE_SECURITY_TYPES = frozenset(
    {
        "PASSWORD",
        "PASSCODE",
        "API_KEY",
        "ACCESS_TOKEN",
        "REFRESH_TOKEN",
        "OAUTH_TOKEN",
        "JWT",
        "AUTHORIZATION_HEADER",
        "CLIENT_SECRET",
        "SESSION_COOKIE",
        "PRIVATE_KEY",
        "SSH_PRIVATE_KEY",
        "DATABASE_CREDENTIAL",
        "CLOUD_CREDENTIAL",
        "CONNECTION_STRING",
        "AWS_ACCESS_KEY",
    }
)

# Minimum action for a BASE_SECURITY entity.
BASE_SECURITY_MINIMUM = ScrubAction.REDACT

REQUIRED_PROFILE_KEYS = ("name", "version", "description")
KNOWN_DETECTORS = frozenset({"presidio", "spacy", "custom_security"})


class ProfileValidationError(ValueError):
    """Raised when a profile file is missing, malformed, or unsafe.

    Always names the offending file so the operator can fix it. Never triggers
    a silent fallback.
    """


@dataclass
class EntityRule:
    """Detection and action configuration for one entity type."""

    type: str
    enabled: bool = True
    action: ScrubAction = ScrubAction.REPLACE
    confidence_threshold: float | None = None
    severity: str | None = None
    detection_methods: tuple[str, ...] = ()
    description: str = ""
    # Per-destination overrides, e.g. {INTERNAL_SIEM: ALLOW} for IP_ADDRESS
    destination_actions: dict[Destination, ScrubAction] = field(
        default_factory=dict
    )
    # Field names / positions exempt from scrubbing (log timestamps etc.)
    field_context_exempt: tuple[str, ...] = ()
    max_pattern_span: int = 0

    def action_for(self, destination: Destination | None) -> ScrubAction:
        """Action for a destination, falling back to the default action."""
        if destination is not None and destination in self.destination_actions:
            return self.destination_actions[destination]
        return self.action

    @property
    def is_destination_sensitive(self) -> bool:
        return bool(self.destination_actions)


@dataclass
class ProfileDefinition:
    """A parsed, validated profile file. Not yet inheritance-resolved."""

    name: str
    version: str
    description: str
    inherits: tuple[str, ...] = ()
    required_detectors: frozenset[str] = frozenset({"presidio"})
    entities: dict[str, EntityRule] = field(default_factory=dict)
    source_path: Path | None = None

    @property
    def max_pattern_span(self) -> int:
        """Longest span any rule in this profile can match.

        Drives chunk overlap (guardrail G17). A PEM recognizer needs kilobytes;
        using a small constant here is how COR-02 lost private keys at chunk
        boundaries.
        """
        spans = [r.max_pattern_span for r in self.entities.values()]
        return max(spans) if spans else 0


def _parse_action(raw: Any, *, where: str, path: Path | None) -> ScrubAction:
    if not isinstance(raw, str):
        raise ProfileValidationError(
            f"{_loc(path)}: {where}: action must be a string, got {type(raw).__name__}"
        )
    try:
        return ScrubAction(raw.strip().upper())
    except ValueError:
        valid = ", ".join(a.value for a in ScrubAction)
        raise ProfileValidationError(
            f"{_loc(path)}: {where}: unknown action {raw!r}. Valid: {valid}"
        ) from None


def _parse_destination(raw: Any, *, where: str, path: Path | None) -> Destination:
    try:
        return Destination(str(raw).strip().upper())
    except ValueError:
        valid = ", ".join(d.value for d in Destination)
        raise ProfileValidationError(
            f"{_loc(path)}: {where}: unknown destination {raw!r}. Valid: {valid}"
        ) from None


def _loc(path: Path | None) -> str:
    return str(path) if path else "<profile>"


def _validate_entity_rule(
    raw: dict[str, Any], path: Path | None, index: int
) -> EntityRule:
    where = f"entities[{index}]"

    entity_type = raw.get("type")
    if not entity_type or not isinstance(entity_type, str):
        raise ProfileValidationError(
            f"{_loc(path)}: {where}: 'type' is required and must be a string"
        )
    entity_type = entity_type.strip().upper()
    where = f"entity '{entity_type}'"

    action = _parse_action(raw.get("action", "REPLACE"), where=where, path=path)

    # --- Guardrail G14 ------------------------------------------------------
    # HASH looks like protection for an SSN and is not. Reject at load time so
    # a reviewer sees it, rather than discovering it in an incident.
    if (
        entity_type in LOW_ENTROPY_TYPES
        and action.value in _INSUFFICIENT_FOR_LOW_ENTROPY
    ):
        raise ProfileValidationError(
            f"{_loc(path)}: {where}: action {action.value} is not adequate "
            f"protection for a low-entropy identifier. The value space is small "
            f"enough to exhaust, so a digest is reversible. "
            f"Use TOKENIZE, REDACT, MASK or BLOCK."
        )

    # --- Guardrail G5 -------------------------------------------------------
    # BASE_SECURITY protection cannot be reduced by a derived profile.
    if entity_type in BASE_SECURITY_TYPES:
        allow_exception = bool(raw.get("security_exception_approved", False))
        if action.priority < BASE_SECURITY_MINIMUM.priority and not allow_exception:
            raise ProfileValidationError(
                f"{_loc(path)}: {where}: action {action.value} is weaker than "
                f"the BASE_SECURITY minimum ({BASE_SECURITY_MINIMUM.value}). "
                f"Credentials must be protected regardless of profile. "
                f"Set 'security_exception_approved: true' only with a "
                f"documented, reviewed exception."
            )

    threshold = raw.get("confidence_threshold")
    if threshold is not None:
        if not isinstance(threshold, (int, float)) or not 0.0 <= threshold <= 1.0:
            raise ProfileValidationError(
                f"{_loc(path)}: {where}: confidence_threshold must be a number "
                f"between 0.0 and 1.0, got {threshold!r}"
            )
        threshold = float(threshold)

    dest_actions: dict[Destination, ScrubAction] = {}
    raw_dest = raw.get("destination_actions") or {}
    if not isinstance(raw_dest, dict):
        raise ProfileValidationError(
            f"{_loc(path)}: {where}: destination_actions must be a mapping"
        )
    for dest_key, dest_action in raw_dest.items():
        destination = _parse_destination(dest_key, where=where, path=path)
        resolved = _parse_action(
            dest_action, where=f"{where}.destination_actions", path=path
        )
        # A destination override must not weaken a BASE_SECURITY entity either.
        if (
            entity_type in BASE_SECURITY_TYPES
            and resolved.priority < BASE_SECURITY_MINIMUM.priority
        ):
            raise ProfileValidationError(
                f"{_loc(path)}: {where}: destination override "
                f"{destination.value}={resolved.value} is weaker than the "
                f"BASE_SECURITY minimum"
            )
        dest_actions[destination] = resolved

    methods = raw.get("detection_methods") or []
    if isinstance(methods, str):
        methods = [methods]

    exempt = raw.get("field_context_exempt") or []
    if isinstance(exempt, str):
        exempt = [exempt]

    span = raw.get("max_pattern_span", 0)
    if not isinstance(span, int) or span < 0:
        raise ProfileValidationError(
            f"{_loc(path)}: {where}: max_pattern_span must be a "
            f"non-negative integer"
        )

    return EntityRule(
        type=entity_type,
        enabled=bool(raw.get("enabled", True)),
        action=action,
        confidence_threshold=threshold,
        severity=(str(raw["severity"]).upper() if raw.get("severity") else None),
        detection_methods=tuple(str(m).lower() for m in methods),
        description=str(raw.get("description", "")),
        destination_actions=dest_actions,
        field_context_exempt=tuple(str(f) for f in exempt),
        max_pattern_span=span,
    )


def validate_profile_dict(
    data: Any, path: Path | None = None
) -> ProfileDefinition:
    """Validate a parsed profile mapping. Raises ProfileValidationError."""
    if not isinstance(data, dict):
        raise ProfileValidationError(
            f"{_loc(path)}: profile must be a YAML mapping, got "
            f"{type(data).__name__}"
        )

    missing = [k for k in REQUIRED_PROFILE_KEYS if not data.get(k)]
    if missing:
        raise ProfileValidationError(
            f"{_loc(path)}: missing required key(s): {', '.join(missing)}"
        )

    inherits_raw = data.get("inherits") or []
    if isinstance(inherits_raw, str):
        inherits_raw = [inherits_raw]
    if not isinstance(inherits_raw, list):
        raise ProfileValidationError(
            f"{_loc(path)}: 'inherits' must be a list of profile names"
        )

    detectors_raw = data.get("required_detectors") or ["presidio"]
    if isinstance(detectors_raw, str):
        detectors_raw = [detectors_raw]
    detectors = frozenset(str(d).strip().lower() for d in detectors_raw)
    unknown = detectors - KNOWN_DETECTORS
    if unknown:
        raise ProfileValidationError(
            f"{_loc(path)}: unknown required_detectors: "
            f"{', '.join(sorted(unknown))}. Known: "
            f"{', '.join(sorted(KNOWN_DETECTORS))}"
        )

    entities_raw = data.get("entities") or []
    if not isinstance(entities_raw, list):
        raise ProfileValidationError(
            f"{_loc(path)}: 'entities' must be a list"
        )

    entities: dict[str, EntityRule] = {}
    for index, raw_rule in enumerate(entities_raw):
        if not isinstance(raw_rule, dict):
            raise ProfileValidationError(
                f"{_loc(path)}: entities[{index}] must be a mapping"
            )
        rule = _validate_entity_rule(raw_rule, path, index)
        if rule.type in entities:
            raise ProfileValidationError(
                f"{_loc(path)}: duplicate entity type '{rule.type}'"
            )
        entities[rule.type] = rule

    return ProfileDefinition(
        name=str(data["name"]).strip().upper(),
        version=str(data["version"]).strip(),
        description=str(data["description"]).strip(),
        inherits=tuple(str(p).strip().upper() for p in inherits_raw),
        required_detectors=detectors,
        entities=entities,
        source_path=path,
    )


def load_profile_file(path: Path) -> ProfileDefinition:
    """Load and validate one profile file.

    Refuses on any problem — a missing or malformed profile must never degrade
    into an unreviewed default (Requirement 19.10).
    """
    if not path.is_file():
        raise ProfileValidationError(f"profile file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ProfileValidationError(
            f"{path}: invalid YAML — {exc.__class__.__name__}"
        ) from None
    except OSError as exc:
        raise ProfileValidationError(
            f"{path}: could not be read — {exc.__class__.__name__}"
        ) from None

    definition = validate_profile_dict(raw, path)

    expected_stem = definition.name
    if path.stem.upper() != expected_stem:
        raise ProfileValidationError(
            f"{path}: profile name '{definition.name}' does not match "
            f"filename '{path.stem}'. Mismatched names make the active policy "
            f"ambiguous."
        )

    return definition
