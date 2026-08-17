"""Profile inheritance resolution.

Merge is restrictiveness-preserving: when a rule appears at multiple levels of
the inheritance chain, or across several simultaneously applied profiles, the
most restrictive action wins (Requirement 13.3, guardrail G5). BASE_SECURITY is
always folded in regardless of what a profile declares, so an operator who picks
the wrong industry profile still cannot leak an API key.

Resolution is cached per profile-name tuple because it is pure — the same names
and the same files always yield the same effective profile, which is what makes
golden-dataset regression testing viable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from models.enums import Destination, ScrubAction
from profiles.schema import (
    EntityRule,
    ProfileDefinition,
    ProfileValidationError,
    load_profile_file,
)
from utils.config import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    MIN_CHUNK_OVERLAP_CHARS,
)

BASE_SECURITY_NAME = "BASE_SECURITY"
DEFAULT_PROFILE_NAME = "DEFAULT_PII"

PROFILES_DIR = Path(__file__).parent.parent / "profiles"


@dataclass
class EffectiveProfile:
    """A fully resolved policy, ready for the Policy Enforcement Point."""

    name: str
    version: str
    applied_profiles: tuple[str, ...]
    entities: dict[str, EntityRule] = field(default_factory=dict)
    required_detectors: frozenset[str] = frozenset()
    profile_versions: dict[str, str] = field(default_factory=dict)

    # -- policy lookup --------------------------------------------------
    def action_for(
        self, entity_type: str, destination: Destination | None = None
    ) -> ScrubAction:
        """Mandated action for an entity type.

        Unknown types default to REDACT rather than ALLOW. Detecting something
        the policy does not describe is a reason for caution, not permission.
        """
        rule = self.entities.get(entity_type.upper())
        if rule is None or not rule.enabled:
            return ScrubAction.REDACT
        return rule.action_for(destination)

    def rule_for(self, entity_type: str) -> EntityRule | None:
        return self.entities.get(entity_type.upper())

    def is_enabled(self, entity_type: str) -> bool:
        rule = self.entities.get(entity_type.upper())
        return rule is not None and rule.enabled

    def threshold_for(self, entity_type: str) -> float:
        rule = self.entities.get(entity_type.upper())
        if rule is not None and rule.confidence_threshold is not None:
            return rule.confidence_threshold
        return DEFAULT_CONFIDENCE_THRESHOLD

    @property
    def enabled_types(self) -> tuple[str, ...]:
        return tuple(sorted(t for t, r in self.entities.items() if r.enabled))

    @property
    def max_pattern_span(self) -> int:
        """Longest span any enabled rule can match.

        Chunk overlap is derived from this (guardrail G17) so a multi-kilobyte
        PEM block is never split across a boundary and missed in both halves.
        """
        spans = [r.max_pattern_span for r in self.entities.values() if r.enabled]
        return max([*spans, MIN_CHUNK_OVERLAP_CHARS])

    @property
    def destination_sensitive_types(self) -> tuple[str, ...]:
        """Types whose action depends on the destination.

        When any of these is detected and no destination is set, the agent must
        ask rather than guess (Requirement 19.9).
        """
        return tuple(
            sorted(t for t, r in self.entities.items() if r.is_destination_sensitive)
        )

    def requires_destination(self, detected_types: set[str]) -> bool:
        sensitive = set(self.destination_sensitive_types)
        return bool(sensitive & {t.upper() for t in detected_types})

    def describe(self) -> str:
        """Human-readable summary, used when the user asks about a profile."""
        lines = [
            f"{self.name} v{self.version}",
            f"Inheritance chain: {' -> '.join(self.applied_profiles)}",
            f"Required detectors: {', '.join(sorted(self.required_detectors))}",
            f"Detects {len(self.enabled_types)} entity types:",
        ]
        for entity_type in self.enabled_types:
            rule = self.entities[entity_type]
            note = ""
            if rule.is_destination_sensitive:
                note = " (varies by destination)"
            lines.append(f"  {entity_type}: {rule.action.value}{note}")
        return "\n".join(lines)

    def to_metadata(self) -> dict[str, object]:
        return {
            "name": self.name,
            "version": self.version,
            "applied_profiles": list(self.applied_profiles),
            "profile_versions": dict(self.profile_versions),
            "required_detectors": sorted(self.required_detectors),
            "entity_count": len(self.enabled_types),
            "max_pattern_span": self.max_pattern_span,
        }


def _merge_rule(existing: EntityRule | None, incoming: EntityRule) -> EntityRule:
    """Merge two rules for the same entity type, keeping the stricter action.

    Applies to both inheritance (parent vs child) and multi-profile combination.
    Per-destination overrides are merged the same way, so a destination cannot
    be used as a loophole to weaken a rule.
    """
    if existing is None:
        return incoming

    action = ScrubAction.most_restrictive(existing.action, incoming.action)

    # Lower threshold == more sensitive detection == more protective.
    thresholds = [
        t
        for t in (existing.confidence_threshold, incoming.confidence_threshold)
        if t is not None
    ]
    threshold = min(thresholds) if thresholds else None

    destinations: dict[Destination, ScrubAction] = dict(existing.destination_actions)
    for dest, dest_action in incoming.destination_actions.items():
        current = destinations.get(dest)
        destinations[dest] = (
            ScrubAction.most_restrictive(current, dest_action)
            if current is not None
            else dest_action
        )

    return EntityRule(
        type=incoming.type,
        # Enabling wins: if either level wants detection, detect.
        enabled=existing.enabled or incoming.enabled,
        action=action,
        confidence_threshold=threshold,
        severity=incoming.severity or existing.severity,
        detection_methods=tuple(
            dict.fromkeys(existing.detection_methods + incoming.detection_methods)
        ),
        description=incoming.description or existing.description,
        destination_actions=destinations,
        field_context_exempt=tuple(
            dict.fromkeys(
                existing.field_context_exempt + incoming.field_context_exempt
            )
        ),
        max_pattern_span=max(existing.max_pattern_span, incoming.max_pattern_span),
    )


class ProfileResolver:
    """Loads, validates, and resolves profiles from a directory."""

    def __init__(self, profiles_dir: Path | None = None) -> None:
        self._dir = Path(profiles_dir) if profiles_dir else PROFILES_DIR
        self._definitions: dict[str, ProfileDefinition] = {}
        self._resolved: dict[tuple[str, ...], EffectiveProfile] = {}

    # -- loading --------------------------------------------------------
    def available_profiles(self) -> tuple[str, ...]:
        return tuple(
            sorted(p.stem.upper() for p in self._dir.glob("*.yaml"))
        )

    def load_definition(self, name: str) -> ProfileDefinition:
        key = name.strip().upper()
        cached = self._definitions.get(key)
        if cached is not None:
            return cached

        path = self._dir / f"{key}.yaml"
        if not path.is_file():
            available = ", ".join(self.available_profiles()) or "(none found)"
            raise ProfileValidationError(
                f"unknown profile '{name}'. Available: {available}"
            )

        definition = load_profile_file(path)
        self._definitions[key] = definition
        return definition

    # -- resolution -----------------------------------------------------
    def _collect_chain(
        self, name: str, seen: list[str] | None = None
    ) -> list[ProfileDefinition]:
        """Depth-first parents-before-children ordering.

        Detects inheritance cycles, which would otherwise recurse until the
        stack gives out.
        """
        seen = seen or []
        key = name.strip().upper()

        if key in seen:
            cycle = " -> ".join([*seen, key])
            raise ProfileValidationError(
                f"circular profile inheritance: {cycle}"
            )

        definition = self.load_definition(key)
        chain: list[ProfileDefinition] = []
        for parent in definition.inherits:
            chain.extend(self._collect_chain(parent, [*seen, key]))
        chain.append(definition)
        return chain

    def resolve(self, *names: str) -> EffectiveProfile:
        """Resolve one or more profiles into a single effective policy."""
        requested = tuple(
            n.strip().upper() for n in (names or (DEFAULT_PROFILE_NAME,)) if n
        ) or (DEFAULT_PROFILE_NAME,)

        cache_key = tuple(sorted(set(requested)))
        cached = self._resolved.get(cache_key)
        if cached is not None:
            return cached

        # BASE_SECURITY is unconditional — never rely on a profile declaring it.
        chain: list[ProfileDefinition] = list(self._collect_chain(BASE_SECURITY_NAME))
        for name in requested:
            if name == BASE_SECURITY_NAME:
                continue
            chain.extend(self._collect_chain(name))

        entities: dict[str, EntityRule] = {}
        detectors: set[str] = set()
        versions: dict[str, str] = {}
        applied: list[str] = []

        for definition in chain:
            if definition.name not in applied:
                applied.append(definition.name)
            versions[definition.name] = definition.version
            detectors |= set(definition.required_detectors)
            for entity_type, rule in definition.entities.items():
                entities[entity_type] = _merge_rule(entities.get(entity_type), rule)

        primary = requested[0] if requested else DEFAULT_PROFILE_NAME
        display_name = (
            primary if len(requested) == 1 else "+".join(sorted(requested))
        )

        effective = EffectiveProfile(
            name=display_name,
            version=versions.get(primary, "0.0.0"),
            applied_profiles=tuple(applied),
            entities=entities,
            required_detectors=frozenset(detectors),
            profile_versions=versions,
        )
        self._resolved[cache_key] = effective
        return effective

    def clear_cache(self) -> None:
        self._definitions.clear()
        self._resolved.clear()


_default_resolver: ProfileResolver | None = None


def get_resolver() -> ProfileResolver:
    """Process-wide resolver. Safe to share: profiles are read-only data."""
    global _default_resolver
    if _default_resolver is None:
        _default_resolver = ProfileResolver()
    return _default_resolver


def resolve_profile(*names: str) -> EffectiveProfile:
    return get_resolver().resolve(*names)
