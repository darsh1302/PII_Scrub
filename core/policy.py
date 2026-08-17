"""Policy Enforcement Point — the only component that decides a scrub action.

Guardrails G4, G5. Requirement 45. Correctness Property 8.
Addresses review finding SEC-04.

In the reviewed design, ``action`` was a free-form argument the LLM supplied with
nothing constraining it to the active profile. The model could pass ALLOW for
US_SSN — a complete policy bypass reachable through ordinary model error or
through injected log content.

The correction is structural rather than procedural. ``resolve`` computes

    applied = max(profile_mandated, requested, key=ACTION_PRIORITY)

so a request can only ever ratchet restrictiveness *upward*. There is no code
path that returns something weaker than the profile mandates, which is why a
compromised reasoning step cannot weaken the outcome. ``Decision`` asserts the
invariant again at construction, so a future refactor that breaks it fails loudly
instead of leaking.

Requests are ignored entirely for BASE_SECURITY entities. Credentials are not
negotiable, and an operator who selected the wrong profile should still not leak
an API key.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from core.profile_resolver import EffectiveProfile
from models.decision import Decision, DecisionSet
from models.entities import Entity
from models.enums import Destination, EntitySeverity, ScrubAction

# Log-structural timestamp positions. A leading ISO timestamp is the format
# essentially every log line uses.
_LEADING_ISO_TIMESTAMP = re.compile(
    r"^\s{0,4}\[?\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
)


class DestinationRequired(RuntimeError):
    """Raised when a decision depends on a destination that was not supplied.

    Requirement 19.9 — the agent asks rather than applying a destructive
    default. Scrubbing every IP because nobody said where the data was going
    would silently destroy SIEM correlation.
    """

    def __init__(self, entity_types: tuple[str, ...]) -> None:
        self.entity_types = entity_types
        super().__init__(
            "handling depends on the destination for: "
            + ", ".join(entity_types)
        )


@dataclass
class PolicyContext:
    """Inputs a decision may depend on beyond the entity itself."""

    profile: EffectiveProfile
    destination: Destination | None = None
    # Full document text, used only for field-context exemptions. Never
    # forwarded anywhere; the PolicyEngine runs inside the trusted core.
    document: str = ""
    requested_action: ScrubAction | None = None


class PolicyEngine:
    """Resolves per-entity scrub actions. The only authority on this."""

    def resolve(
        self,
        entities: list[Entity],
        context: PolicyContext,
        *,
        strict_destination: bool = True,
    ) -> DecisionSet:
        """Resolve every entity to a Decision.

        Raises DestinationRequired when a destination-sensitive type is present
        and no destination was supplied, unless ``strict_destination`` is off
        (used for dry-run reporting where no artifact is produced).
        """
        if strict_destination and context.destination is None:
            pending = tuple(
                sorted(
                    {
                        e.type.upper()
                        for e in entities
                        if self._needs_destination(e, context.profile)
                    }
                )
            )
            if pending:
                raise DestinationRequired(pending)

        return DecisionSet(
            decisions=[self.resolve_one(entity, context) for entity in entities]
        )

    def resolve_one(self, entity: Entity, context: PolicyContext) -> Decision:
        """Resolve a single entity. Monotonic by construction."""
        profile = context.profile
        rule = profile.rule_for(entity.type)

        # Unknown types default to REDACT, not ALLOW. Detecting something the
        # policy does not describe is a reason for caution, not permission.
        mandated = profile.action_for(entity.type, context.destination)

        is_base_security = entity.is_base_security or self._is_base_security_type(
            entity, profile
        )

        # --- Field-context exemption (COR-04) ------------------------------
        # A leading log timestamp is structural, not personal. Scrubbing it
        # destroys the ability to correlate events, which is the point of logs.
        if rule is not None and rule.field_context_exempt and not is_base_security:
            exemption = self._matching_exemption(entity, rule, context.document)
            if exemption is not None:
                return Decision(
                    entity=entity,
                    profile_mandated_action=ScrubAction.ALLOW,
                    applied_action=ScrubAction.ALLOW,
                    requested_action=context.requested_action,
                    deciding_rule=f"field_context_exempt:{exemption}",
                    is_base_security=False,
                )

        # --- BASE_SECURITY: requests are ignored entirely (G5) -------------
        if is_base_security:
            return Decision(
                entity=entity,
                profile_mandated_action=mandated,
                applied_action=mandated,
                requested_action=context.requested_action,
                deciding_rule="base_security_mandate",
                is_base_security=True,
                request_was_discarded=(
                    context.requested_action is not None
                    and context.requested_action != mandated
                ),
            )

        # --- Ratchet: requests may only increase restrictiveness (G4) ------
        requested = context.requested_action
        applied = ScrubAction.most_restrictive(mandated, requested)

        if requested is None:
            rule_name = "profile_mandate"
            discarded = False
        elif applied == requested and requested != mandated:
            rule_name = "request_escalated"
            discarded = False
        elif requested == mandated:
            rule_name = "request_matched_profile"
            discarded = False
        else:
            # The request was weaker and has been dropped. Recorded rather than
            # silently ignored so the user gets an explanation.
            rule_name = "request_discarded_weaker_than_profile"
            discarded = True

        return Decision(
            entity=entity,
            profile_mandated_action=mandated,
            applied_action=applied,
            requested_action=requested,
            deciding_rule=rule_name,
            is_base_security=False,
            request_was_discarded=discarded,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _is_base_security_type(entity: Entity, profile: EffectiveProfile) -> bool:
        from profiles.schema import BASE_SECURITY_TYPES

        if entity.type.upper() in BASE_SECURITY_TYPES:
            return True
        # HIGH severity with a credential-ish detector attribution also counts:
        # a new recognizer added without updating BASE_SECURITY_TYPES should
        # still get unconditional handling.
        return (
            entity.severity is EntitySeverity.HIGH
            and "custom_security" in entity.detected_by
        )

    @staticmethod
    def _needs_destination(entity: Entity, profile: EffectiveProfile) -> bool:
        rule = profile.rule_for(entity.type)
        return rule is not None and rule.is_destination_sensitive

    @staticmethod
    def _matching_exemption(entity: Entity, rule, document: str) -> str | None:
        """Return the exemption name that applies to this entity, if any.

        Two forms are supported:

        * ``leading_iso_timestamp`` — the entity sits at the start of its line
          and looks like a log timestamp.
        * a field name — the entity is the value of a key with that name, as
          produced by the structured parsers (``path: value``).
        """
        if not document:
            return None

        line_start = document.rfind("\n", 0, entity.start) + 1
        line_end = document.find("\n", entity.end)
        if line_end == -1:
            line_end = len(document)
        line = document[line_start:line_end]
        offset_in_line = entity.start - line_start

        for name in rule.field_context_exempt:
            if name == "leading_iso_timestamp":
                # Only exempt if the entity is at the very start of the line and
                # the line opens with a timestamp shape.
                if offset_in_line <= 4 and _LEADING_ISO_TIMESTAMP.match(line):
                    return name
                continue

            # Field-name form: the value follows "<name>:" or "<name>=".
            prefix = line[:offset_in_line]
            if re.search(
                rf"(?:^|[\s,{{\[\"']){re.escape(name)}[\"']?\s*[:=]\s*[\"']?$",
                prefix,
                re.IGNORECASE,
            ):
                return name

        return None


_engine: PolicyEngine | None = None


def get_policy_engine() -> PolicyEngine:
    """Process-wide engine. Stateless, so sharing is safe."""
    global _engine
    if _engine is None:
        _engine = PolicyEngine()
    return _engine
