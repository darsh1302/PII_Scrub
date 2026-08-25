"""Enumerations shared across the pipeline.

``ScrubAction`` and ``ACTION_PRIORITY`` together form the lattice that makes the
policy ratchet monotonic (guardrail G4, Property 8). Resolution is ``max()`` over
the priority map, so a requested action can only ever increase restrictiveness.
That property is what contains the blast radius of prompt injection: even a fully
manipulated reasoning step cannot select a weaker action than policy mandates.
"""

from __future__ import annotations

from enum import Enum

from pii_agent.utils.config import ACTION_PRIORITY


class ScrubAction(str, Enum):
    """What happens to a detected entity."""

    ALLOW = "ALLOW"
    REPLACE = "REPLACE"
    MASK = "MASK"
    HASH = "HASH"
    TOKENIZE = "TOKENIZE"
    REDACT = "REDACT"
    BLOCK = "BLOCK"

    @property
    def priority(self) -> int:
        return ACTION_PRIORITY[self.value]

    def is_more_restrictive_than(self, other: "ScrubAction") -> bool:
        return self.priority > other.priority

    @classmethod
    def most_restrictive(cls, *actions: "ScrubAction | None") -> "ScrubAction":
        """Return the most restrictive of the given actions.

        The single place restrictiveness is compared. ``None`` values are
        ignored so callers can pass an absent request without branching.
        """
        present = [a for a in actions if a is not None]
        if not present:
            raise ValueError("at least one action is required")
        return max(present, key=lambda a: a.priority)

    @property
    def suppresses_artifact(self) -> bool:
        """True when this action forbids producing a sanitized artifact at all.

        BLOCK is not a synonym for REDACT (COR-05). REDACT removes a span and
        still yields output; BLOCK means no artifact is produced.
        """
        return self is ScrubAction.BLOCK


class AgentStateEnum(str, Enum):
    """Operational phase of the agent, surfaced live in the UI."""

    IDLE = "IDLE"
    THINKING = "THINKING"
    PLANNING = "PLANNING"
    EXECUTING = "EXECUTING"
    ANALYZING = "ANALYZING"
    REPORTING = "REPORTING"
    WAITING_FOR_INPUT = "WAITING_FOR_INPUT"


class SourceType(str, Enum):
    TEXT = "TEXT"
    FILE = "FILE"
    APPLICATION_LOG = "APPLICATION_LOG"
    AWS_CLOUDWATCH = "AWS_CLOUDWATCH"
    WINDOWS_EVENT_LOG = "WINDOWS_EVENT_LOG"


class Destination(str, Enum):
    """Where sanitized output is going.

    Affects policy: operational identifiers useful for internal investigation
    (IP, hostname, username) may be permitted for INTERNAL_SIEM while being
    scrubbed for anything external (Requirement 40).
    """

    INTERNAL_SIEM = "INTERNAL_SIEM"
    EXTERNAL_ANALYTICS = "EXTERNAL_ANALYTICS"
    EXTERNAL_LLM = "EXTERNAL_LLM"
    FILE = "FILE"
    S3 = "S3"

    @property
    def is_external(self) -> bool:
        return self in {
            Destination.EXTERNAL_ANALYTICS,
            Destination.EXTERNAL_LLM,
            Destination.S3,
        }


class EntitySeverity(str, Enum):
    """Severity class, used for reconciliation ties and LLM-exposure rules."""

    HIGH = "HIGH"  # credentials, secrets, private keys
    MEDIUM = "MEDIUM"  # direct PII: SSN, credit card, medical record
    LOW = "LOW"  # indirect identifiers: dates, IPs, org names

    @property
    def rank(self) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3}[self.value]

    @property
    def text_may_reach_llm(self) -> bool:
        """HIGH-severity entity text never enters the reasoning context.

        Requirement 31.2, Property 9. Sending a detected secret to the model to
        ask whether it is a secret would defeat the point.
        """
        return self is not EntitySeverity.HIGH


class ConfidenceSource(str, Enum):
    """Whether a confidence value means anything.

    spaCy emits no calibrated probability, so the pipeline assigns a heuristic
    constant. Recording which is which stops reconciliation and the UI from
    treating that constant as comparable to a Presidio score (COR-03).
    """

    CALIBRATED = "CALIBRATED"
    HEURISTIC = "HEURISTIC"


class RefusalReason(str, Enum):
    """Why the pipeline declined to produce a sanitized artifact.

    Refusals are features. Each must be observably distinct from success and
    from the others, in both the tool contract and the UI.
    """

    DEGRADED_COVERAGE = "DEGRADED_COVERAGE"
    RESIDUAL_PII_DETECTED = "RESIDUAL_PII_DETECTED"
    BLOCKED_ARTIFACT = "BLOCKED_ARTIFACT"
    INVALID_PROFILE = "INVALID_PROFILE"
    TIMEOUT = "TIMEOUT"
    NEEDS_DESTINATION = "NEEDS_DESTINATION"
    LIMIT_EXCEEDED = "LIMIT_EXCEEDED"
    SOURCE_ERROR = "SOURCE_ERROR"

    @property
    def user_message(self) -> str:
        """Plain-language explanation. No stack traces, no internal codes."""
        return {
            "DEGRADED_COVERAGE": (
                "Part of the source could not be inspected, so a cleaned "
                "version would look verified without actually being verified."
            ),
            "RESIDUAL_PII_DETECTED": (
                "The verification pass still found sensitive data in the "
                "cleaned output. The artifact was withheld — this is a defect."
            ),
            "BLOCKED_ARTIFACT": (
                "The active policy blocks producing any cleaned copy of this "
                "content."
            ),
            "INVALID_PROFILE": (
                "The requested profile is missing or failed validation."
            ),
            "TIMEOUT": (
                "Processing exceeded its time budget, so coverage is "
                "incomplete."
            ),
            "NEEDS_DESTINATION": (
                "Handling depends on where this data is going."
            ),
            "LIMIT_EXCEEDED": "The source exceeds a configured limit.",
            "SOURCE_ERROR": "The source could not be read.",
        }[self.value]


class DetectorName(str, Enum):
    """Detectors, in reconciliation precedence order (highest first).

    Precedence: a purpose-built security recognizer beats generic Presidio,
    which beats spaCy's statistical guess (COR-03 rule 4).
    """

    CUSTOM_SECURITY = "custom_security"
    PRESIDIO = "presidio"
    SPACY = "spacy"

    @property
    def precedence(self) -> int:
        return {"custom_security": 3, "presidio": 2, "spacy": 1}[self.value]
