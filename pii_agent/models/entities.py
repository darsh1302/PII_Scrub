"""Entity and NormalizedEvent models.

Two invariants matter here:

* ``Entity.start``/``end`` are **whole-document** coordinates. Chunk-local
  offsets are converted before reconciliation and must never reach the applier
  (Requirement 28.2, Property 12). A chunk-local offset applied to a full
  document scrubs the wrong span, silently.
* ``Entity.text`` is server-side only. ``to_llm_metadata()`` is the only
  sanctioned path toward the model and omits both text (for HIGH severity) and
  offsets entirely (Requirement 31.2, Property 9).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pii_agent.models.enums import (
    ConfidenceSource,
    DetectorName,
    EntitySeverity,
    ScrubAction,
    SourceType,
)

# Default severity by entity type. Drives LLM-exposure rules and reconciliation
# tie-breaks. Anything unlisted defaults to MEDIUM — biased toward protection.
DEFAULT_SEVERITY: dict[str, EntitySeverity] = {
    # HIGH — credentials and secrets
    "PASSWORD": EntitySeverity.HIGH,
    "API_KEY": EntitySeverity.HIGH,
    "ACCESS_TOKEN": EntitySeverity.HIGH,
    "REFRESH_TOKEN": EntitySeverity.HIGH,
    "OAUTH_TOKEN": EntitySeverity.HIGH,
    "JWT": EntitySeverity.HIGH,
    "AUTHORIZATION_HEADER": EntitySeverity.HIGH,
    "CLIENT_SECRET": EntitySeverity.HIGH,
    "SESSION_COOKIE": EntitySeverity.HIGH,
    "PRIVATE_KEY": EntitySeverity.HIGH,
    "SSH_PRIVATE_KEY": EntitySeverity.HIGH,
    "DATABASE_CREDENTIAL": EntitySeverity.HIGH,
    "CLOUD_CREDENTIAL": EntitySeverity.HIGH,
    "CONNECTION_STRING": EntitySeverity.HIGH,
    "AWS_ACCESS_KEY": EntitySeverity.HIGH,
    "CVV": EntitySeverity.HIGH,
    "PIN": EntitySeverity.HIGH,
    "TRACK_DATA": EntitySeverity.HIGH,
    "MODEL_PROVIDER_TOKEN": EntitySeverity.HIGH,
    # MEDIUM — direct identifiers
    "US_SSN": EntitySeverity.MEDIUM,
    "CREDIT_CARD": EntitySeverity.MEDIUM,
    "PAN": EntitySeverity.MEDIUM,
    "US_PASSPORT": EntitySeverity.MEDIUM,
    "US_DRIVER_LICENSE": EntitySeverity.MEDIUM,
    "US_BANK_NUMBER": EntitySeverity.MEDIUM,
    "IBAN_CODE": EntitySeverity.MEDIUM,
    "MEDICAL_LICENSE": EntitySeverity.MEDIUM,
    "MEDICAL_RECORD_NUMBER": EntitySeverity.MEDIUM,
    "PATIENT_IDENTIFIER": EntitySeverity.MEDIUM,
    "ROUTING_NUMBER": EntitySeverity.MEDIUM,
    "SWIFT_CODE": EntitySeverity.MEDIUM,
    "FINANCIAL_ACCOUNT": EntitySeverity.MEDIUM,
    "TAX_IDENTIFIER": EntitySeverity.MEDIUM,
    "WIRE_INSTRUCTIONS": EntitySeverity.MEDIUM,
    # A card expiry alone does not identify anyone; paired with a PAN it
    # completes a usable card, and the PAN carries its own MEDIUM rating.
    "CARD_EXPIRY": EntitySeverity.LOW,
    "CREDIT_SCORE": EntitySeverity.LOW,
    # LLM payloads carry whatever the user typed, so their real severity is the
    # severity of their contents. MEDIUM because a prompt log is, empirically,
    # dense with direct identifiers — and an embedding is not opaque: inversion
    # recovers much of the source text, so it ranks with the text it encodes.
    "USER_PROMPT": EntitySeverity.MEDIUM,
    "SYSTEM_PROMPT": EntitySeverity.MEDIUM,
    "MODEL_COMPLETION": EntitySeverity.MEDIUM,
    "AGENT_MEMORY": EntitySeverity.MEDIUM,
    "TOOL_ARGUMENTS": EntitySeverity.MEDIUM,
    "TOOL_RESPONSE": EntitySeverity.MEDIUM,
    "RETRIEVED_DOCUMENT": EntitySeverity.MEDIUM,
    "VECTOR_EMBEDDING": EntitySeverity.MEDIUM,
    "EMAIL_ADDRESS": EntitySeverity.MEDIUM,
    "PHONE_NUMBER": EntitySeverity.MEDIUM,
    "PERSON": EntitySeverity.MEDIUM,
    # LOW — indirect identifiers
    "LOCATION": EntitySeverity.LOW,
    "IP_ADDRESS": EntitySeverity.LOW,
    "DATE_TIME": EntitySeverity.LOW,
    "ORGANIZATION": EntitySeverity.LOW,
    "NRP": EntitySeverity.LOW,
    "URL": EntitySeverity.LOW,
}

# Entity types backed by a checksum or structural validator. Reconciliation
# rule 3 prefers these over unvalidated guesses.
VALIDATOR_BACKED_TYPES = frozenset(
    {
        "CREDIT_CARD",
        "PAN",
        "IBAN_CODE",
        "US_SSN",
        "JWT",
        "AWS_ACCESS_KEY",
        # ABA weighted checksum, enforced in RoutingNumberRecognizer. Without it
        # a bare nine-digit run is indistinguishable from an ordinary log id.
        "ROUTING_NUMBER",
    }
)


def severity_for(entity_type: str) -> EntitySeverity:
    """Severity for a type, defaulting to MEDIUM when unknown."""
    return DEFAULT_SEVERITY.get(entity_type.upper(), EntitySeverity.MEDIUM)


@dataclass
class Entity:
    """A detected sensitive item, in whole-document coordinates."""

    type: str
    start: int
    end: int
    confidence: float
    text: str = field(repr=False, default="")
    confidence_source: ConfidenceSource = ConfidenceSource.CALIBRATED
    severity: EntitySeverity | None = None
    detected_by: list[str] = field(default_factory=list)
    action: ScrubAction | None = None
    is_base_security: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity is None:
            self.severity = severity_for(self.type)
        if self.start < 0 or self.end < 0:
            raise ValueError(f"negative offset: [{self.start}, {self.end})")
        if self.end <= self.start:
            raise ValueError(
                f"empty or inverted span: [{self.start}, {self.end}) "
                f"for {self.type}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence out of range: {self.confidence}")

    def __repr__(self) -> str:
        """Never render ``text`` — this object holds raw PII."""
        return (
            f"Entity(type={self.type!r}, span=[{self.start},{self.end}), "
            f"confidence={self.confidence:.2f}, "
            f"severity={self.severity.value if self.severity else None}, "
            f"detected_by={self.detected_by})"
        )

    # -- geometry -------------------------------------------------------
    @property
    def span(self) -> tuple[int, int]:
        return (self.start, self.end)

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "Entity") -> bool:
        return self.start < other.end and other.start < self.end

    def contains(self, other: "Entity") -> bool:
        return self.start <= other.start and other.end <= self.end

    @property
    def is_validator_backed(self) -> bool:
        return self.type.upper() in VALIDATOR_BACKED_TYPES

    # -- LLM exposure ---------------------------------------------------
    def to_llm_metadata(self) -> dict[str, Any]:
        """The only sanctioned representation for the reasoning context.

        Omits offsets entirely — the model has no legitimate use for them and
        transcribing them is how PII leaks (SEC-02). Omits text for HIGH
        severity so a detected secret is never sent to the model.
        """
        payload: dict[str, Any] = {
            "type": self.type,
            "severity": self.severity.value if self.severity else "MEDIUM",
            "confidence": round(self.confidence, 2),
            "confidence_source": self.confidence_source.value,
            "detected_by": list(self.detected_by),
        }
        if self.severity and self.severity.text_may_reach_llm:
            payload["preview"] = self.masked_preview()
        else:
            payload["preview"] = f"[{self.type}]"
        return payload

    def masked_preview(self) -> str:
        """Short masked rendering for UI and non-HIGH metadata."""
        if self.severity is EntitySeverity.HIGH:
            return f"[{self.type}]"
        if len(self.text) <= 4:
            return "*" * len(self.text)
        return f"{self.text[:2]}{'*' * (len(self.text) - 4)}{self.text[-2:]}"

    def shifted(self, offset: int) -> "Entity":
        """Return a copy translated by ``offset`` (chunk-local → document)."""
        return Entity(
            type=self.type,
            start=self.start + offset,
            end=self.end + offset,
            confidence=self.confidence,
            text=self.text,
            confidence_source=self.confidence_source,
            severity=self.severity,
            detected_by=list(self.detected_by),
            action=self.action,
            is_base_security=self.is_base_security,
            metadata=dict(self.metadata),
        )


@dataclass
class NormalizedEvent:
    """Common representation of content regardless of origin.

    Source-specific metadata is kept separate from ``content`` so operational
    fields (log group, event id, timestamps) are not themselves scanned as
    document text (Requirement 26.2).
    """

    source_type: SourceType
    content: str = field(repr=False, default="")
    timestamp: str = ""
    source_metadata: dict[str, Any] = field(default_factory=dict)
    chunk_index: int = 0
    total_chunks: int = 1
    global_offset_base: int = 0

    def __repr__(self) -> str:
        return (
            f"NormalizedEvent(source_type={self.source_type.value}, "
            f"chunk={self.chunk_index + 1}/{self.total_chunks}, "
            f"base={self.global_offset_base}, len={len(self.content)})"
        )

    @property
    def is_chunked(self) -> bool:
        return self.total_chunks > 1

    def to_document_offsets(self, entities: list[Entity]) -> list[Entity]:
        """Translate chunk-local entities into document coordinates."""
        if self.global_offset_base == 0:
            return entities
        return [e.shifted(self.global_offset_base) for e in entities]
