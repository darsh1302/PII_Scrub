"""Storage records — the row shapes the repositories move.

Frozen dataclasses rather than an ORM's mutable models. Two reasons, and the
second is the load-bearing one.

An ORM's identity map and lazy loading make it possible to reach related rows
without stating a workspace, which is precisely the ambient access `[R15.3]` rules
out. Explicit records and hand-written SQL keep the workspace predicate visible in
the statement where a reviewer can see it.

And these records cross the seam into presenters, which are unit-tested without a
database. A row that cannot be constructed in a test without a session is a row
whose presenter needs a database to test.

``workspace_id`` is a required field on every record carrying data, not an
inherited attribute. Design document, "Core tables".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from uuid import UUID


class Role(str, Enum):
    """Held on the membership, not the user.

    The same person may approve in one workspace and only read in another, which
    a role on the user cannot express. `[R15.2]`, `[R15.6]`.
    """

    READER = "reader"
    AUTHOR = "author"
    APPROVER = "approver"
    ADMIN = "admin"


class CompletionReason(str, Enum):
    """`[R6.9]`, NOT NULL on ``run``.

    A run that ends without one is a loud failure rather than a row that looks
    finished. Design document, "Completion reasons".
    """

    COMPLETED = "completed"
    MAX_STEPS = "max_steps"
    BUDGET_EXHAUSTED = "budget_exhausted"
    POLICY_BLOCKED = "policy_blocked"
    PROVIDER_ERROR = "provider_error"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    AWAITING_APPROVAL = "awaiting_approval"


@dataclass(frozen=True)
class Workspace:
    """The isolation boundary. Deletion cascades to everything it owns `[R14.5]`."""

    id: UUID
    name: str
    created_at: datetime


@dataclass(frozen=True)
class User:
    """Identity. ``password_verifier`` carries its own KDF parameters.

    Recording the KDF and its parameters per row is what makes raising the cost
    factor later possible without invalidating every existing password — task 3.1.
    """

    id: UUID
    email: str
    password_verifier: str
    created_at: datetime
    disabled: bool = False


@dataclass(frozen=True)
class Membership:
    """A user's role within one workspace."""

    id: UUID
    workspace_id: UUID
    user_id: UUID
    role: Role
    created_at: datetime


@dataclass(frozen=True)
class Experiment:
    """A saved lab configuration plus the question it was asked to answer.

    ``purpose`` is not decoration. A configuration without a stated purpose is
    unusable three weeks later, and the comparison lab's value depends on knowing
    what a run was trying to show.
    """

    id: UUID
    workspace_id: UUID
    lab: str
    name: str
    purpose: str
    configuration: dict[str, object]
    created_at: datetime
    created_by: UUID | None = None


@dataclass(frozen=True)
class Run:
    """One execution. ``completion_reason`` is never None once terminal."""

    id: UUID
    workspace_id: UUID
    experiment_id: UUID | None
    status: str
    completion_reason: CompletionReason | None
    started_at: datetime
    finished_at: datetime | None = None
    prompt_template_version_id: UUID | None = None
    price_table_version: str | None = None
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_micros: int = 0
    token_counts_are_estimated: bool = False
    """`[R1.4]`. Where a provider does not report usage the gateway estimates and
    says so, rather than presenting an estimate as a measurement."""
    latency_ms: int | None = None
    error_detail: str | None = None


@dataclass(frozen=True)
class Document:
    """Metadata only. The payload lives in the object store under ``payload_ref``.

    ``sha256`` is over the original bytes, which is how a re-upload is recognised
    without holding a second copy.
    """

    id: UUID
    workspace_id: UUID
    label: str
    media_type: str
    byte_size: int
    sha256: str
    payload_ref: str
    created_at: datetime
    source_kind: str = "upload"
    page_count: int | None = None


@dataclass(frozen=True)
class Chunk:
    """Offsets refer to the original document, never to a normalized intermediate.

    Property 13. A normalized intermediate is a different string, so an offset
    into it cannot locate a citation or a redaction in what the user uploaded.
    """

    id: UUID
    workspace_id: UUID
    document_id: UUID
    sequence: int
    start_offset: int
    end_offset: int
    token_count: int
    strategy: str
    text_ref: str | None = None
    page_or_section: str | None = None

    def __post_init__(self) -> None:
        if self.end_offset < self.start_offset:
            raise ValueError(
                f"chunk {self.sequence}: end_offset {self.end_offset} precedes "
                f"start_offset {self.start_offset}"
            )
        if self.start_offset < 0:
            raise ValueError(f"chunk {self.sequence}: negative start_offset")


@dataclass(frozen=True)
class Embedding:
    """A vector with its provenance.

    ``embedding_model`` and ``embedding_model_version`` are NOT NULL because
    Property 12 forbids comparing across models, and a search cannot refuse a
    mismatch it has no record of. Cosine distance between two embedding spaces is
    a number with no meaning.
    """

    id: UUID
    workspace_id: UUID
    chunk_id: UUID
    document_id: UUID
    embedding_model: str
    embedding_model_version: str
    dimensions: int
    vector: tuple[float, ...]
    created_at: datetime

    def __post_init__(self) -> None:
        if not self.embedding_model or not self.embedding_model_version:
            raise ValueError(
                "an embedding without model provenance cannot be safely "
                "searched — Property 12"
            )
        if len(self.vector) != self.dimensions:
            raise ValueError(
                f"vector length {len(self.vector)} does not match declared "
                f"dimensions {self.dimensions}"
            )


@dataclass(frozen=True)
class ScoredRecord:
    """A search hit: the embedding, its score, and enough to show the source."""

    embedding_id: UUID
    chunk_id: UUID
    document_id: UUID
    score: float
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class TraceEvent:
    """Ordered by ``(run_id, sequence)``. Payload is redacted before it arrives.

    ``redaction_count`` lets a trace state "3 values redacted" without holding
    them — `[R6.7]`, Property 11.
    """

    id: UUID
    workspace_id: UUID
    run_id: UUID
    sequence: int
    event_type: str
    occurred_at: datetime
    duration_ms: int | None
    payload: dict[str, object]
    redaction_count: int = 0


@dataclass(frozen=True)
class PromptTemplateVersion:
    """Versioned. A run references a specific version `[R2.1]`, `[R2.6]`."""

    id: UUID
    workspace_id: UUID
    template_id: UUID
    version: int
    body: str
    variables: tuple[str, ...]
    created_at: datetime


@dataclass(frozen=True)
class ToolInvocation:
    """One tool call within a run, with its risk level and outcome."""

    id: UUID
    workspace_id: UUID
    run_id: UUID
    sequence: int
    tool_name: str
    risk_level: str
    status: str
    started_at: datetime
    finished_at: datetime | None = None
    requires_approval: bool = False


@dataclass(frozen=True)
class Approval:
    """`[R10.4]`, `[R15.6]`. Records who decided, and what was actually executed.

    ``executed_parameters`` is stored separately from the requested parameters so
    Property 9 can assert they are equal. Substituting a value at execution time
    and calling it approved is the failure this shape exists to make visible.
    """

    id: UUID
    workspace_id: UUID
    tool_invocation_id: UUID
    approver_user_id: UUID
    decision: str
    decided_at: datetime
    requested_parameters: dict[str, object]
    executed_parameters: dict[str, object] | None = None
    note: str | None = None


@dataclass(frozen=True)
class RetentionPolicy:
    """One row per workspace per content category `[R14.3]`, `[R14.4]`.

    Startup refuses when a category required by the classification registry has
    no row. ``retention_days`` is deliberately not nullable: "no expiry" has to be
    spelled as a long period someone chose, not left blank.
    """

    id: UUID
    workspace_id: UUID
    category: str
    retention_days: int
    updated_at: datetime

    def __post_init__(self) -> None:
        if self.retention_days < 1:
            raise ValueError(
                f"{self.category}: retention_days must be at least 1 — a zero or "
                f"negative period would delete data on write"
            )


@dataclass(frozen=True)
class PriceTableVersion:
    """Versioned model pricing. A run records the version it used `[R1.8]`."""

    version: str
    effective_from: datetime
    entries: dict[str, object]
    created_at: datetime
