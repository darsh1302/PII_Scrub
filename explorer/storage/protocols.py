"""Repository and object-store protocols — task 2.1.

One rule governs every signature here: **``workspace_id`` is an explicit
parameter.** Not ambient context, not a thread-local, not a current-workspace
global set by middleware.

That is a deliberate ergonomic cost. An ambient workspace would remove a parameter
from perhaps sixty call sites. It would also mean that a cross-tenant read looks
identical in the source to a correct one, and the difference lives in whether some
earlier frame set a variable. `[R15.3]` requires filtering at the query level, and
`[R15.4]` requires that a cross-workspace read be impossible rather than unlikely;
neither is testable when the scope is invisible at the call site.

Protocols rather than base classes so an adapter is structurally typed — the
in-memory adapter used by presenter tests is not a subclass of anything, and the
architecture test does not need to know it exists.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from typing import Protocol, runtime_checkable
from uuid import UUID

from explorer.storage.records import (
    Approval,
    Chunk,
    Document,
    Embedding,
    Experiment,
    Membership,
    PromptTemplateVersion,
    RetentionPolicy,
    Role,
    Run,
    ScoredRecord,
    ToolInvocation,
    TraceEvent,
    User,
    Workspace,
)


class StorageError(RuntimeError):
    """Base for storage failures that callers are expected to handle."""


class NotFound(StorageError):
    """A row does not exist, or exists in another workspace.

    The two cases are deliberately indistinguishable. `[R15.4]` requires that a
    cross-workspace attempt not disclose existence, and a distinct
    "wrong workspace" error is exactly that disclosure — it confirms the id is
    real. Returning the same failure for both means an attacker learns nothing
    from the difference.
    """


class ObjectStoreError(StorageError):
    """The payload store failed. Distinct from a missing row."""


@runtime_checkable
class ObjectStore(Protocol):
    """Content payloads. Filesystem locally, S3-compatible in deployment.

    Keys are opaque and workspace-prefixed by the caller through
    :func:`explorer.storage.object_store.payload_key`, so a leaked key does not
    name a document and a listing cannot walk out of a workspace.
    """

    def put(self, key: str, data: bytes, *, content_type: str) -> None: ...

    def get(self, key: str) -> bytes: ...

    def delete(self, key: str) -> bool:
        """True when something was removed.

        Idempotent: deleting an absent key is not an error. The retention sweeper
        and the cascade both re-run, and a sweeper that raises on the second pass
        is a sweeper someone disables.
        """
        ...

    def exists(self, key: str) -> bool: ...

    def iter_keys(self, prefix: str) -> Iterator[str]:
        """Keys under ``prefix``. Used by the orphan check, not by read paths."""
        ...

    def delete_prefix(self, prefix: str) -> int:
        """Remove everything under a prefix; returns how many objects went.

        Workspace deletion needs this `[R14.5]`. Deleting key by key would leave a
        partially-emptied workspace if it failed midway, and the count is what the
        deletion audit record reports `[R14.6]`.
        """
        ...


@runtime_checkable
class AuditWriter(Protocol):
    """The narrow slice of the audit chain that deletion needs.

    Declared here rather than importing
    :class:`explorer.observability.audit_chain.AuditChain`, because rule D8 makes
    storage the bottom layer and observability sits above it.

    That rule caught this the moment it was written, which is the point of having it.
    The alternative — storage importing observability — would have run fine and would
    have meant a change to trace-event handling could break document deletion. Storage
    declares what it requires; the composition root supplies it.
    """

    def append(self, record: dict[str, object]) -> str:
        """Persist a record durably and return its hash."""
        ...


@runtime_checkable
class WorkspaceRepository(Protocol):
    """The one repository without a ``workspace_id`` parameter, being the table
    that defines it."""

    def create(self, workspace: Workspace) -> None: ...

    def get(self, workspace_id: UUID) -> Workspace: ...

    def list_for_user(self, user_id: UUID) -> list[Workspace]: ...

    def delete(self, workspace_id: UUID) -> None:
        """Cascades to everything the workspace owns `[R14.5]`."""
        ...


@runtime_checkable
class UserRepository(Protocol):
    """Also workspace-free: a user exists before joining anything."""

    def create(self, user: User) -> None: ...

    def get(self, user_id: UUID) -> User: ...

    def find_by_email(self, email: str) -> User | None: ...


@runtime_checkable
class MembershipRepository(Protocol):
    def add(self, membership: Membership) -> None: ...

    def role_for(self, *, workspace_id: UUID, user_id: UUID) -> Role | None:
        """``None`` means not a member. Callers must treat that as no access
        rather than as a default role."""
        ...

    def list_members(self, workspace_id: UUID) -> list[Membership]: ...

    def remove(self, *, workspace_id: UUID, user_id: UUID) -> bool: ...


@runtime_checkable
class ExperimentRepository(Protocol):
    def create(self, experiment: Experiment) -> None: ...

    def get(self, experiment_id: UUID, *, workspace_id: UUID) -> Experiment: ...

    def list(
        self, *, workspace_id: UUID, lab: str | None = None, limit: int = 50
    ) -> list[Experiment]: ...

    def delete(self, experiment_id: UUID, *, workspace_id: UUID) -> bool: ...


@runtime_checkable
class RunRepository(Protocol):
    def create(self, run: Run) -> None: ...

    def get(self, run_id: UUID, *, workspace_id: UUID) -> Run: ...

    def finish(
        self,
        run_id: UUID,
        *,
        workspace_id: UUID,
        completion_reason: str,
        finished_at: object,
        latency_ms: int | None = None,
        error_detail: str | None = None,
    ) -> None:
        """Terminal transition. ``completion_reason`` has no default `[R6.9]`.

        Property 7 is a database constraint, but the absent default here is what
        makes a caller decide rather than accept ``COMPLETED`` by omission.
        """
        ...

    def list(
        self,
        *,
        workspace_id: UUID,
        experiment_id: UUID | None = None,
        limit: int = 50,
    ) -> list[Run]: ...

    def delete(self, run_id: UUID, *, workspace_id: UUID) -> bool:
        """Cascades to trace events, tool invocations and approvals `[R14.5]`."""
        ...


@runtime_checkable
class DocumentRepository(Protocol):
    def create(self, document: Document) -> None: ...

    def get(self, document_id: UUID, *, workspace_id: UUID) -> Document: ...

    def find_by_sha256(self, sha256: str, *, workspace_id: UUID) -> Document | None:
        """Scoped, so an identical upload in another workspace is not disclosed —
        and not shared either. Deduplicating across workspaces would make one
        workspace's retention decision affect another's data."""
        ...

    def list(self, *, workspace_id: UUID, limit: int = 50) -> list[Document]: ...

    def delete(self, document_id: UUID, *, workspace_id: UUID) -> bool:
        """Cascades to chunks and embeddings; the caller removes payloads.

        Property 14 asserts the whole cascade including object-store keys, which
        the database cannot do on its own.
        """
        ...


@runtime_checkable
class ChunkRepository(Protocol):
    def replace_for_document(
        self, document_id: UUID, *, workspace_id: UUID, chunks: Sequence[Chunk]
    ) -> None:
        """Rechunking replaces wholesale rather than appending.

        Two strategies' chunks in one table for one document would give retrieval
        overlapping duplicates with no way to tell which run produced them.
        """
        ...

    def list_for_document(
        self, document_id: UUID, *, workspace_id: UUID
    ) -> list[Chunk]: ...

    def get(self, chunk_id: UUID, *, workspace_id: UUID) -> Chunk: ...

    def count_for_document(self, document_id: UUID, *, workspace_id: UUID) -> int: ...


@runtime_checkable
class VectorStore(Protocol):
    """Both adapters filter by workspace inside the query, never after it.

    A post-filter means the other workspace's rows were already read, and a
    similarity search that reads them has already computed scores over them —
    timing alone then discloses corpus size.
    """

    def upsert(self, records: Sequence[Embedding]) -> None: ...

    def search(
        self,
        query_vector: Sequence[float],
        *,
        workspace_id: UUID,
        embedding_model: str,
        top_k: int,
        score_threshold: float | None = None,
        metadata_filter: Mapping[str, object] | None = None,
    ) -> list[ScoredRecord]:
        """Refuses when ``embedding_model`` differs from the stored vectors'
        model `[R4.7]`, Property 12."""
        ...

    def delete_by_document(self, document_id: UUID, *, workspace_id: UUID) -> int: ...

    def count(self, *, workspace_id: UUID) -> int: ...


@runtime_checkable
class TraceEventRepository(Protocol):
    """Writes go through the redaction middleware, not directly here.

    Property 11 is asserted on the write call rather than on rendered output, so
    this protocol is deliberately the *inner* interface: a caller that reaches it
    without passing through redaction is the thing task 5.2's test looks for.
    """

    def append(self, event: TraceEvent) -> None: ...

    def list_for_run(self, run_id: UUID, *, workspace_id: UUID) -> list[TraceEvent]:
        """Ordered by ``(run_id, sequence)``."""
        ...

    def delete_for_run(self, run_id: UUID, *, workspace_id: UUID) -> int: ...


@runtime_checkable
class PromptTemplateRepository(Protocol):
    def add_version(self, version: PromptTemplateVersion) -> None: ...

    def get_version(
        self, version_id: UUID, *, workspace_id: UUID
    ) -> PromptTemplateVersion: ...

    def latest(
        self, template_id: UUID, *, workspace_id: UUID
    ) -> PromptTemplateVersion | None: ...

    def list_versions(
        self, template_id: UUID, *, workspace_id: UUID
    ) -> list[PromptTemplateVersion]: ...


@runtime_checkable
class ToolInvocationRepository(Protocol):
    def create(self, invocation: ToolInvocation) -> None: ...

    def get(self, invocation_id: UUID, *, workspace_id: UUID) -> ToolInvocation: ...

    def list_for_run(
        self, run_id: UUID, *, workspace_id: UUID
    ) -> list[ToolInvocation]: ...


@runtime_checkable
class ApprovalRepository(Protocol):
    def record(self, approval: Approval) -> None: ...

    def for_invocation(
        self, tool_invocation_id: UUID, *, workspace_id: UUID
    ) -> Approval | None: ...


@runtime_checkable
class RetentionPolicyRepository(Protocol):
    def upsert(self, policy: RetentionPolicy) -> None: ...

    def get(self, *, workspace_id: UUID, category: str) -> RetentionPolicy | None: ...

    def list_for_workspace(self, workspace_id: UUID) -> list[RetentionPolicy]: ...

    def missing_categories(
        self, workspace_id: UUID, required: frozenset[str]
    ) -> set[str]:
        """Categories with no configured period.

        Task 4.1 turns a non-empty result into a startup refusal `[R14.3]`. It
        lives here rather than in the caller because the query is the cheap part
        and the set comparison is where an off-by-one silently permits an
        unbounded default.
        """
        ...
