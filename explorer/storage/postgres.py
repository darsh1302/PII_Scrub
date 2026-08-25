"""psycopg implementations of the repository protocols.

Every statement that reads or writes a workspace-scoped table carries
``workspace_id = %s`` in its ``WHERE`` clause. Not in a helper that callers may
forget, not in a session variable, not applied to the result set afterwards — in the
statement. `[R15.3]` asks for query-level filtering and `[R15.4]` asks for it to be
impossible to bypass, and a predicate you can read in the SQL is the only version of
that which survives review.

A read for a row in another workspace raises :class:`NotFound`, identical to a read
for a row that does not exist. The indistinguishability is the point: a distinct
"wrong workspace" error confirms the identifier is real.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from psycopg.types.json import Jsonb

from explorer.storage.engine import Database
from explorer.storage.protocols import NotFound
from explorer.storage.records import (
    Approval,
    Chunk,
    CompletionReason,
    Document,
    Embedding,
    Experiment,
    Membership,
    PriceTableVersion,
    PromptTemplateVersion,
    RetentionPolicy,
    Role,
    Run,
    ToolInvocation,
    TraceEvent,
    User,
    Workspace,
)


class _Base:
    """Shared connection handle. Not a repository in itself."""

    def __init__(self, database: Database) -> None:
        self._db = database

    def _one(self, statement: str, params: Sequence[Any]) -> Mapping[str, Any]:
        with self._db.connect() as conn:
            row = conn.execute(statement, params).fetchone()
        if row is None:
            raise NotFound("no such row in this workspace")
        return row

    def _all(self, statement: str, params: Sequence[Any]) -> list[Mapping[str, Any]]:
        with self._db.connect() as conn:
            return list(conn.execute(statement, params).fetchall())

    def _write(self, statement: str, params: Sequence[Any]) -> int:
        with self._db.connect() as conn:
            cursor = conn.execute(statement, params)
            conn.commit()
            return cursor.rowcount


# ---------------------------------------------------------------------------
# workspace, users, membership
# ---------------------------------------------------------------------------
class PgWorkspaceRepository(_Base):
    def create(self, workspace: Workspace) -> None:
        self._write(
            "INSERT INTO workspace (id, name, created_at) VALUES (%s, %s, %s)",
            (workspace.id, workspace.name, workspace.created_at),
        )

    def get(self, workspace_id: UUID) -> Workspace:
        row = self._one("SELECT * FROM workspace WHERE id = %s", (workspace_id,))
        return _workspace(row)

    def list_for_user(self, user_id: UUID) -> list[Workspace]:
        # Through membership, so a user sees only workspaces they belong to. This
        # is the first isolation boundary a request crosses.
        rows = self._all(
            """
            SELECT w.* FROM workspace w
            JOIN membership m ON m.workspace_id = w.id
            WHERE m.user_id = %s
            ORDER BY w.created_at
            """,
            (user_id,),
        )
        return [_workspace(r) for r in rows]

    def delete(self, workspace_id: UUID) -> None:
        """Rows cascade. Object-store payloads are the caller's responsibility.

        The database cannot reach the object store, so a complete `[R14.5]`
        deletion is two steps and Property 14 asserts both. Task 4.2 owns the
        orchestration; this is the half that is SQL.
        """
        self._write("DELETE FROM workspace WHERE id = %s", (workspace_id,))


class PgUserRepository(_Base):
    def create(self, user: User) -> None:
        self._write(
            """
            INSERT INTO app_user
                (id, email, password_verifier, created_at, disabled)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                user.id,
                user.email,
                user.password_verifier,
                user.created_at,
                user.disabled,
            ),
        )

    def get(self, user_id: UUID) -> User:
        return _user(self._one("SELECT * FROM app_user WHERE id = %s", (user_id,)))

    def find_by_email(self, email: str) -> User | None:
        # lower(email) matches the unique index, so this uses it rather than
        # scanning. Case-sensitive lookup would also let two accounts differing
        # only in case both exist, which an approval record cannot disambiguate.
        rows = self._all(
            "SELECT * FROM app_user WHERE lower(email) = lower(%s)", (email,)
        )
        return _user(rows[0]) if rows else None


class PgMembershipRepository(_Base):
    def add(self, membership: Membership) -> None:
        self._write(
            """
            INSERT INTO membership (id, workspace_id, user_id, role, created_at)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (
                membership.id,
                membership.workspace_id,
                membership.user_id,
                membership.role.value,
                membership.created_at,
            ),
        )

    def role_for(self, *, workspace_id: UUID, user_id: UUID) -> Role | None:
        rows = self._all(
            "SELECT role FROM membership WHERE workspace_id = %s AND user_id = %s",
            (workspace_id, user_id),
        )
        return Role(rows[0]["role"]) if rows else None

    def list_members(self, workspace_id: UUID) -> list[Membership]:
        rows = self._all(
            "SELECT * FROM membership WHERE workspace_id = %s ORDER BY created_at",
            (workspace_id,),
        )
        return [_membership(r) for r in rows]

    def remove(self, *, workspace_id: UUID, user_id: UUID) -> bool:
        return (
            self._write(
                "DELETE FROM membership WHERE workspace_id = %s AND user_id = %s",
                (workspace_id, user_id),
            )
            > 0
        )


# ---------------------------------------------------------------------------
# experiments and runs
# ---------------------------------------------------------------------------
class PgExperimentRepository(_Base):
    def create(self, experiment: Experiment) -> None:
        self._write(
            """
            INSERT INTO experiment
                (id, workspace_id, lab, name, purpose, configuration,
                 created_at, created_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                experiment.id,
                experiment.workspace_id,
                experiment.lab,
                experiment.name,
                experiment.purpose,
                Jsonb(experiment.configuration),
                experiment.created_at,
                experiment.created_by,
            ),
        )

    def get(self, experiment_id: UUID, *, workspace_id: UUID) -> Experiment:
        return _experiment(
            self._one(
                "SELECT * FROM experiment WHERE id = %s AND workspace_id = %s",
                (experiment_id, workspace_id),
            )
        )

    def list(
        self, *, workspace_id: UUID, lab: str | None = None, limit: int = 50
    ) -> list[Experiment]:
        if lab is None:
            rows = self._all(
                """
                SELECT * FROM experiment WHERE workspace_id = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (workspace_id, limit),
            )
        else:
            rows = self._all(
                """
                SELECT * FROM experiment WHERE workspace_id = %s AND lab = %s
                ORDER BY created_at DESC LIMIT %s
                """,
                (workspace_id, lab, limit),
            )
        return [_experiment(r) for r in rows]

    def delete(self, experiment_id: UUID, *, workspace_id: UUID) -> bool:
        return (
            self._write(
                "DELETE FROM experiment WHERE id = %s AND workspace_id = %s",
                (experiment_id, workspace_id),
            )
            > 0
        )


class PgRunRepository(_Base):
    def create(self, run: Run) -> None:
        self._write(
            """
            INSERT INTO run
                (id, workspace_id, experiment_id, status, completion_reason,
                 started_at, finished_at, prompt_template_version_id,
                 price_table_version, total_input_tokens, total_output_tokens,
                 total_cost_micros, token_counts_are_estimated, latency_ms,
                 error_detail)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                run.id,
                run.workspace_id,
                run.experiment_id,
                run.status,
                run.completion_reason.value if run.completion_reason else None,
                run.started_at,
                run.finished_at,
                run.prompt_template_version_id,
                run.price_table_version,
                run.total_input_tokens,
                run.total_output_tokens,
                run.total_cost_micros,
                run.token_counts_are_estimated,
                run.latency_ms,
                run.error_detail,
            ),
        )

    def get(self, run_id: UUID, *, workspace_id: UUID) -> Run:
        return _run(
            self._one(
                "SELECT * FROM run WHERE id = %s AND workspace_id = %s",
                (run_id, workspace_id),
            )
        )

    def finish(
        self,
        run_id: UUID,
        *,
        workspace_id: UUID,
        completion_reason: str,
        finished_at: datetime,
        latency_ms: int | None = None,
        error_detail: str | None = None,
    ) -> None:
        """Sets status to terminal and the reason together, in one statement.

        Separate updates would leave a window in which the row is terminal with no
        reason — which the ``run_terminal_requires_reason`` check would reject
        anyway, and rightly.
        """
        updated = self._write(
            """
            UPDATE run
            SET status = 'terminal',
                completion_reason = %s,
                finished_at = %s,
                latency_ms = %s,
                error_detail = %s
            WHERE id = %s AND workspace_id = %s
            """,
            (
                completion_reason,
                finished_at,
                latency_ms,
                error_detail,
                run_id,
                workspace_id,
            ),
        )
        if updated == 0:
            raise NotFound("no such run in this workspace")

    def record_usage(
        self,
        run_id: UUID,
        *,
        workspace_id: UUID,
        input_tokens: int,
        output_tokens: int,
        cost_micros: int,
        estimated: bool,
    ) -> None:
        """Accumulate usage. ``estimated`` is sticky once true.

        A run whose totals mix reported and estimated counts is estimated. Letting
        a later exact call clear the flag would present a partly-guessed number as
        a measurement `[R1.4]`.
        """
        self._write(
            """
            UPDATE run
            SET total_input_tokens = total_input_tokens + %s,
                total_output_tokens = total_output_tokens + %s,
                total_cost_micros = total_cost_micros + %s,
                token_counts_are_estimated = token_counts_are_estimated OR %s
            WHERE id = %s AND workspace_id = %s
            """,
            (input_tokens, output_tokens, cost_micros, estimated, run_id,
             workspace_id),
        )

    def list(
        self,
        *,
        workspace_id: UUID,
        experiment_id: UUID | None = None,
        limit: int = 50,
    ) -> list[Run]:
        if experiment_id is None:
            rows = self._all(
                """
                SELECT * FROM run WHERE workspace_id = %s
                ORDER BY started_at DESC LIMIT %s
                """,
                (workspace_id, limit),
            )
        else:
            rows = self._all(
                """
                SELECT * FROM run WHERE workspace_id = %s AND experiment_id = %s
                ORDER BY started_at DESC LIMIT %s
                """,
                (workspace_id, experiment_id, limit),
            )
        return [_run(r) for r in rows]

    def delete(self, run_id: UUID, *, workspace_id: UUID) -> bool:
        return (
            self._write(
                "DELETE FROM run WHERE id = %s AND workspace_id = %s",
                (run_id, workspace_id),
            )
            > 0
        )


# ---------------------------------------------------------------------------
# documents and chunks
# ---------------------------------------------------------------------------
class PgDocumentRepository(_Base):
    def create(self, document: Document) -> None:
        self._write(
            """
            INSERT INTO document
                (id, workspace_id, label, media_type, byte_size, sha256,
                 payload_ref, created_at, source_kind, page_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                document.id,
                document.workspace_id,
                document.label,
                document.media_type,
                document.byte_size,
                document.sha256,
                document.payload_ref,
                document.created_at,
                document.source_kind,
                document.page_count,
            ),
        )

    def get(self, document_id: UUID, *, workspace_id: UUID) -> Document:
        return _document(
            self._one(
                "SELECT * FROM document WHERE id = %s AND workspace_id = %s",
                (document_id, workspace_id),
            )
        )

    def find_by_sha256(self, sha256: str, *, workspace_id: UUID) -> Document | None:
        rows = self._all(
            "SELECT * FROM document WHERE workspace_id = %s AND sha256 = %s",
            (workspace_id, sha256),
        )
        return _document(rows[0]) if rows else None

    def list(self, *, workspace_id: UUID, limit: int = 50) -> list[Document]:
        rows = self._all(
            """
            SELECT * FROM document WHERE workspace_id = %s
            ORDER BY created_at DESC LIMIT %s
            """,
            (workspace_id, limit),
        )
        return [_document(r) for r in rows]

    def delete(self, document_id: UUID, *, workspace_id: UUID) -> bool:
        return (
            self._write(
                "DELETE FROM document WHERE id = %s AND workspace_id = %s",
                (document_id, workspace_id),
            )
            > 0
        )


class PgChunkRepository(_Base):
    def replace_for_document(
        self, document_id: UUID, *, workspace_id: UUID, chunks: Sequence[Chunk]
    ) -> None:
        """Delete then insert, in one transaction.

        Wholesale replacement rather than append: two strategies' chunks in this
        table for one document would give retrieval overlapping duplicates with no
        way to tell which run produced them. One transaction, so a failure does not
        leave the document with no chunks at all.
        """
        with self._db.transaction() as conn:
            conn.execute(
                "DELETE FROM chunk WHERE document_id = %s AND workspace_id = %s",
                (document_id, workspace_id),
            )
            for chunk in chunks:
                conn.execute(
                    """
                    INSERT INTO chunk
                        (id, workspace_id, document_id, sequence, start_offset,
                         end_offset, token_count, strategy, text_ref,
                         page_or_section)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """,
                    (
                        chunk.id,
                        chunk.workspace_id,
                        chunk.document_id,
                        chunk.sequence,
                        chunk.start_offset,
                        chunk.end_offset,
                        chunk.token_count,
                        chunk.strategy,
                        chunk.text_ref,
                        chunk.page_or_section,
                    ),
                )

    def list_for_document(
        self, document_id: UUID, *, workspace_id: UUID
    ) -> list[Chunk]:
        rows = self._all(
            """
            SELECT * FROM chunk WHERE document_id = %s AND workspace_id = %s
            ORDER BY sequence
            """,
            (document_id, workspace_id),
        )
        return [_chunk(r) for r in rows]

    def get(self, chunk_id: UUID, *, workspace_id: UUID) -> Chunk:
        return _chunk(
            self._one(
                "SELECT * FROM chunk WHERE id = %s AND workspace_id = %s",
                (chunk_id, workspace_id),
            )
        )

    def count_for_document(self, document_id: UUID, *, workspace_id: UUID) -> int:
        rows = self._all(
            """
            SELECT count(*) AS n FROM chunk
            WHERE document_id = %s AND workspace_id = %s
            """,
            (document_id, workspace_id),
        )
        return int(rows[0]["n"])


class PgEmbeddingRepository(_Base):
    """Row storage only. Similarity search is the vector adapter, task 9.2.

    Kept separate because search has a refusal condition — a model mismatch
    `[R4.7]` — and mixing it into a plain repository would put that decision
    somewhere nobody looks for it.
    """

    def upsert(self, records: Sequence[Embedding]) -> None:
        with self._db.transaction() as conn:
            for record in records:
                conn.execute(
                    """
                    INSERT INTO embedding
                        (id, workspace_id, chunk_id, document_id, embedding_model,
                         embedding_model_version, dimensions, vector, created_at)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (chunk_id, embedding_model, embedding_model_version)
                    DO UPDATE SET vector = EXCLUDED.vector,
                                  dimensions = EXCLUDED.dimensions,
                                  created_at = EXCLUDED.created_at
                    """,
                    (
                        record.id,
                        record.workspace_id,
                        record.chunk_id,
                        record.document_id,
                        record.embedding_model,
                        record.embedding_model_version,
                        record.dimensions,
                        list(record.vector),
                        record.created_at,
                    ),
                )

    def get(self, embedding_id: UUID, *, workspace_id: UUID) -> Embedding:
        return _embedding(
            self._one(
                "SELECT * FROM embedding WHERE id = %s AND workspace_id = %s",
                (embedding_id, workspace_id),
            )
        )

    def list_for_document(
        self, document_id: UUID, *, workspace_id: UUID
    ) -> list[Embedding]:
        rows = self._all(
            """
            SELECT * FROM embedding WHERE document_id = %s AND workspace_id = %s
            ORDER BY created_at
            """,
            (document_id, workspace_id),
        )
        return [_embedding(r) for r in rows]

    def delete_by_document(self, document_id: UUID, *, workspace_id: UUID) -> int:
        return self._write(
            "DELETE FROM embedding WHERE document_id = %s AND workspace_id = %s",
            (document_id, workspace_id),
        )

    def count(self, *, workspace_id: UUID) -> int:
        rows = self._all(
            "SELECT count(*) AS n FROM embedding WHERE workspace_id = %s",
            (workspace_id,),
        )
        return int(rows[0]["n"])


# ---------------------------------------------------------------------------
# traces, tools, approvals
# ---------------------------------------------------------------------------
class PgTraceEventRepository(_Base):
    """The inner interface. Writes are expected to arrive already redacted.

    Property 11 is asserted on the call into this repository rather than on
    rendered output, so task 5.2's middleware sits above it and a caller reaching
    here directly is exactly what that test looks for.
    """

    def append(self, event: TraceEvent) -> None:
        self._write(
            """
            INSERT INTO trace_event
                (id, workspace_id, run_id, sequence, event_type, occurred_at,
                 duration_ms, payload, redaction_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                event.id,
                event.workspace_id,
                event.run_id,
                event.sequence,
                event.event_type,
                event.occurred_at,
                event.duration_ms,
                Jsonb(event.payload),
                event.redaction_count,
            ),
        )

    def list_for_run(self, run_id: UUID, *, workspace_id: UUID) -> list[TraceEvent]:
        rows = self._all(
            """
            SELECT * FROM trace_event WHERE run_id = %s AND workspace_id = %s
            ORDER BY sequence
            """,
            (run_id, workspace_id),
        )
        return [_trace_event(r) for r in rows]

    def delete_for_run(self, run_id: UUID, *, workspace_id: UUID) -> int:
        return self._write(
            "DELETE FROM trace_event WHERE run_id = %s AND workspace_id = %s",
            (run_id, workspace_id),
        )


class PgToolInvocationRepository(_Base):
    def create(self, invocation: ToolInvocation) -> None:
        self._write(
            """
            INSERT INTO tool_invocation
                (id, workspace_id, run_id, sequence, tool_name, risk_level,
                 status, started_at, finished_at, requires_approval)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                invocation.id,
                invocation.workspace_id,
                invocation.run_id,
                invocation.sequence,
                invocation.tool_name,
                invocation.risk_level,
                invocation.status,
                invocation.started_at,
                invocation.finished_at,
                invocation.requires_approval,
            ),
        )

    def get(self, invocation_id: UUID, *, workspace_id: UUID) -> ToolInvocation:
        return _tool_invocation(
            self._one(
                "SELECT * FROM tool_invocation WHERE id = %s AND workspace_id = %s",
                (invocation_id, workspace_id),
            )
        )

    def list_for_run(
        self, run_id: UUID, *, workspace_id: UUID
    ) -> list[ToolInvocation]:
        rows = self._all(
            """
            SELECT * FROM tool_invocation
            WHERE run_id = %s AND workspace_id = %s ORDER BY sequence
            """,
            (run_id, workspace_id),
        )
        return [_tool_invocation(r) for r in rows]


class PgApprovalRepository(_Base):
    def record(self, approval: Approval) -> None:
        self._write(
            """
            INSERT INTO approval
                (id, workspace_id, tool_invocation_id, approver_user_id,
                 decision, decided_at, requested_parameters,
                 executed_parameters, note)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                approval.id,
                approval.workspace_id,
                approval.tool_invocation_id,
                approval.approver_user_id,
                approval.decision,
                approval.decided_at,
                Jsonb(approval.requested_parameters),
                Jsonb(approval.executed_parameters)
                if approval.executed_parameters is not None
                else None,
                approval.note,
            ),
        )

    def for_invocation(
        self, tool_invocation_id: UUID, *, workspace_id: UUID
    ) -> Approval | None:
        rows = self._all(
            """
            SELECT * FROM approval
            WHERE tool_invocation_id = %s AND workspace_id = %s
            """,
            (tool_invocation_id, workspace_id),
        )
        return _approval(rows[0]) if rows else None


# ---------------------------------------------------------------------------
# prompts, retention, pricing
# ---------------------------------------------------------------------------
class PgPromptTemplateRepository(_Base):
    def create_template(
        self, *, template_id: UUID, workspace_id: UUID, name: str, created_at: datetime
    ) -> None:
        self._write(
            """
            INSERT INTO prompt_template (id, workspace_id, name, created_at)
            VALUES (%s, %s, %s, %s)
            """,
            (template_id, workspace_id, name, created_at),
        )

    def add_version(self, version: PromptTemplateVersion) -> None:
        self._write(
            """
            INSERT INTO prompt_template_version
                (id, workspace_id, template_id, version, body, variables,
                 created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                version.id,
                version.workspace_id,
                version.template_id,
                version.version,
                version.body,
                list(version.variables),
                version.created_at,
            ),
        )

    def get_version(
        self, version_id: UUID, *, workspace_id: UUID
    ) -> PromptTemplateVersion:
        return _prompt_version(
            self._one(
                """
                SELECT * FROM prompt_template_version
                WHERE id = %s AND workspace_id = %s
                """,
                (version_id, workspace_id),
            )
        )

    def latest(
        self, template_id: UUID, *, workspace_id: UUID
    ) -> PromptTemplateVersion | None:
        rows = self._all(
            """
            SELECT * FROM prompt_template_version
            WHERE template_id = %s AND workspace_id = %s
            ORDER BY version DESC LIMIT 1
            """,
            (template_id, workspace_id),
        )
        return _prompt_version(rows[0]) if rows else None

    def list_versions(
        self, template_id: UUID, *, workspace_id: UUID
    ) -> list[PromptTemplateVersion]:
        rows = self._all(
            """
            SELECT * FROM prompt_template_version
            WHERE template_id = %s AND workspace_id = %s ORDER BY version
            """,
            (template_id, workspace_id),
        )
        return [_prompt_version(r) for r in rows]


class PgRetentionPolicyRepository(_Base):
    def upsert(self, policy: RetentionPolicy) -> None:
        self._write(
            """
            INSERT INTO retention_policy
                (id, workspace_id, category, retention_days, updated_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (workspace_id, category)
            DO UPDATE SET retention_days = EXCLUDED.retention_days,
                          updated_at = EXCLUDED.updated_at
            """,
            (
                policy.id,
                policy.workspace_id,
                policy.category,
                policy.retention_days,
                policy.updated_at,
            ),
        )

    def get(self, *, workspace_id: UUID, category: str) -> RetentionPolicy | None:
        rows = self._all(
            """
            SELECT * FROM retention_policy
            WHERE workspace_id = %s AND category = %s
            """,
            (workspace_id, category),
        )
        return _retention_policy(rows[0]) if rows else None

    def list_for_workspace(self, workspace_id: UUID) -> list[RetentionPolicy]:
        rows = self._all(
            "SELECT * FROM retention_policy WHERE workspace_id = %s ORDER BY category",
            (workspace_id,),
        )
        return [_retention_policy(r) for r in rows]

    def missing_categories(
        self, workspace_id: UUID, required: frozenset[str]
    ) -> set[str]:
        """Required categories with no configured period.

        Task 4.1 turns a non-empty result into a startup refusal `[R14.3]`.
        """
        configured = {p.category for p in self.list_for_workspace(workspace_id)}
        return set(required) - configured


class PgPriceTableRepository(_Base):
    def add_version(self, version: PriceTableVersion) -> None:
        self._write(
            """
            INSERT INTO price_table (version, effective_from, entries, created_at)
            VALUES (%s, %s, %s, %s)
            """,
            (
                version.version,
                version.effective_from,
                Jsonb(version.entries),
                version.created_at,
            ),
        )

    def get(self, version: str) -> PriceTableVersion:
        row = self._one("SELECT * FROM price_table WHERE version = %s", (version,))
        return PriceTableVersion(
            version=row["version"],
            effective_from=row["effective_from"],
            entries=row["entries"],
            created_at=row["created_at"],
        )

    def current(self, *, at: datetime) -> PriceTableVersion | None:
        rows = self._all(
            """
            SELECT * FROM price_table WHERE effective_from <= %s
            ORDER BY effective_from DESC LIMIT 1
            """,
            (at,),
        )
        if not rows:
            return None
        row = rows[0]
        return PriceTableVersion(
            version=row["version"],
            effective_from=row["effective_from"],
            entries=row["entries"],
            created_at=row["created_at"],
        )


# ---------------------------------------------------------------------------
# row mapping
# ---------------------------------------------------------------------------
# One function per record rather than a generic mapper. A generic one would have to
# guess how a column becomes a field, and the guess is wrong exactly where it
# matters -- an enum silently arriving as a string, a vector as a list.
def _workspace(row: Mapping[str, Any]) -> Workspace:
    return Workspace(id=row["id"], name=row["name"], created_at=row["created_at"])


def _user(row: Mapping[str, Any]) -> User:
    return User(
        id=row["id"],
        email=row["email"],
        password_verifier=row["password_verifier"],
        created_at=row["created_at"],
        disabled=row["disabled"],
    )


def _membership(row: Mapping[str, Any]) -> Membership:
    return Membership(
        id=row["id"],
        workspace_id=row["workspace_id"],
        user_id=row["user_id"],
        role=Role(row["role"]),
        created_at=row["created_at"],
    )


def _experiment(row: Mapping[str, Any]) -> Experiment:
    return Experiment(
        id=row["id"],
        workspace_id=row["workspace_id"],
        lab=row["lab"],
        name=row["name"],
        purpose=row["purpose"],
        configuration=row["configuration"],
        created_at=row["created_at"],
        created_by=row["created_by"],
    )


def _run(row: Mapping[str, Any]) -> Run:
    reason = row["completion_reason"]
    return Run(
        id=row["id"],
        workspace_id=row["workspace_id"],
        experiment_id=row["experiment_id"],
        status=row["status"],
        completion_reason=CompletionReason(reason) if reason else None,
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        prompt_template_version_id=row["prompt_template_version_id"],
        price_table_version=row["price_table_version"],
        total_input_tokens=row["total_input_tokens"],
        total_output_tokens=row["total_output_tokens"],
        total_cost_micros=row["total_cost_micros"],
        token_counts_are_estimated=row["token_counts_are_estimated"],
        latency_ms=row["latency_ms"],
        error_detail=row["error_detail"],
    )


def _document(row: Mapping[str, Any]) -> Document:
    return Document(
        id=row["id"],
        workspace_id=row["workspace_id"],
        label=row["label"],
        media_type=row["media_type"],
        byte_size=row["byte_size"],
        sha256=row["sha256"],
        payload_ref=row["payload_ref"],
        created_at=row["created_at"],
        source_kind=row["source_kind"],
        page_count=row["page_count"],
    )


def _chunk(row: Mapping[str, Any]) -> Chunk:
    return Chunk(
        id=row["id"],
        workspace_id=row["workspace_id"],
        document_id=row["document_id"],
        sequence=row["sequence"],
        start_offset=row["start_offset"],
        end_offset=row["end_offset"],
        token_count=row["token_count"],
        strategy=row["strategy"],
        text_ref=row["text_ref"],
        page_or_section=row["page_or_section"],
    )


def _embedding(row: Mapping[str, Any]) -> Embedding:
    return Embedding(
        id=row["id"],
        workspace_id=row["workspace_id"],
        chunk_id=row["chunk_id"],
        document_id=row["document_id"],
        embedding_model=row["embedding_model"],
        embedding_model_version=row["embedding_model_version"],
        dimensions=row["dimensions"],
        vector=tuple(row["vector"]),
        created_at=row["created_at"],
    )


def _trace_event(row: Mapping[str, Any]) -> TraceEvent:
    return TraceEvent(
        id=row["id"],
        workspace_id=row["workspace_id"],
        run_id=row["run_id"],
        sequence=row["sequence"],
        event_type=row["event_type"],
        occurred_at=row["occurred_at"],
        duration_ms=row["duration_ms"],
        payload=row["payload"],
        redaction_count=row["redaction_count"],
    )


def _tool_invocation(row: Mapping[str, Any]) -> ToolInvocation:
    return ToolInvocation(
        id=row["id"],
        workspace_id=row["workspace_id"],
        run_id=row["run_id"],
        sequence=row["sequence"],
        tool_name=row["tool_name"],
        risk_level=row["risk_level"],
        status=row["status"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        requires_approval=row["requires_approval"],
    )


def _approval(row: Mapping[str, Any]) -> Approval:
    return Approval(
        id=row["id"],
        workspace_id=row["workspace_id"],
        tool_invocation_id=row["tool_invocation_id"],
        approver_user_id=row["approver_user_id"],
        decision=row["decision"],
        decided_at=row["decided_at"],
        requested_parameters=row["requested_parameters"],
        executed_parameters=row["executed_parameters"],
        note=row["note"],
    )


def _prompt_version(row: Mapping[str, Any]) -> PromptTemplateVersion:
    return PromptTemplateVersion(
        id=row["id"],
        workspace_id=row["workspace_id"],
        template_id=row["template_id"],
        version=row["version"],
        body=row["body"],
        variables=tuple(row["variables"]),
        created_at=row["created_at"],
    )


def _retention_policy(row: Mapping[str, Any]) -> RetentionPolicy:
    return RetentionPolicy(
        id=row["id"],
        workspace_id=row["workspace_id"],
        category=row["category"],
        retention_days=row["retention_days"],
        updated_at=row["updated_at"],
    )
