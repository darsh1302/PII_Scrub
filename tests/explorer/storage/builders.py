"""Record builders for storage tests.

Every builder takes ``workspace_id`` and nothing else is required. Defaults are
valid but uninteresting, so a test states only the field it is about — which makes
the assertion readable and means a test that cares about ``completion_reason`` is
not also silently asserting a token count.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID, uuid4

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

NOW = datetime(2026, 8, 24, 12, 0, 0, tzinfo=UTC)


def workspace(workspace_id: UUID, *, name: str = "Test workspace") -> Workspace:
    return Workspace(id=workspace_id, name=name, created_at=NOW)


def user(*, email: str = "a@example.test", disabled: bool = False) -> User:
    return User(
        id=uuid4(),
        email=email,
        # A fabricated verifier string. Not a hash of anything, and never compared
        # by these tests — task 3.1 owns the KDF.
        password_verifier="argon2id$v=19$m=65536,t=3,p=4$fake",
        created_at=NOW,
        disabled=disabled,
    )


def membership(
    workspace_id: UUID, user_id: UUID, *, role: Role = Role.AUTHOR
) -> Membership:
    return Membership(
        id=uuid4(),
        workspace_id=workspace_id,
        user_id=user_id,
        role=role,
        created_at=NOW,
    )


def experiment(
    workspace_id: UUID,
    *,
    lab: str = "prompt",
    name: str = "baseline",
    experiment_id: UUID | None = None,
) -> Experiment:
    return Experiment(
        id=experiment_id or uuid4(),
        workspace_id=workspace_id,
        lab=lab,
        name=name,
        purpose="establish a baseline before changing the system prompt",
        configuration={"temperature": 0.0, "model": "gpt-4o"},
        created_at=NOW,
    )


def run(
    workspace_id: UUID,
    *,
    experiment_id: UUID | None = None,
    status: str = "running",
    completion_reason: CompletionReason | None = None,
    run_id: UUID | None = None,
) -> Run:
    return Run(
        id=run_id or uuid4(),
        workspace_id=workspace_id,
        experiment_id=experiment_id,
        status=status,
        completion_reason=completion_reason,
        started_at=NOW,
        finished_at=NOW if status == "terminal" else None,
    )


def document(
    workspace_id: UUID,
    *,
    label: str = "handbook.txt",
    sha256: str = "a" * 64,
    document_id: UUID | None = None,
) -> Document:
    identifier = document_id or uuid4()
    return Document(
        id=identifier,
        workspace_id=workspace_id,
        label=label,
        media_type="text/plain",
        byte_size=1024,
        sha256=sha256,
        payload_ref=f"{workspace_id}/original/{identifier}",
        created_at=NOW,
    )


def chunk(
    workspace_id: UUID,
    document_id: UUID,
    *,
    sequence: int = 0,
    start: int = 0,
    end: int = 100,
    chunk_id: UUID | None = None,
) -> Chunk:
    return Chunk(
        id=chunk_id or uuid4(),
        workspace_id=workspace_id,
        document_id=document_id,
        sequence=sequence,
        start_offset=start,
        end_offset=end,
        token_count=25,
        strategy="fixed",
    )


def embedding(
    workspace_id: UUID,
    chunk_id: UUID,
    document_id: UUID,
    *,
    model: str = "text-embedding-3-small",
    model_version: str = "1",
    vector: tuple[float, ...] = (0.1, 0.2, 0.3),
) -> Embedding:
    return Embedding(
        id=uuid4(),
        workspace_id=workspace_id,
        chunk_id=chunk_id,
        document_id=document_id,
        embedding_model=model,
        embedding_model_version=model_version,
        dimensions=len(vector),
        vector=vector,
        created_at=NOW,
    )


def trace_event(
    workspace_id: UUID,
    run_id: UUID,
    *,
    sequence: int = 0,
    event_type: str = "model_call",
    redaction_count: int = 0,
) -> TraceEvent:
    return TraceEvent(
        id=uuid4(),
        workspace_id=workspace_id,
        run_id=run_id,
        sequence=sequence,
        event_type=event_type,
        occurred_at=NOW,
        duration_ms=42,
        payload={"model": "gpt-4o", "prompt_tokens": 100},
        redaction_count=redaction_count,
    )


def tool_invocation(
    workspace_id: UUID,
    run_id: UUID,
    *,
    sequence: int = 0,
    tool_name: str = "pii_scrub",
    invocation_id: UUID | None = None,
    requires_approval: bool = False,
) -> ToolInvocation:
    return ToolInvocation(
        id=invocation_id or uuid4(),
        workspace_id=workspace_id,
        run_id=run_id,
        sequence=sequence,
        tool_name=tool_name,
        risk_level="medium",
        status="succeeded",
        started_at=NOW,
        finished_at=NOW,
        requires_approval=requires_approval,
    )


def approval(
    workspace_id: UUID,
    tool_invocation_id: UUID,
    approver_user_id: UUID,
    *,
    decision: str = "approved",
    executed: dict[str, object] | None = None,
) -> Approval:
    requested: dict[str, object] = {"destination": "INTERNAL_SIEM"}
    return Approval(
        id=uuid4(),
        workspace_id=workspace_id,
        tool_invocation_id=tool_invocation_id,
        approver_user_id=approver_user_id,
        decision=decision,
        decided_at=NOW,
        requested_parameters=requested,
        executed_parameters=requested if executed is None else executed,
    )


def prompt_version(
    workspace_id: UUID,
    template_id: UUID,
    *,
    version: int = 1,
    version_id: UUID | None = None,
) -> PromptTemplateVersion:
    return PromptTemplateVersion(
        id=version_id or uuid4(),
        workspace_id=workspace_id,
        template_id=template_id,
        version=version,
        body="Answer using only the provided context.\n\n{context}",
        variables=("context",),
        created_at=NOW,
    )


def retention_policy(
    workspace_id: UUID, *, category: str = "document", days: int = 30
) -> RetentionPolicy:
    return RetentionPolicy(
        id=uuid4(),
        workspace_id=workspace_id,
        category=category,
        retention_days=days,
        updated_at=NOW,
    )


def price_table(*, version: str = "2026-08-01") -> PriceTableVersion:
    return PriceTableVersion(
        version=version,
        effective_from=NOW,
        entries={"gpt-4o": {"input_per_mtok": 2.50, "output_per_mtok": 10.00}},
        created_at=NOW,
    )
