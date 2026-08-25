"""Cascade deletion across both stores — task 4.2, Property 14, `[R14.5]`.

The database cascade removes rows. It cannot remove object-store payloads, because it
has no reach into the object store — so a complete deletion is two steps, and the
interesting question is what happens between them.

Order: payloads first, then rows
--------------------------------

Deliberate, and the opposite of what feels natural.

Deleting rows first and then failing on the payload leaves an orphaned object: bytes on
disk with nothing referencing them, no workspace to attribute them to, and no way to
find them except by walking the store. That is content surviving its own deletion,
which is the failure `[R14.5]` exists to prevent.

Deleting payloads first and then failing on the rows leaves a row pointing at a missing
payload. That is visible — a fetch returns :class:`ObjectStoreError` — attributable, and
re-running the deletion fixes it. A dangling reference is a bug you can find; an orphan
payload is content you cannot.

So the residual failure mode is chosen rather than accepted, and it is the recoverable
one.

The audit record is written last, and always
--------------------------------------------

Last, because a record claiming a deletion that then failed is worse than no record.
Always, including on partial failure — `[R14.6]` wants evidence of what happened, and
"we tried to delete this and got halfway" is exactly the thing an operator needs to
know. The record carries counts and identifiers, never content, and it lives in the
hash-chained file rather than a table so it survives the rows it describes.

The writer arrives as :class:`~explorer.storage.protocols.AuditWriter` rather than as a
concrete ``AuditChain``. Rule D8 makes storage the bottom layer, and the first draft of
this module imported ``explorer.observability`` directly — which would have run
perfectly and meant a change to trace-event handling could break document deletion.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import UUID

from explorer.storage.object_store import workspace_prefix
from explorer.storage.protocols import AuditWriter, NotFound, ObjectStoreError

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class DeletionReceipt:
    """What a deletion actually removed.

    Returned rather than logged, so a caller — the retention sweeper, an API handler,
    a test — can assert on it. ``complete`` being false is not an exception: the audit
    record is written either way and the caller decides whether to retry.
    """

    subject: str
    subject_id: UUID
    workspace_id: UUID
    rows_deleted: int = 0
    payloads_deleted: int = 0
    complete: bool = True
    failures: tuple[str, ...] = field(default_factory=tuple)
    audit_hash: str | None = None


class Deleter:
    """Cascade deletion, coordinating the database and the object store.

    Takes repositories and a store rather than constructing them, so a test can drive
    it against a filesystem store in ``tmp_path`` and assert both halves happened.
    """

    def __init__(
        self,
        *,
        documents,
        chunks,
        embeddings,
        runs,
        workspaces,
        object_store,
        audit: AuditWriter,
    ) -> None:
        self._documents = documents
        self._chunks = chunks
        self._embeddings = embeddings
        self._runs = runs
        self._workspaces = workspaces
        self._store = object_store
        self._audit = audit

    # -----------------------------------------------------------------
    # document
    # -----------------------------------------------------------------
    def delete_document(
        self,
        document_id: UUID,
        *,
        workspace_id: UUID,
        reason: str,
        actor_user_id: UUID | None = None,
    ) -> DeletionReceipt:
        """Remove a document, its chunks, its embeddings and its payloads.

        Chunks and embeddings are counted before deletion, not after. The database
        cascade removes them when the document row goes, so counting afterwards would
        report zero for a cascade that worked perfectly.
        """
        failures: list[str] = []

        try:
            document = self._documents.get(document_id, workspace_id=workspace_id)
        except NotFound:
            # Idempotent. The sweeper and a manual deletion can race, and a second
            # attempt should be a no-op rather than an error — otherwise the sweeper
            # raises on a document someone deleted from the UI a moment earlier.
            return self._record(
                DeletionReceipt(
                    subject="document",
                    subject_id=document_id,
                    workspace_id=workspace_id,
                    rows_deleted=0,
                    complete=True,
                ),
                reason=reason,
                actor_user_id=actor_user_id,
                already_absent=True,
            )

        chunk_count = self._chunks.count_for_document(
            document_id, workspace_id=workspace_id
        )
        embedding_rows = self._embeddings.list_for_document(
            document_id, workspace_id=workspace_id
        )

        # Payloads first — see the module docstring on ordering.
        payload_keys = [document.payload_ref]
        payload_keys.extend(
            chunk.text_ref
            for chunk in self._chunks.list_for_document(
                document_id, workspace_id=workspace_id
            )
            if chunk.text_ref
        )

        payloads_deleted = 0
        for key in payload_keys:
            try:
                if self._store.delete(key):
                    payloads_deleted += 1
            except ObjectStoreError as exc:
                failures.append(f"payload {key}: {exc}")

        rows_deleted = 0
        if not failures:
            if self._documents.delete(document_id, workspace_id=workspace_id):
                # The document row plus everything the cascade took with it.
                rows_deleted = 1 + chunk_count + len(embedding_rows)
        else:
            failures.append(
                "rows left in place because a payload could not be removed — a row "
                "pointing at a missing payload is visible and recoverable, an orphan "
                "payload is not"
            )

        return self._record(
            DeletionReceipt(
                subject="document",
                subject_id=document_id,
                workspace_id=workspace_id,
                rows_deleted=rows_deleted,
                payloads_deleted=payloads_deleted,
                complete=not failures,
                failures=tuple(failures),
            ),
            reason=reason,
            actor_user_id=actor_user_id,
        )

    # -----------------------------------------------------------------
    # run
    # -----------------------------------------------------------------
    def delete_run(
        self,
        run_id: UUID,
        *,
        workspace_id: UUID,
        reason: str,
        actor_user_id: UUID | None = None,
    ) -> DeletionReceipt:
        """Remove a run, its trace events, tool invocations and approvals.

        All rows, no payloads — a run holds no content in the object store. Kept as a
        separate method rather than folded into a generic one because the cascade
        differs and a generic deleter would have to branch anyway.
        """
        removed = self._runs.delete(run_id, workspace_id=workspace_id)

        return self._record(
            DeletionReceipt(
                subject="run",
                subject_id=run_id,
                workspace_id=workspace_id,
                rows_deleted=1 if removed else 0,
                complete=True,
            ),
            reason=reason,
            actor_user_id=actor_user_id,
            already_absent=not removed,
        )

    # -----------------------------------------------------------------
    # workspace
    # -----------------------------------------------------------------
    def delete_workspace(
        self,
        workspace_id: UUID,
        *,
        reason: str,
        actor_user_id: UUID | None = None,
    ) -> DeletionReceipt:
        """Remove a workspace and everything it owns `[R14.5]`.

        The whole object-store prefix goes in one operation rather than key by key. A
        per-key loop that failed midway would leave a partially emptied workspace with
        no record of how far it got, and the prefix is the only handle on "everything
        this tenant owned".
        """
        failures: list[str] = []
        payloads_deleted = 0

        try:
            payloads_deleted = self._store.delete_prefix(
                workspace_prefix(workspace_id)
            )
        except ObjectStoreError as exc:
            failures.append(f"object store prefix: {exc}")

        rows_deleted = 0
        if not failures:
            self._workspaces.delete(workspace_id)
            rows_deleted = 1
        else:
            failures.append("workspace rows left in place; payloads not fully removed")

        return self._record(
            DeletionReceipt(
                subject="workspace",
                subject_id=workspace_id,
                workspace_id=workspace_id,
                rows_deleted=rows_deleted,
                payloads_deleted=payloads_deleted,
                complete=not failures,
                failures=tuple(failures),
            ),
            reason=reason,
            actor_user_id=actor_user_id,
        )

    # -----------------------------------------------------------------
    # audit
    # -----------------------------------------------------------------
    def _record(
        self,
        receipt: DeletionReceipt,
        *,
        reason: str,
        actor_user_id: UUID | None,
        already_absent: bool = False,
    ) -> DeletionReceipt:
        """Write the audit record and return the receipt carrying its hash.

        Identifiers and counts only. The field names are checked against the audit
        chain's forbidden set on write, so a future change that started recording, say,
        a document label would fail rather than quietly put content into the one file
        designed to outlive every retention policy.

        A label would be tempting and wrong: "deleted 2026-terminations.pdf" is more
        useful to read and is content.
        """
        record = {
            "event": "deletion",
            "subject": receipt.subject,
            "subject_id": str(receipt.subject_id),
            "workspace_id": str(receipt.workspace_id),
            "reason": reason,
            "actor_user_id": str(actor_user_id) if actor_user_id else None,
            "rows_deleted": receipt.rows_deleted,
            "payloads_deleted": receipt.payloads_deleted,
            "complete": receipt.complete,
            "already_absent": already_absent,
            "failure_count": len(receipt.failures),
            "deleted_at": datetime.now(UTC).isoformat(),
        }

        audit_hash = self._audit.append(record)

        if not receipt.complete:
            log.error(
                "incomplete deletion of %s %s: %s",
                receipt.subject,
                receipt.subject_id,
                "; ".join(receipt.failures),
            )

        return DeletionReceipt(
            subject=receipt.subject,
            subject_id=receipt.subject_id,
            workspace_id=receipt.workspace_id,
            rows_deleted=receipt.rows_deleted,
            payloads_deleted=receipt.payloads_deleted,
            complete=receipt.complete,
            failures=receipt.failures,
            audit_hash=audit_hash,
        )
