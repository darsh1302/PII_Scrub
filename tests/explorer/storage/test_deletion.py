"""Cascade deletion across both stores — tasks 4.2, 4.4, 4.6; Properties 14 and 15.

Against a real database and a real filesystem object store, because the thing being
asserted is that two stores end up consistent. A mocked store would assert that the
mock was called.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from explorer.observability.audit_chain import AuditChain, AuditIntegrityError
from explorer.storage.deletion import Deleter
from explorer.storage.engine import Database
from explorer.storage.object_store import (
    FilesystemObjectStore,
    payload_key,
    workspace_prefix,
)
from explorer.storage.postgres import (
    PgChunkRepository,
    PgDocumentRepository,
    PgEmbeddingRepository,
    PgRunRepository,
    PgToolInvocationRepository,
    PgTraceEventRepository,
    PgWorkspaceRepository,
)
from explorer.storage.protocols import ObjectStoreError
from tests.explorer.conftest import requires_database
from tests.explorer.storage import builders

pytestmark = requires_database


@pytest.fixture
def store(tmp_path: Path) -> FilesystemObjectStore:
    return FilesystemObjectStore(tmp_path / "objects")


@pytest.fixture
def audit(tmp_path: Path) -> AuditChain:
    return AuditChain(tmp_path / "audit")


@pytest.fixture
def scene(db: Database, store, audit, workspace_id, other_workspace_id):
    """A document with chunks, embeddings and payloads, in each of two workspaces."""
    PgWorkspaceRepository(db).create(builders.workspace(workspace_id, name="mine"))
    PgWorkspaceRepository(db).create(
        builders.workspace(other_workspace_id, name="theirs")
    )

    documents = PgDocumentRepository(db)
    chunks = PgChunkRepository(db)
    embeddings = PgEmbeddingRepository(db)

    created = {}
    for name, ws, digest in (
        ("mine", workspace_id, "a" * 64),
        ("theirs", other_workspace_id, "b" * 64),
    ):
        document = builders.document(ws, sha256=digest)
        documents.create(document)
        store.put(document.payload_ref, b"the original bytes", content_type="text/plain")

        chunk_records = []
        for index in range(2):
            chunk = builders.chunk(
                ws, document.id, sequence=index, start=index * 50, end=(index + 1) * 50
            )
            text_ref = payload_key(
                workspace_id=ws, kind="chunk", object_id=chunk.id
            )
            chunk = type(chunk)(**{**vars(chunk), "text_ref": text_ref})
            store.put(text_ref, b"chunk text", content_type="text/plain")
            chunk_records.append(chunk)

        chunks.replace_for_document(document.id, workspace_id=ws, chunks=chunk_records)
        embeddings.upsert(
            [builders.embedding(ws, c.id, document.id) for c in chunk_records]
        )
        created[name] = {"workspace_id": ws, "document": document, "chunks": chunk_records}

    deleter = Deleter(
        documents=documents,
        chunks=chunks,
        embeddings=embeddings,
        runs=PgRunRepository(db),
        workspaces=PgWorkspaceRepository(db),
        object_store=store,
        audit=audit,
    )
    return {"db": db, "store": store, "audit": audit, "deleter": deleter, **created}


def _count(db: Database, table: str) -> int:
    return int(db.execute_scalar(f"SELECT count(*) FROM {table}"))  # noqa: S608


# ---------------------------------------------------------------------------
# document deletion
# ---------------------------------------------------------------------------
def test_deleting_a_document_removes_rows_and_payloads(scene):
    """Property 14, both halves.

    The database cascade cannot reach the object store, so a test that only counted rows
    would pass while leaving content on disk — which is the failure `[R14.5]` is about.
    """
    mine = scene["mine"]
    receipt = scene["deleter"].delete_document(
        mine["document"].id, workspace_id=mine["workspace_id"], reason="operator"
    )

    assert receipt.complete is True
    # One document + two chunks + two embeddings.
    assert receipt.rows_deleted == 5
    # One original + two chunk texts.
    assert receipt.payloads_deleted == 3

    assert _count(scene["db"], "chunk") == 2  # the other workspace's
    assert _count(scene["db"], "embedding") == 2
    assert not scene["store"].exists(mine["document"].payload_ref)
    for chunk in mine["chunks"]:
        assert not scene["store"].exists(chunk.text_ref)


def test_deleting_a_document_leaves_the_other_workspaces_payloads(scene):
    mine, theirs = scene["mine"], scene["theirs"]
    scene["deleter"].delete_document(
        mine["document"].id, workspace_id=mine["workspace_id"], reason="operator"
    )

    assert scene["store"].exists(theirs["document"].payload_ref)
    assert len(list(scene["store"].iter_keys(workspace_prefix(theirs["workspace_id"])))) == 3


def test_deleting_the_same_document_twice_is_a_no_op(scene):
    """Idempotent, because the sweeper and a manual deletion can race.

    Without this the sweeper raises on a document someone removed from the UI a moment
    earlier, and a scheduled job that throws is a scheduled job someone disables.
    """
    mine = scene["mine"]
    first = scene["deleter"].delete_document(
        mine["document"].id, workspace_id=mine["workspace_id"], reason="operator"
    )
    second = scene["deleter"].delete_document(
        mine["document"].id, workspace_id=mine["workspace_id"], reason="retention"
    )

    assert first.complete and second.complete
    assert second.rows_deleted == 0


def test_a_cross_workspace_deletion_removes_nothing(scene):
    mine, theirs = scene["mine"], scene["theirs"]
    receipt = scene["deleter"].delete_document(
        theirs["document"].id, workspace_id=mine["workspace_id"], reason="operator"
    )

    assert receipt.rows_deleted == 0
    assert scene["store"].exists(theirs["document"].payload_ref)
    assert _count(scene["db"], "document") == 2


def test_rows_are_kept_when_a_payload_cannot_be_removed(scene, monkeypatch):
    """The ordering decision, asserted.

    Payloads go first. If that fails, the rows stay — leaving a row pointing at a
    missing payload, which is visible and recoverable. The alternative ordering leaves
    bytes on disk with nothing referencing them and no workspace to attribute them to,
    which is content surviving its own deletion.
    """
    mine = scene["mine"]

    def refuse(_key):
        raise ObjectStoreError("permission denied")

    monkeypatch.setattr(scene["store"], "delete", refuse)

    receipt = scene["deleter"].delete_document(
        mine["document"].id, workspace_id=mine["workspace_id"], reason="operator"
    )

    assert receipt.complete is False
    assert receipt.rows_deleted == 0
    assert any("payload" in f for f in receipt.failures)
    # The row survives, so re-running the deletion can finish the job.
    assert PgDocumentRepository(scene["db"]).get(
        mine["document"].id, workspace_id=mine["workspace_id"]
    )


# ---------------------------------------------------------------------------
# run and workspace deletion
# ---------------------------------------------------------------------------
def test_deleting_a_run_removes_its_traces_and_invocations(scene):
    db = scene["db"]
    workspace_id = scene["mine"]["workspace_id"]

    runs = PgRunRepository(db)
    run = builders.run(workspace_id)
    runs.create(run)
    PgTraceEventRepository(db).append(builders.trace_event(workspace_id, run.id))
    PgToolInvocationRepository(db).create(
        builders.tool_invocation(workspace_id, run.id)
    )

    receipt = scene["deleter"].delete_run(
        run.id, workspace_id=workspace_id, reason="operator"
    )

    assert receipt.complete is True
    assert _count(db, "trace_event") == 0
    assert _count(db, "tool_invocation") == 0


def test_deleting_a_workspace_removes_everything_it_owns(scene):
    """`[R14.5]`, both stores."""
    mine, theirs = scene["mine"], scene["theirs"]

    receipt = scene["deleter"].delete_workspace(
        mine["workspace_id"], reason="tenant offboarding"
    )

    assert receipt.complete is True
    assert receipt.payloads_deleted == 3
    assert list(scene["store"].iter_keys(workspace_prefix(mine["workspace_id"]))) == []
    assert _count(scene["db"], "document") == 1
    assert scene["store"].exists(theirs["document"].payload_ref)


# ---------------------------------------------------------------------------
# the audit record
# ---------------------------------------------------------------------------
def test_a_deletion_writes_an_audit_record(scene):
    mine = scene["mine"]
    receipt = scene["deleter"].delete_document(
        mine["document"].id,
        workspace_id=mine["workspace_id"],
        reason="operator",
        actor_user_id=uuid4(),
    )

    records = scene["audit"].records_of_type("deletion")
    assert len(records) == 1
    assert records[0]["record_hash"] == receipt.audit_hash
    assert records[0]["subject"] == "document"
    assert records[0]["rows_deleted"] == 5
    assert records[0]["reason"] == "operator"


def test_the_audit_record_survives_the_data_it_describes(scene):
    """Property 15, `[R14.6]`.

    The reason audit is a hash-chained file rather than a table: it is not foreign-keyed
    to the deleted rows, so nothing cascades into it. Asserted after deleting the whole
    workspace, which is the widest cascade there is.
    """
    mine = scene["mine"]
    document_id = mine["document"].id

    scene["deleter"].delete_document(
        document_id, workspace_id=mine["workspace_id"], reason="operator"
    )
    scene["deleter"].delete_workspace(mine["workspace_id"], reason="offboarding")

    records = scene["audit"].records_of_type("deletion")
    subjects = {r["subject_id"] for r in records}

    assert str(document_id) in subjects
    assert _count(scene["db"], "document") == 1  # only the other workspace remains
    ok, bad = scene["audit"].verify_chain()
    assert ok, f"chain broken at {bad}"


def test_an_incomplete_deletion_is_still_audited(scene, monkeypatch):
    """"We tried and got halfway" is exactly what an operator needs to know.

    Writing a record only on success would leave the one case that requires
    intervention as the one case with no evidence.
    """
    mine = scene["mine"]
    monkeypatch.setattr(
        scene["store"],
        "delete",
        lambda _key: (_ for _ in ()).throw(ObjectStoreError("disk full")),
    )

    receipt = scene["deleter"].delete_document(
        mine["document"].id, workspace_id=mine["workspace_id"], reason="retention"
    )

    records = scene["audit"].records_of_type("deletion")
    assert len(records) == 1
    assert records[0]["complete"] is False
    assert records[0]["failure_count"] >= 1
    assert receipt.audit_hash is not None


def test_the_audit_record_carries_no_document_label(scene):
    """The tempting and wrong field.

    "Deleted 2026-terminations.pdf" is more useful to read and is content, in the one
    file designed to outlive every retention policy. Identifiers and counts only.
    """
    mine = scene["mine"]
    scene["deleter"].delete_document(
        mine["document"].id, workspace_id=mine["workspace_id"], reason="operator"
    )

    rendered = str(scene["audit"].records_of_type("deletion"))
    assert mine["document"].label not in rendered
    assert mine["document"].sha256 not in rendered


def test_the_chain_detects_a_tampered_record(scene, tmp_path):
    """Tamper evidence, which is what this buys — not tamper prevention."""
    mine = scene["mine"]
    scene["deleter"].delete_document(
        mine["document"].id, workspace_id=mine["workspace_id"], reason="operator"
    )

    files = sorted((tmp_path / "audit").glob("explorer-audit-*.jsonl"))
    assert files
    content = files[0].read_text(encoding="utf-8")
    files[0].write_text(content.replace('"rows_deleted":5', '"rows_deleted":0'),
                        encoding="utf-8")

    ok, bad = scene["audit"].verify_chain()
    assert ok is False
    assert bad is not None
