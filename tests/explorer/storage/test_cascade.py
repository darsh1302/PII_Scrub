"""Cascade deletion — task 2.4, groundwork for Property 14.

Task 4.2 owns the orchestration that also removes object-store payloads. What is
asserted here is the database half: after deleting a parent, no child row referencing
it remains, and the cascade does not reach into another workspace.

Counted with raw SQL rather than through the repositories. A repository read filters
by workspace and would report zero for a row that survived with a foreign
``workspace_id`` — so using it here would hide exactly the failure being looked for.
"""

from __future__ import annotations

import pytest

from explorer.storage.engine import Database
from explorer.storage.postgres import (
    PgChunkRepository,
    PgDocumentRepository,
    PgEmbeddingRepository,
    PgExperimentRepository,
    PgRunRepository,
    PgToolInvocationRepository,
    PgTraceEventRepository,
    PgWorkspaceRepository,
)
from tests.explorer.conftest import requires_database
from tests.explorer.storage import builders

pytestmark = requires_database


def _count(db: Database, table: str) -> int:
    # Table names are literals from this module, never input.
    return int(db.execute_scalar(f"SELECT count(*) FROM {table}"))  # noqa: S608


@pytest.fixture
def populated(db: Database, workspace_id, other_workspace_id):
    """One document with chunks and embeddings, one run with events, in each of
    two workspaces."""
    PgWorkspaceRepository(db).create(builders.workspace(workspace_id))
    PgWorkspaceRepository(db).create(builders.workspace(other_workspace_id))

    documents = PgDocumentRepository(db)
    chunks = PgChunkRepository(db)
    embeddings = PgEmbeddingRepository(db)
    experiments = PgExperimentRepository(db)
    runs = PgRunRepository(db)
    events = PgTraceEventRepository(db)
    invocations = PgToolInvocationRepository(db)

    created: dict[str, object] = {}

    for name, ws in (("mine", workspace_id), ("theirs", other_workspace_id)):
        document = builders.document(ws, sha256=f"{name[0]}" * 64)
        documents.create(document)

        chunk_records = [
            builders.chunk(ws, document.id, sequence=i, start=i * 100,
                           end=(i + 1) * 100)
            for i in range(3)
        ]
        chunks.replace_for_document(document.id, workspace_id=ws, chunks=chunk_records)
        embeddings.upsert(
            [builders.embedding(ws, c.id, document.id) for c in chunk_records]
        )

        experiment = builders.experiment(ws)
        experiments.create(experiment)
        run = builders.run(ws, experiment_id=experiment.id)
        runs.create(run)
        for sequence in range(2):
            events.append(builders.trace_event(ws, run.id, sequence=sequence))
        invocations.create(builders.tool_invocation(ws, run.id))

        created[name] = {
            "workspace_id": ws,
            "document": document,
            "experiment": experiment,
            "run": run,
        }

    return db, created


def test_deleting_a_document_removes_its_chunks_and_embeddings(populated):
    db, created = populated
    mine = created["mine"]

    assert _count(db, "chunk") == 6
    assert _count(db, "embedding") == 6

    PgDocumentRepository(db).delete(
        mine["document"].id, workspace_id=mine["workspace_id"]
    )

    # Three of each gone, and exactly three of each left — the other workspace's.
    assert _count(db, "chunk") == 3
    assert _count(db, "embedding") == 3
    assert _count(db, "document") == 1


def test_deleting_a_document_leaves_the_other_workspace_untouched(populated):
    db, created = populated
    mine, theirs = created["mine"], created["theirs"]

    PgDocumentRepository(db).delete(
        mine["document"].id, workspace_id=mine["workspace_id"]
    )

    surviving = PgChunkRepository(db).list_for_document(
        theirs["document"].id, workspace_id=theirs["workspace_id"]
    )
    assert len(surviving) == 3


def test_deleting_a_document_from_the_wrong_workspace_deletes_nothing(populated):
    db, created = populated
    mine, theirs = created["mine"], created["theirs"]

    removed = PgDocumentRepository(db).delete(
        theirs["document"].id, workspace_id=mine["workspace_id"]
    )

    assert removed is False
    assert _count(db, "document") == 2
    assert _count(db, "chunk") == 6


def test_deleting_a_run_removes_its_trace_events_and_invocations(populated):
    db, created = populated
    mine = created["mine"]

    assert _count(db, "trace_event") == 4
    assert _count(db, "tool_invocation") == 2

    PgRunRepository(db).delete(mine["run"].id, workspace_id=mine["workspace_id"])

    assert _count(db, "trace_event") == 2
    assert _count(db, "tool_invocation") == 1


def test_deleting_an_experiment_removes_its_runs_and_their_traces(populated):
    db, created = populated
    mine = created["mine"]

    PgExperimentRepository(db).delete(
        mine["experiment"].id, workspace_id=mine["workspace_id"]
    )

    assert _count(db, "run") == 1
    assert _count(db, "trace_event") == 2


def test_deleting_a_workspace_removes_everything_it_owns(populated):
    """`[R14.5]`. Rows only — payload removal is task 4.2 and Property 14."""
    db, created = populated
    mine, theirs = created["mine"], created["theirs"]

    PgWorkspaceRepository(db).delete(mine["workspace_id"])

    for table in (
        "document",
        "experiment",
        "run",
        "tool_invocation",
    ):
        assert _count(db, table) == 1, f"{table} should have only the other workspace"
    assert _count(db, "chunk") == 3
    assert _count(db, "embedding") == 3
    assert _count(db, "trace_event") == 2

    # And the survivor is genuinely readable, not merely counted.
    assert PgDocumentRepository(db).get(
        theirs["document"].id, workspace_id=theirs["workspace_id"]
    )


def test_no_orphan_rows_remain_after_a_workspace_deletion(populated):
    """A cascade that misses one edge leaves rows pointing at nothing.

    Asserted as a general property over the child tables rather than per-table, so
    a table added later without a cascade shows up here.
    """
    db, created = populated
    PgWorkspaceRepository(db).delete(created["mine"]["workspace_id"])

    orphan_checks = {
        "chunk": "SELECT count(*) FROM chunk c "
        "LEFT JOIN document d ON d.id = c.document_id WHERE d.id IS NULL",
        "embedding": "SELECT count(*) FROM embedding e "
        "LEFT JOIN chunk c ON c.id = e.chunk_id WHERE c.id IS NULL",
        "trace_event": "SELECT count(*) FROM trace_event t "
        "LEFT JOIN run r ON r.id = t.run_id WHERE r.id IS NULL",
        "tool_invocation": "SELECT count(*) FROM tool_invocation i "
        "LEFT JOIN run r ON r.id = i.run_id WHERE r.id IS NULL",
    }
    for table, statement in orphan_checks.items():
        assert int(db.execute_scalar(statement)) == 0, f"orphan rows left in {table}"
