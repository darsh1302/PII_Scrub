"""The composite foreign keys, verified by trying to violate them.

These are the tests that justify the redundant ``UNIQUE (workspace_id, id)`` index
on every parent table. Each one attempts an insert that a plain single-column
reference would happily accept, and asserts the database refuses it.

Why this matters more than it looks
-----------------------------------

Every read path filters on ``workspace_id``, so a row whose ``workspace_id``
disagrees with its parent's is invisible to both workspaces — harmless, on the face
of it.

Embeddings are where it stops being harmless. A vector search filters
``embedding.workspace_id = :caller`` and scores whatever matches. An embedding row
carrying the caller's ``workspace_id`` but another workspace's ``document_id`` would
be scored, returned, and its source text fetched for display. One mistake in one
caller, and a cross-workspace disclosure.

Filtering correctly at every call site forever is not a control. A constraint is.
This is the structural half of Property 10, and it is why the design's
single-column references were not good enough.
"""

from __future__ import annotations

import psycopg
import pytest

from explorer.storage.engine import Database
from explorer.storage.postgres import (
    PgChunkRepository,
    PgDocumentRepository,
    PgEmbeddingRepository,
    PgExperimentRepository,
    PgRunRepository,
    PgToolInvocationRepository,
    PgWorkspaceRepository,
)
from tests.explorer.conftest import requires_database
from tests.explorer.storage import builders

pytestmark = requires_database


@pytest.fixture
def two_workspaces(db: Database, workspace_id, other_workspace_id):
    repository = PgWorkspaceRepository(db)
    repository.create(builders.workspace(workspace_id, name="mine"))
    repository.create(builders.workspace(other_workspace_id, name="theirs"))
    return db


def test_a_chunk_cannot_point_at_another_workspaces_document(
    two_workspaces, workspace_id, other_workspace_id
):
    documents = PgDocumentRepository(two_workspaces)
    chunks = PgChunkRepository(two_workspaces)

    theirs = builders.document(other_workspace_id)
    documents.create(theirs)

    # workspace_id says mine, document_id is theirs. A plain
    # `REFERENCES document(id)` would accept this row.
    smuggled = builders.chunk(workspace_id, theirs.id)

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        chunks.replace_for_document(
            theirs.id, workspace_id=workspace_id, chunks=[smuggled]
        )


def test_an_embedding_cannot_point_at_another_workspaces_chunk(
    two_workspaces, workspace_id, other_workspace_id
):
    """The one that would actually leak content through vector search."""
    documents = PgDocumentRepository(two_workspaces)
    chunks = PgChunkRepository(two_workspaces)
    embeddings = PgEmbeddingRepository(two_workspaces)

    theirs = builders.document(other_workspace_id)
    documents.create(theirs)
    their_chunk = builders.chunk(other_workspace_id, theirs.id)
    chunks.replace_for_document(
        theirs.id, workspace_id=other_workspace_id, chunks=[their_chunk]
    )

    smuggled = builders.embedding(workspace_id, their_chunk.id, theirs.id)

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        embeddings.upsert([smuggled])


def test_an_embedding_cannot_disagree_with_its_own_chunk_about_the_document(
    two_workspaces, workspace_id, other_workspace_id
):
    """``embedding.document_id`` is denormalized; the constraint keeps it honest.

    Denormalizing it lets ``delete_by_document`` be one statement with the
    workspace predicate in it. Without the composite reference, that convenience
    would create a column free to disagree with the chunk it belongs to.
    """
    documents = PgDocumentRepository(two_workspaces)
    chunks = PgChunkRepository(two_workspaces)
    embeddings = PgEmbeddingRepository(two_workspaces)

    mine = builders.document(workspace_id, sha256="c" * 64)
    documents.create(mine)
    my_chunk = builders.chunk(workspace_id, mine.id)
    chunks.replace_for_document(mine.id, workspace_id=workspace_id, chunks=[my_chunk])

    theirs = builders.document(other_workspace_id, sha256="d" * 64)
    documents.create(theirs)

    # Right workspace, right chunk, but a document belonging to someone else.
    inconsistent = builders.embedding(workspace_id, my_chunk.id, theirs.id)

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        embeddings.upsert([inconsistent])


def test_a_run_cannot_belong_to_another_workspaces_experiment(
    two_workspaces, workspace_id, other_workspace_id
):
    experiments = PgExperimentRepository(two_workspaces)
    runs = PgRunRepository(two_workspaces)

    theirs = builders.experiment(other_workspace_id)
    experiments.create(theirs)

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        runs.create(builders.run(workspace_id, experiment_id=theirs.id))


def test_a_run_with_no_experiment_is_still_allowed(two_workspaces, workspace_id):
    """MATCH SIMPLE skips the check when a referencing column is NULL.

    Worth asserting: a composite key that also forbade unattached runs would break
    every ad-hoc execution, and the fix someone would reach for is dropping the
    constraint.
    """
    runs = PgRunRepository(two_workspaces)
    run = builders.run(workspace_id, experiment_id=None)
    runs.create(run)

    assert runs.get(run.id, workspace_id=workspace_id).experiment_id is None


def test_a_trace_event_cannot_attach_to_another_workspaces_run(
    two_workspaces, workspace_id, other_workspace_id
):
    from explorer.storage.postgres import PgTraceEventRepository

    runs = PgRunRepository(two_workspaces)
    events = PgTraceEventRepository(two_workspaces)

    their_run = builders.run(other_workspace_id)
    runs.create(their_run)

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        events.append(builders.trace_event(workspace_id, their_run.id))


def test_a_tool_invocation_cannot_attach_to_another_workspaces_run(
    two_workspaces, workspace_id, other_workspace_id
):
    runs = PgRunRepository(two_workspaces)
    invocations = PgToolInvocationRepository(two_workspaces)

    their_run = builders.run(other_workspace_id)
    runs.create(their_run)

    with pytest.raises(psycopg.errors.ForeignKeyViolation):
        invocations.create(builders.tool_invocation(workspace_id, their_run.id))
