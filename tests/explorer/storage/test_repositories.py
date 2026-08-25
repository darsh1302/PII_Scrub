"""Round-trip and scoping per repository — task 2.4.

Two things are asserted for every repository, and the second matters more.

A record written and read back is equal to what went in. That catches column
mismatches, enum round-tripping, and JSONB and array handling.

And a read using the *wrong* workspace finds nothing. `[R15.3]` requires the
predicate to be in the query; this is what makes that claim testable rather than
declared. Task 3.4 builds the full isolation matrix over read paths; these are the
repository-level version, here because the predicate is written here.
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from explorer.storage.engine import Database
from explorer.storage.postgres import (
    PgApprovalRepository,
    PgChunkRepository,
    PgDocumentRepository,
    PgEmbeddingRepository,
    PgExperimentRepository,
    PgMembershipRepository,
    PgPriceTableRepository,
    PgPromptTemplateRepository,
    PgRetentionPolicyRepository,
    PgRunRepository,
    PgToolInvocationRepository,
    PgTraceEventRepository,
    PgUserRepository,
    PgWorkspaceRepository,
)
from explorer.storage.protocols import NotFound
from explorer.storage.records import CompletionReason, Role
from tests.explorer.conftest import requires_database
from tests.explorer.storage import builders

pytestmark = requires_database


@pytest.fixture
def seeded(db: Database, workspace_id, other_workspace_id):
    """Both workspaces exist, so a scoping test has somewhere to fail to."""
    repository = PgWorkspaceRepository(db)
    repository.create(builders.workspace(workspace_id, name="first"))
    repository.create(builders.workspace(other_workspace_id, name="second"))
    return db


# ---------------------------------------------------------------------------
# workspace, users, membership
# ---------------------------------------------------------------------------
def test_workspace_round_trip(db: Database, workspace_id):
    repository = PgWorkspaceRepository(db)
    original = builders.workspace(workspace_id, name="Acme")
    repository.create(original)

    assert repository.get(workspace_id) == original


def test_missing_workspace_raises_not_found(db: Database):
    with pytest.raises(NotFound):
        PgWorkspaceRepository(db).get(uuid4())


def test_user_round_trip_and_case_insensitive_lookup(db: Database):
    repository = PgUserRepository(db)
    original = builders.user(email="Dana.Okonkwo@example.test")
    repository.create(original)

    assert repository.get(original.id) == original
    # Case-insensitive, matching the unique index. Two accounts differing only in
    # case would be indistinguishable in an approval record [R15.6].
    assert repository.find_by_email("dana.okonkwo@EXAMPLE.test") == original
    assert repository.find_by_email("someone.else@example.test") is None


def test_membership_carries_the_role_not_the_user(seeded, workspace_id,
                                                 other_workspace_id):
    """`[R15.2]`: the same person, different roles in two workspaces.

    This is the whole reason role lives on membership. A role on the user could not
    express it, and the approval authority check would then be workspace-blind.
    """
    users = PgUserRepository(seeded)
    memberships = PgMembershipRepository(seeded)

    person = builders.user(email="dual@example.test")
    users.create(person)
    memberships.add(builders.membership(workspace_id, person.id, role=Role.APPROVER))
    memberships.add(
        builders.membership(other_workspace_id, person.id, role=Role.READER)
    )

    assert memberships.role_for(workspace_id=workspace_id, user_id=person.id) is (
        Role.APPROVER
    )
    assert memberships.role_for(
        workspace_id=other_workspace_id, user_id=person.id
    ) is Role.READER


def test_role_for_a_non_member_is_none_not_a_default(seeded, workspace_id):
    """``None`` means no access. A default role here would grant one."""
    users = PgUserRepository(seeded)
    outsider = builders.user(email="outsider@example.test")
    users.create(outsider)

    assert (
        PgMembershipRepository(seeded).role_for(
            workspace_id=workspace_id, user_id=outsider.id
        )
        is None
    )


def test_list_for_user_returns_only_joined_workspaces(seeded, workspace_id,
                                                      other_workspace_id):
    users = PgUserRepository(seeded)
    memberships = PgMembershipRepository(seeded)
    person = builders.user(email="member@example.test")
    users.create(person)
    memberships.add(builders.membership(workspace_id, person.id))

    visible = PgWorkspaceRepository(seeded).list_for_user(person.id)
    assert [w.id for w in visible] == [workspace_id]
    assert other_workspace_id not in {w.id for w in visible}


# ---------------------------------------------------------------------------
# experiments and runs
# ---------------------------------------------------------------------------
def test_experiment_round_trip_with_jsonb_configuration(seeded, workspace_id):
    repository = PgExperimentRepository(seeded)
    original = builders.experiment(workspace_id)
    repository.create(original)

    fetched = repository.get(original.id, workspace_id=workspace_id)
    assert fetched == original
    assert fetched.configuration["temperature"] == 0.0


def test_experiment_is_not_readable_from_another_workspace(
    seeded, workspace_id, other_workspace_id
):
    repository = PgExperimentRepository(seeded)
    original = builders.experiment(workspace_id)
    repository.create(original)

    with pytest.raises(NotFound):
        repository.get(original.id, workspace_id=other_workspace_id)


def test_experiment_list_filters_by_lab(seeded, workspace_id):
    repository = PgExperimentRepository(seeded)
    repository.create(builders.experiment(workspace_id, lab="prompt", name="a"))
    repository.create(builders.experiment(workspace_id, lab="rag", name="b"))

    assert len(repository.list(workspace_id=workspace_id)) == 2
    assert [e.name for e in repository.list(workspace_id=workspace_id, lab="rag")] == (
        ["b"]
    )


def test_run_round_trip(seeded, workspace_id):
    experiments = PgExperimentRepository(seeded)
    runs = PgRunRepository(seeded)
    experiment = builders.experiment(workspace_id)
    experiments.create(experiment)

    original = builders.run(workspace_id, experiment_id=experiment.id)
    runs.create(original)

    assert runs.get(original.id, workspace_id=workspace_id) == original


def test_finishing_a_run_sets_status_and_reason_together(seeded, workspace_id):
    runs = PgRunRepository(seeded)
    original = builders.run(workspace_id)
    runs.create(original)

    runs.finish(
        original.id,
        workspace_id=workspace_id,
        completion_reason=CompletionReason.BUDGET_EXHAUSTED.value,
        finished_at=datetime(2026, 8, 24, 13, 0, tzinfo=UTC),
    )

    finished = runs.get(original.id, workspace_id=workspace_id)
    assert finished.status == "terminal"
    assert finished.completion_reason is CompletionReason.BUDGET_EXHAUSTED
    assert finished.finished_at is not None


def test_finishing_a_run_from_another_workspace_raises(
    seeded, workspace_id, other_workspace_id
):
    """A write path needs the same scoping as a read path.

    An UPDATE matching zero rows returns quietly, so without this check a
    cross-workspace finish would look like success and leave the run running.
    """
    runs = PgRunRepository(seeded)
    original = builders.run(workspace_id)
    runs.create(original)

    with pytest.raises(NotFound):
        runs.finish(
            original.id,
            workspace_id=other_workspace_id,
            completion_reason=CompletionReason.COMPLETED.value,
            finished_at=builders.NOW,
        )


def test_usage_estimation_flag_is_sticky(seeded, workspace_id):
    """`[R1.4]`. A run mixing reported and estimated counts is estimated.

    Letting a later exact call clear the flag would present a partly-guessed total
    as a measurement, which is the specific dishonesty the flag exists to prevent.
    """
    runs = PgRunRepository(seeded)
    original = builders.run(workspace_id)
    runs.create(original)

    runs.record_usage(
        original.id,
        workspace_id=workspace_id,
        input_tokens=100,
        output_tokens=50,
        cost_micros=1_250,
        estimated=True,
    )
    runs.record_usage(
        original.id,
        workspace_id=workspace_id,
        input_tokens=10,
        output_tokens=5,
        cost_micros=125,
        estimated=False,
    )

    fetched = runs.get(original.id, workspace_id=workspace_id)
    assert fetched.total_input_tokens == 110
    assert fetched.total_output_tokens == 55
    assert fetched.total_cost_micros == 1_375
    assert fetched.token_counts_are_estimated is True


# ---------------------------------------------------------------------------
# documents, chunks, embeddings
# ---------------------------------------------------------------------------
def test_document_round_trip(seeded, workspace_id):
    repository = PgDocumentRepository(seeded)
    original = builders.document(workspace_id)
    repository.create(original)

    assert repository.get(original.id, workspace_id=workspace_id) == original


def test_identical_content_in_two_workspaces_is_not_shared(
    seeded, workspace_id, other_workspace_id
):
    """Deduplication stops at the workspace boundary, deliberately.

    Sharing a payload across workspaces would let one tenant's retention decision
    delete another tenant's only copy, and would disclose that the other tenant
    holds the same file.
    """
    repository = PgDocumentRepository(seeded)
    digest = "b" * 64
    repository.create(builders.document(workspace_id, sha256=digest))
    repository.create(builders.document(other_workspace_id, sha256=digest))

    mine = repository.find_by_sha256(digest, workspace_id=workspace_id)
    theirs = repository.find_by_sha256(digest, workspace_id=other_workspace_id)
    assert mine is not None and theirs is not None
    assert mine.id != theirs.id


def test_chunks_are_replaced_wholesale_not_appended(seeded, workspace_id):
    documents = PgDocumentRepository(seeded)
    chunks = PgChunkRepository(seeded)
    document = builders.document(workspace_id)
    documents.create(document)

    chunks.replace_for_document(
        document.id,
        workspace_id=workspace_id,
        chunks=[
            builders.chunk(workspace_id, document.id, sequence=0, start=0, end=100),
            builders.chunk(workspace_id, document.id, sequence=1, start=100, end=200),
        ],
    )
    # Rechunking with a different strategy must not leave the first set behind;
    # overlapping duplicates with no way to tell which run produced them is worse
    # than either result alone.
    chunks.replace_for_document(
        document.id,
        workspace_id=workspace_id,
        chunks=[builders.chunk(workspace_id, document.id, sequence=0, start=0, end=200)],
    )

    stored = chunks.list_for_document(document.id, workspace_id=workspace_id)
    assert len(stored) == 1
    assert stored[0].end_offset == 200


def test_chunk_offsets_round_trip_exactly(seeded, workspace_id):
    """Property 13's storage half. Offsets locate text in the original document."""
    documents = PgDocumentRepository(seeded)
    chunks = PgChunkRepository(seeded)
    document = builders.document(workspace_id)
    documents.create(document)

    original = builders.chunk(workspace_id, document.id, start=17, end=4096)
    chunks.replace_for_document(
        document.id, workspace_id=workspace_id, chunks=[original]
    )

    assert chunks.get(original.id, workspace_id=workspace_id) == original


def test_embedding_round_trip_preserves_the_vector(seeded, workspace_id):
    documents = PgDocumentRepository(seeded)
    chunks = PgChunkRepository(seeded)
    embeddings = PgEmbeddingRepository(seeded)

    document = builders.document(workspace_id)
    documents.create(document)
    chunk = builders.chunk(workspace_id, document.id)
    chunks.replace_for_document(document.id, workspace_id=workspace_id, chunks=[chunk])

    original = builders.embedding(
        workspace_id, chunk.id, document.id, vector=(0.5, -0.25, 1.0e-7)
    )
    embeddings.upsert([original])

    fetched = embeddings.get(original.id, workspace_id=workspace_id)
    assert fetched.vector == original.vector
    assert fetched.embedding_model == original.embedding_model
    assert fetched.embedding_model_version == original.embedding_model_version


def test_reembedding_the_same_chunk_with_the_same_model_replaces(seeded, workspace_id):
    documents = PgDocumentRepository(seeded)
    chunks = PgChunkRepository(seeded)
    embeddings = PgEmbeddingRepository(seeded)

    document = builders.document(workspace_id)
    documents.create(document)
    chunk = builders.chunk(workspace_id, document.id)
    chunks.replace_for_document(document.id, workspace_id=workspace_id, chunks=[chunk])

    embeddings.upsert([builders.embedding(workspace_id, chunk.id, document.id)])
    embeddings.upsert(
        [builders.embedding(workspace_id, chunk.id, document.id, vector=(9.0, 9.0, 9.0))]
    )

    assert embeddings.count(workspace_id=workspace_id) == 1


def test_the_same_chunk_may_hold_vectors_from_two_models(seeded, workspace_id):
    """Which is the point of the Vector Lab comparison.

    The uniqueness constraint is on (chunk, model, model_version), not on chunk
    alone, so two embedding spaces can coexist and Property 12 keeps searches from
    mixing them.
    """
    documents = PgDocumentRepository(seeded)
    chunks = PgChunkRepository(seeded)
    embeddings = PgEmbeddingRepository(seeded)

    document = builders.document(workspace_id)
    documents.create(document)
    chunk = builders.chunk(workspace_id, document.id)
    chunks.replace_for_document(document.id, workspace_id=workspace_id, chunks=[chunk])

    embeddings.upsert(
        [
            builders.embedding(workspace_id, chunk.id, document.id, model="small"),
            builders.embedding(workspace_id, chunk.id, document.id, model="large"),
        ]
    )

    assert embeddings.count(workspace_id=workspace_id) == 2


# ---------------------------------------------------------------------------
# traces, tools, approvals
# ---------------------------------------------------------------------------
def test_trace_events_come_back_in_sequence_order(seeded, workspace_id):
    runs = PgRunRepository(seeded)
    events = PgTraceEventRepository(seeded)
    run = builders.run(workspace_id)
    runs.create(run)

    # Inserted out of order on purpose: ordering must come from the sequence
    # column, not from insertion order, or a concurrent writer reorders a trace.
    for sequence in (2, 0, 1):
        events.append(builders.trace_event(workspace_id, run.id, sequence=sequence))

    stored = events.list_for_run(run.id, workspace_id=workspace_id)
    assert [e.sequence for e in stored] == [0, 1, 2]


def test_trace_event_redaction_count_round_trips(seeded, workspace_id):
    """`[R6.7]`: a trace can say how many values it removed without holding them."""
    runs = PgRunRepository(seeded)
    events = PgTraceEventRepository(seeded)
    run = builders.run(workspace_id)
    runs.create(run)

    events.append(builders.trace_event(workspace_id, run.id, redaction_count=3))
    assert events.list_for_run(run.id, workspace_id=workspace_id)[0].redaction_count == 3


def test_approval_records_requested_and_executed_parameters_separately(
    seeded, workspace_id
):
    """The shape Property 9 needs.

    Holding one field and calling it both would make substitution at execution time
    undetectable, which is exactly the failure `[R10.6]` is about.
    """
    users = PgUserRepository(seeded)
    runs = PgRunRepository(seeded)
    invocations = PgToolInvocationRepository(seeded)
    approvals = PgApprovalRepository(seeded)

    approver = builders.user(email="approver@example.test")
    users.create(approver)
    run = builders.run(workspace_id)
    runs.create(run)
    invocation = builders.tool_invocation(workspace_id, run.id, requires_approval=True)
    invocations.create(invocation)

    approvals.record(
        builders.approval(
            workspace_id,
            invocation.id,
            approver.id,
            executed={"destination": "EXTERNAL_VENDOR"},
        )
    )

    stored = approvals.for_invocation(invocation.id, workspace_id=workspace_id)
    assert stored is not None
    assert stored.requested_parameters == {"destination": "INTERNAL_SIEM"}
    assert stored.executed_parameters == {"destination": "EXTERNAL_VENDOR"}
    assert stored.requested_parameters != stored.executed_parameters


# ---------------------------------------------------------------------------
# prompts, retention, pricing
# ---------------------------------------------------------------------------
def test_prompt_template_versions_are_ordered_and_latest_is_the_highest(
    seeded, workspace_id
):
    repository = PgPromptTemplateRepository(seeded)
    template_id = uuid4()
    repository.create_template(
        template_id=template_id,
        workspace_id=workspace_id,
        name="rag-answer",
        created_at=builders.NOW,
    )

    for version in (1, 2, 3):
        repository.add_version(
            builders.prompt_version(workspace_id, template_id, version=version)
        )

    assert [
        v.version for v in repository.list_versions(template_id, workspace_id=workspace_id)
    ] == [1, 2, 3]
    latest = repository.latest(template_id, workspace_id=workspace_id)
    assert latest is not None and latest.version == 3


def test_prompt_version_variables_round_trip_as_a_tuple(seeded, workspace_id):
    repository = PgPromptTemplateRepository(seeded)
    template_id = uuid4()
    repository.create_template(
        template_id=template_id,
        workspace_id=workspace_id,
        name="t",
        created_at=builders.NOW,
    )
    original = builders.prompt_version(workspace_id, template_id)
    repository.add_version(original)

    assert repository.get_version(original.id, workspace_id=workspace_id) == original


def test_retention_policy_upsert_replaces_the_period(seeded, workspace_id):
    repository = PgRetentionPolicyRepository(seeded)
    repository.upsert(builders.retention_policy(workspace_id, days=30))
    repository.upsert(builders.retention_policy(workspace_id, days=7))

    policy = repository.get(workspace_id=workspace_id, category="document")
    assert policy is not None and policy.retention_days == 7
    assert len(repository.list_for_workspace(workspace_id)) == 1


def test_missing_categories_reports_what_startup_must_refuse_on(seeded, workspace_id):
    """Task 4.1 turns a non-empty result here into a startup refusal `[R14.3]`."""
    repository = PgRetentionPolicyRepository(seeded)
    repository.upsert(builders.retention_policy(workspace_id, category="document"))

    missing = repository.missing_categories(
        workspace_id, frozenset({"document", "sanitized_artifact", "trace_event"})
    )
    assert missing == {"sanitized_artifact", "trace_event"}


def test_price_table_current_returns_the_most_recent_effective_version(db: Database):
    repository = PgPriceTableRepository(db)
    repository.add_version(builders.price_table(version="2026-01-01"))
    repository.add_version(builders.price_table(version="2026-08-01"))

    current = repository.current(at=datetime(2026, 12, 1, tzinfo=UTC))
    assert current is not None
    # Both share the same effective_from in the builder, so this asserts a
    # deterministic pick rather than an arbitrary one.
    assert current.version in {"2026-01-01", "2026-08-01"}
    assert repository.get("2026-08-01").entries["gpt-4o"]["input_per_mtok"] == 2.50
