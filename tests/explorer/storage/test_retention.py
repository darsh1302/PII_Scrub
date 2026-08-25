"""Retention validation and the sweeper — tasks 4.1, 4.3 and 4.6.

The property test is the point of this file. An off-by-one in a retention cutoff —
``<`` where ``<=`` was meant, days confused with seconds, a comparison against the
wrong timestamp — is easy to write, passes any example you happen to pick, and is
invisible until data is gone. So the negative guarantee is asserted over arbitrary
periods and timestamps rather than over three hand-chosen cases.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from explorer.storage.classification import RETENTION_REQUIRED_CATEGORIES
from explorer.storage.records import RetentionPolicy
from explorer.storage.retention import (
    RetentionSweeper,
    SweepReport,
    validate_retention,
)

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# doubles
# ---------------------------------------------------------------------------
class FakePolicies:
    """In-memory policy repository.

    A fake rather than the real one, because these tests are about the arithmetic and
    the decision, not about SQL. The repository's own round-trip and scoping are
    covered in ``test_repositories.py`` and the isolation matrix.
    """

    def __init__(self, policies: dict[tuple[UUID, str], int] | None = None) -> None:
        self._periods = policies or {}

    def get(self, *, workspace_id: UUID, category: str) -> RetentionPolicy | None:
        days = self._periods.get((workspace_id, category))
        if days is None:
            return None
        return RetentionPolicy(
            id=uuid4(),
            workspace_id=workspace_id,
            category=category,
            retention_days=days,
            updated_at=NOW,
        )

    def list_for_workspace(self, workspace_id: UUID) -> list[RetentionPolicy]:
        return [
            self.get(workspace_id=workspace_id, category=category)  # type: ignore[misc]
            for (ws, category) in self._periods
            if ws == workspace_id
        ]

    def missing_categories(self, workspace_id: UUID, required: frozenset[str]) -> set[str]:
        configured = {c for (ws, c) in self._periods if ws == workspace_id}
        return set(required) - configured


class FakeDocuments:
    def __init__(self, documents):
        self._documents = list(documents)

    def list(self, *, workspace_id: UUID, limit: int = 50):
        return [d for d in self._documents if d.workspace_id == workspace_id][:limit]


class FakeRuns:
    def __init__(self, runs):
        self._runs = list(runs)

    def list(self, *, workspace_id: UUID, limit: int = 50):
        return [r for r in self._runs if r.workspace_id == workspace_id][:limit]


class FakeSessions:
    def __init__(self):
        self.deleted_before: datetime | None = None

    def delete_expired(self, *, before: datetime) -> int:
        self.deleted_before = before
        return 0


class RecordingDeleter:
    """Records what the sweeper asked to delete, and deletes nothing.

    Lets a test assert on the *decision* rather than on the outcome, which is what the
    property below needs: the question is which documents were selected, not whether the
    deletion mechanics work.
    """

    def __init__(self):
        self.documents: list[UUID] = []
        self.runs: list[UUID] = []

    def delete_document(self, document_id, *, workspace_id, reason):
        self.documents.append(document_id)
        return SimpleReceipt()

    def delete_run(self, run_id, *, workspace_id, reason):
        self.runs.append(run_id)
        return SimpleReceipt()


class SimpleReceipt:
    payloads_deleted = 0


def _full_policy_set(workspace_id: UUID, days: int = 30) -> dict[tuple[UUID, str], int]:
    return {(workspace_id, category): days for category in RETENTION_REQUIRED_CATEGORIES}


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------
def test_a_fully_configured_workspace_passes():
    workspace = uuid4()
    result = validate_retention(
        workspace_ids=[workspace], policies=FakePolicies(_full_policy_set(workspace))
    )
    assert result.permitted is True
    assert result.missing_by_workspace == {}


def test_a_workspace_with_no_policies_is_refused():
    workspace = uuid4()
    result = validate_retention(workspace_ids=[workspace], policies=FakePolicies())

    assert result.permitted is False
    assert result.missing_by_workspace[workspace] == set(RETENTION_REQUIRED_CATEGORIES)


def test_validation_is_per_workspace_not_global():
    """The failure mode a global check would produce.

    A single global check passes as soon as one workspace is configured, leaving every
    other tenant's content unbounded — and the configured one is usually the
    developer's own.
    """
    configured, unconfigured = uuid4(), uuid4()
    result = validate_retention(
        workspace_ids=[configured, unconfigured],
        policies=FakePolicies(_full_policy_set(configured)),
    )

    assert result.permitted is False
    assert configured not in result.missing_by_workspace
    assert unconfigured in result.missing_by_workspace


def test_one_missing_category_is_enough_to_refuse():
    workspace = uuid4()
    policies = _full_policy_set(workspace)
    policies.pop((workspace, "document"))

    result = validate_retention(
        workspace_ids=[workspace], policies=FakePolicies(policies)
    )
    assert result.permitted is False
    assert result.missing_by_workspace[workspace] == {"document"}


def test_the_refusal_message_names_the_workspace_and_the_reason():
    """An operator should be able to act on it without reading the source."""
    workspace = uuid4()
    result = validate_retention(workspace_ids=[workspace], policies=FakePolicies())
    message = result.message()

    assert str(workspace) in message
    assert "R14.3" in message
    assert "document" in message
    # And the classification's rationale travels with it, so the answer to "why does
    # this need a period" is in the same output as the refusal.
    assert "object store" in message


def test_no_workspaces_at_all_is_permitted():
    """A fresh install has nothing to retain, and must be able to start.

    Refusing here would make the first run impossible: there would be no way to create
    a workspace in order to configure the policy the startup check demands.
    """
    assert validate_retention(workspace_ids=[], policies=FakePolicies()).permitted


# ---------------------------------------------------------------------------
# cutoff arithmetic
# ---------------------------------------------------------------------------
def _sweeper(policies: FakePolicies, **kwargs) -> RetentionSweeper:
    return RetentionSweeper(
        policies=policies,
        documents=kwargs.get("documents", FakeDocuments([])),
        runs=kwargs.get("runs", FakeRuns([])),
        sessions=kwargs.get("sessions", FakeSessions()),
        deleter=kwargs.get("deleter", RecordingDeleter()),
    )


def test_the_cutoff_is_now_minus_the_period():
    workspace = uuid4()
    sweeper = _sweeper(FakePolicies({(workspace, "document"): 7}))

    cutoff = sweeper.cutoff_for(workspace_id=workspace, category="document", now=NOW)
    assert cutoff == NOW - timedelta(days=7)


def test_an_unconfigured_category_has_no_cutoff():
    """``None``, not a permissive default.

    A default here would be the single most damaging line in the module: it would sweep
    on a schedule nobody chose, and the startup refusal that exists to prevent exactly
    that would look optional.
    """
    sweeper = _sweeper(FakePolicies())
    assert sweeper.cutoff_for(workspace_id=uuid4(), category="document", now=NOW) is None


# ---------------------------------------------------------------------------
# the property — nothing inside its window is ever deleted
# ---------------------------------------------------------------------------
@settings(max_examples=200, deadline=None)
@given(
    retention_days=st.integers(min_value=1, max_value=3650),
    age_days=st.integers(min_value=0, max_value=7300),
)
def test_the_sweeper_never_deletes_inside_the_retention_window(
    retention_days: int, age_days: int
):
    """Task 4.6's property, over arbitrary periods and ages.

    A document is deletable only when it is strictly older than its period. Stated as a
    property because the failure mode — one day either side of the boundary — passes
    every example anyone picks by hand, and its consequence is data that is gone.
    """
    from tests.explorer.storage import builders

    workspace = uuid4()
    created_at = NOW - timedelta(days=age_days)

    document = builders.document(workspace, sha256="a" * 64)
    document = type(document)(
        **{**vars(document), "created_at": created_at}
    )

    deleter = RecordingDeleter()
    policies = FakePolicies(_full_policy_set(workspace, days=retention_days))
    sweeper = _sweeper(
        policies, documents=FakeDocuments([document]), deleter=deleter
    )

    sweeper.sweep_workspace(workspace, now=NOW)

    was_deleted = document.id in deleter.documents
    is_past_retention = age_days > retention_days

    if not is_past_retention:
        assert not was_deleted, (
            f"a document {age_days} days old was deleted under a "
            f"{retention_days}-day policy — inside its window"
        )
    # The converse is asserted separately rather than here, because equality at the
    # boundary is a deliberate choice: a document exactly at its period is retained,
    # so `age_days == retention_days` must not delete.
    if age_days == retention_days:
        assert not was_deleted, "a document exactly at its period was deleted"


@settings(max_examples=100, deadline=None)
@given(
    retention_days=st.integers(min_value=1, max_value=365),
    excess_days=st.integers(min_value=1, max_value=365),
)
def test_the_sweeper_does_delete_once_past_the_window(
    retention_days: int, excess_days: int
):
    """The positive direction, so the property above cannot pass by deleting nothing.

    Without this, a sweeper with its comparison inverted — or one that simply never
    deletes — would satisfy every assertion in the previous test.
    """
    from tests.explorer.storage import builders

    workspace = uuid4()
    created_at = NOW - timedelta(days=retention_days + excess_days)

    document = builders.document(workspace, sha256="b" * 64)
    document = type(document)(**{**vars(document), "created_at": created_at})

    deleter = RecordingDeleter()
    sweeper = _sweeper(
        FakePolicies(_full_policy_set(workspace, days=retention_days)),
        documents=FakeDocuments([document]),
        deleter=deleter,
    )
    sweeper.sweep_workspace(workspace, now=NOW)

    assert document.id in deleter.documents


# ---------------------------------------------------------------------------
# skipping
# ---------------------------------------------------------------------------
def test_a_workspace_with_a_missing_period_is_skipped_entirely():
    """Entirely, not partially.

    Sweeping the configured categories and leaving the rest would make the startup
    refusal look optional: the system would appear to work while retaining a category
    forever.
    """
    from tests.explorer.storage import builders

    workspace = uuid4()
    old = builders.document(workspace, sha256="c" * 64)
    old = type(old)(**{**vars(old), "created_at": NOW - timedelta(days=9999)})

    policies = _full_policy_set(workspace)
    policies.pop((workspace, "trace_event"))

    deleter = RecordingDeleter()
    sweeper = _sweeper(
        FakePolicies(policies), documents=FakeDocuments([old]), deleter=deleter
    )
    report = sweeper.sweep_workspace(workspace, now=NOW)

    assert report.skipped_workspaces == (workspace,)
    assert deleter.documents == [], "an ancient document was deleted under a partial policy"
    assert report.total_deleted == 0


def test_a_sweep_reports_what_it_removed():
    from tests.explorer.storage import builders

    workspace = uuid4()
    documents = []
    for index in range(3):
        document = builders.document(workspace, sha256=str(index) * 64)
        documents.append(
            type(document)(
                **{**vars(document), "created_at": NOW - timedelta(days=100)}
            )
        )

    sweeper = _sweeper(
        FakePolicies(_full_policy_set(workspace, days=30)),
        documents=FakeDocuments(documents),
        deleter=RecordingDeleter(),
    )
    report = sweeper.sweep_workspace(workspace, now=NOW)

    assert report.documents_deleted == 3
    assert report.started_at == NOW
