"""Retention as a startup precondition — tasks 4.1 and 4.3, `[R14.3]`.

`[R14.3]` says the platform refuses to start when a content category has no configured
period, because an unbounded default is how temporary storage becomes permanent. That
makes retention a gate rather than a document.

Two halves here. :func:`validate_retention` is the gate. :class:`RetentionSweeper` is
the enforcement — following the PII agent's ``sweep_idle_sessions`` pattern, because
retention that depends on someone remembering to run something is not retention.

The required set is derived
---------------------------

:data:`explorer.storage.classification.RETENTION_REQUIRED_CATEGORIES` comes from the
classification registry rather than being listed here. That is the load-bearing detail:
a new content category acquires the requirement to configure a period by virtue of
being classified as content, so it cannot be added and then quietly retained forever.
A second list would drift from the first, and the drift would be in the permissive
direction.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from explorer.storage.classification import (
    RETENTION_REQUIRED_CATEGORIES,
    BY_CATEGORY,
)

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class RetentionValidation:
    """Whether every workspace has the periods it needs.

    Carries the detail rather than a bare boolean so the refusal can name the
    workspace and the category. "Startup blocked: retention" is not actionable.
    """

    permitted: bool
    missing_by_workspace: dict[UUID, set[str]] = field(default_factory=dict)

    def message(self) -> str:
        if self.permitted:
            return "Retention policies are configured for every content category."

        lines = ["Startup blocked: content categories with no retention period."]
        for workspace_id, categories in sorted(
            self.missing_by_workspace.items(), key=lambda item: str(item[0])
        ):
            lines.append(f"  workspace {workspace_id}:")
            for category in sorted(categories):
                classification = BY_CATEGORY.get(category)
                why = classification.rationale if classification else ""
                lines.append(f"    {category} — {why}")
        lines.append(
            "\n[R14.3] refuses an unbounded default: that is how temporary storage "
            "becomes permanent. Configure a period for each, or delete the workspace."
        )
        return "\n".join(lines)


def validate_retention(
    *, workspace_ids: Sequence[UUID], policies, required: frozenset[str] | None = None
) -> RetentionValidation:
    """Check every workspace against the required categories.

    Per workspace, not globally. A single global check would pass as soon as one
    workspace was configured, leaving every other tenant's content unbounded — and the
    first workspace is usually the developer's own.
    """
    needed = required if required is not None else RETENTION_REQUIRED_CATEGORIES
    missing: dict[UUID, set[str]] = {}

    for workspace_id in workspace_ids:
        absent = policies.missing_categories(workspace_id, needed)
        if absent:
            missing[workspace_id] = absent

    return RetentionValidation(permitted=not missing, missing_by_workspace=missing)


@dataclass(frozen=True)
class SweepReport:
    """What one sweep removed. Suitable for an audit record and a health panel."""

    started_at: datetime
    documents_deleted: int = 0
    runs_deleted: int = 0
    trace_events_deleted: int = 0
    sessions_deleted: int = 0
    payloads_deleted: int = 0
    skipped_workspaces: tuple[UUID, ...] = ()
    """Workspaces skipped because a required period was missing.

    Skipped rather than swept with a default. A sweeper that invented a period for an
    unconfigured category would delete data on a schedule nobody chose, which is worse
    than retaining it while the refusal is visible at startup."""

    @property
    def total_deleted(self) -> int:
        return (
            self.documents_deleted
            + self.runs_deleted
            + self.trace_events_deleted
            + self.sessions_deleted
        )


class RetentionSweeper:
    """Deletes what is past its period, and nothing else.

    The correctness property that matters is negative: nothing inside its retention
    window is ever removed. ``tests/explorer/storage/test_retention.py`` asserts it as a
    Hypothesis property over arbitrary periods and timestamps, because the
    off-by-one — ``<`` against ``<=``, or days against seconds — is both easy to write
    and invisible until data is gone.
    """

    def __init__(self, *, policies, documents, runs, sessions, deleter) -> None:
        self._policies = policies
        self._documents = documents
        self._runs = runs
        self._sessions = sessions
        self._deleter = deleter

    def cutoff_for(
        self, *, workspace_id: UUID, category: str, now: datetime
    ) -> datetime | None:
        """The timestamp before which data in this category may be deleted.

        ``None`` means no policy exists, and the caller must skip rather than assume.
        Returning a permissive default here would be the single most damaging line in
        the module.
        """
        policy = self._policies.get(workspace_id=workspace_id, category=category)
        if policy is None:
            return None
        return now - timedelta(days=policy.retention_days)

    def sweep_workspace(
        self, workspace_id: UUID, *, now: datetime | None = None
    ) -> SweepReport:
        """Sweep one workspace. Skips it entirely if a required period is absent.

        Entirely, not partially. Sweeping the configured categories and leaving the
        rest would make the startup refusal look optional — the system would appear to
        work while quietly retaining a category forever.
        """
        moment = now or datetime.now(UTC)

        absent = self._policies.missing_categories(
            workspace_id, RETENTION_REQUIRED_CATEGORIES
        )
        if absent:
            log.warning(
                "skipping retention sweep for workspace %s: no period configured "
                "for %s",
                workspace_id,
                ", ".join(sorted(absent)),
            )
            return SweepReport(
                started_at=moment, skipped_workspaces=(workspace_id,)
            )

        documents_deleted = 0
        payloads_deleted = 0

        document_cutoff = self.cutoff_for(
            workspace_id=workspace_id, category="document", now=moment
        )
        if document_cutoff is not None:
            for document in self._documents.list(workspace_id=workspace_id, limit=10_000):
                if document.created_at < document_cutoff:
                    receipt = self._deleter.delete_document(
                        document.id, workspace_id=workspace_id, reason="retention"
                    )
                    documents_deleted += 1
                    payloads_deleted += receipt.payloads_deleted

        trace_cutoff = self.cutoff_for(
            workspace_id=workspace_id, category="trace_event", now=moment
        )
        runs_deleted = 0
        if trace_cutoff is not None:
            for run in self._runs.list(workspace_id=workspace_id, limit=10_000):
                if run.started_at < trace_cutoff:
                    self._deleter.delete_run(
                        run.id, workspace_id=workspace_id, reason="retention"
                    )
                    runs_deleted += 1

        sessions_deleted = 0
        session_cutoff = self.cutoff_for(
            workspace_id=workspace_id, category="session", now=moment
        )
        if session_cutoff is not None:
            # Sessions expire on their own clock as well; this removes the rows once
            # they are also past retention. Both are needed: expiry stops a session
            # working, retention stops the record of it persisting.
            sessions_deleted = self._sessions.delete_expired(before=session_cutoff)

        return SweepReport(
            started_at=moment,
            documents_deleted=documents_deleted,
            runs_deleted=runs_deleted,
            sessions_deleted=sessions_deleted,
            payloads_deleted=payloads_deleted,
        )
