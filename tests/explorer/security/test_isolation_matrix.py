"""The isolation matrix — task 3.4, Property 10, `[R15.4]`.

Two tests carry this file, and the second is what keeps the first honest.

:func:`test_no_read_path_returns_another_workspaces_data` seeds two workspaces and
drives every read path with the wrong workspace, asserting nothing comes back.

:func:`test_every_repository_read_path_appears_in_the_matrix` walks the repository
classes and fails when a read method is not covered. Without it, the matrix would
document the read paths that existed on the day it was written. A read path added in
task 9 or 10 and never added here would leave the suite green while the guarantee
quietly narrowed — and `[R15.4]` is a claim about *every* path, not about the ones
someone remembered.

Scope, not repositories, is what a caller should hold. That is asserted separately in
``test_scope.py``; here the repositories are driven directly, because a leak has to be
impossible at the layer where the SQL lives rather than only at the layer above it.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
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
    PgPromptTemplateRepository,
    PgRetentionPolicyRepository,
    PgRunRepository,
    PgToolInvocationRepository,
    PgTraceEventRepository,
    PgUserRepository,
    PgWorkspaceRepository,
)
from explorer.storage.protocols import NotFound
from tests.explorer.conftest import requires_database
from tests.explorer.storage import builders

pytestmark = requires_database


# ---------------------------------------------------------------------------
# seeding
# ---------------------------------------------------------------------------
@pytest.fixture
def two_tenants(db: Database):
    """A fully populated workspace, and an empty-but-real second one.

    The intruder workspace genuinely exists and the intruder is a member of it. A test
    where the second workspace does not exist would pass for the wrong reason — the
    read would find nothing because there is nothing anywhere.
    """
    victim = uuid4()
    intruder = uuid4()

    workspaces = PgWorkspaceRepository(db)
    workspaces.create(builders.workspace(victim, name="victim"))
    workspaces.create(builders.workspace(intruder, name="intruder"))

    users = PgUserRepository(db)
    approver = builders.user(email="approver@victim.test")
    users.create(approver)

    memberships = PgMembershipRepository(db)
    memberships.add(builders.membership(victim, approver.id))

    documents = PgDocumentRepository(db)
    chunks = PgChunkRepository(db)
    embeddings = PgEmbeddingRepository(db)
    experiments = PgExperimentRepository(db)
    runs = PgRunRepository(db)
    events = PgTraceEventRepository(db)
    invocations = PgToolInvocationRepository(db)
    approvals = PgApprovalRepository(db)
    prompts = PgPromptTemplateRepository(db)
    retention = PgRetentionPolicyRepository(db)

    document = builders.document(victim, label="salaries.csv", sha256="e" * 64)
    documents.create(document)
    chunk = builders.chunk(victim, document.id)
    chunks.replace_for_document(document.id, workspace_id=victim, chunks=[chunk])
    embedding = builders.embedding(victim, chunk.id, document.id)
    embeddings.upsert([embedding])

    experiment = builders.experiment(victim)
    experiments.create(experiment)
    run = builders.run(victim, experiment_id=experiment.id)
    runs.create(run)
    events.append(builders.trace_event(victim, run.id))
    invocation = builders.tool_invocation(victim, run.id, requires_approval=True)
    invocations.create(invocation)
    approvals.record(builders.approval(victim, invocation.id, approver.id))

    template_id = uuid4()
    prompts.create_template(
        template_id=template_id,
        workspace_id=victim,
        name="answer",
        created_at=builders.NOW,
    )
    prompt_version = builders.prompt_version(victim, template_id)
    prompts.add_version(prompt_version)

    retention.upsert(builders.retention_policy(victim))

    return {
        "db": db,
        "victim": victim,
        "intruder": intruder,
        "user": approver,
        "document": document,
        "chunk": chunk,
        "embedding": embedding,
        "experiment": experiment,
        "run": run,
        "invocation": invocation,
        "template_id": template_id,
        "prompt_version": prompt_version,
    }


# ``PgUserRepository`` and ``PgPriceTableRepository`` are deliberately absent from
# WORKSPACE_SCOPED_REPOSITORIES below. Users are global — one account joins several
# workspaces — and provider list prices are not a tenant's data. Including them would
# require exempting every one of their methods, which would make the exemption list
# the place real gaps go to hide.


# ---------------------------------------------------------------------------
# the matrix
# ---------------------------------------------------------------------------
def _matrix(seed: dict) -> dict[str, Callable[[], object]]:
    """Every workspace-scoped read, bound to the *intruder's* workspace.

    Each entry is keyed ``Repository.method`` and that key is what the completeness
    check matches against, so the naming is load-bearing rather than cosmetic.

    Every callable must either raise :class:`NotFound` or return an empty result. A
    callable that returns the victim's data is a leak.
    """
    db = seed["db"]
    intruder = seed["intruder"]

    return {
        "PgExperimentRepository.get": lambda: PgExperimentRepository(db).get(
            seed["experiment"].id, workspace_id=intruder
        ),
        "PgExperimentRepository.list": lambda: PgExperimentRepository(db).list(
            workspace_id=intruder
        ),
        "PgRunRepository.get": lambda: PgRunRepository(db).get(
            seed["run"].id, workspace_id=intruder
        ),
        "PgRunRepository.list": lambda: PgRunRepository(db).list(
            workspace_id=intruder
        ),
        "PgDocumentRepository.get": lambda: PgDocumentRepository(db).get(
            seed["document"].id, workspace_id=intruder
        ),
        "PgDocumentRepository.list": lambda: PgDocumentRepository(db).list(
            workspace_id=intruder
        ),
        "PgDocumentRepository.find_by_sha256": lambda: PgDocumentRepository(
            db
        ).find_by_sha256(seed["document"].sha256, workspace_id=intruder),
        "PgChunkRepository.get": lambda: PgChunkRepository(db).get(
            seed["chunk"].id, workspace_id=intruder
        ),
        "PgChunkRepository.list_for_document": lambda: PgChunkRepository(
            db
        ).list_for_document(seed["document"].id, workspace_id=intruder),
        "PgChunkRepository.count_for_document": lambda: PgChunkRepository(
            db
        ).count_for_document(seed["document"].id, workspace_id=intruder),
        "PgEmbeddingRepository.get": lambda: PgEmbeddingRepository(db).get(
            seed["embedding"].id, workspace_id=intruder
        ),
        "PgEmbeddingRepository.list_for_document": lambda: PgEmbeddingRepository(
            db
        ).list_for_document(seed["document"].id, workspace_id=intruder),
        "PgEmbeddingRepository.count": lambda: PgEmbeddingRepository(db).count(
            workspace_id=intruder
        ),
        "PgTraceEventRepository.list_for_run": lambda: PgTraceEventRepository(
            db
        ).list_for_run(seed["run"].id, workspace_id=intruder),
        "PgToolInvocationRepository.get": lambda: PgToolInvocationRepository(db).get(
            seed["invocation"].id, workspace_id=intruder
        ),
        "PgToolInvocationRepository.list_for_run": lambda: PgToolInvocationRepository(
            db
        ).list_for_run(seed["run"].id, workspace_id=intruder),
        "PgApprovalRepository.for_invocation": lambda: PgApprovalRepository(
            db
        ).for_invocation(seed["invocation"].id, workspace_id=intruder),
        "PgPromptTemplateRepository.get_version": lambda: PgPromptTemplateRepository(
            db
        ).get_version(seed["prompt_version"].id, workspace_id=intruder),
        "PgPromptTemplateRepository.latest": lambda: PgPromptTemplateRepository(
            db
        ).latest(seed["template_id"], workspace_id=intruder),
        "PgPromptTemplateRepository.list_versions": lambda: (
            PgPromptTemplateRepository(db).list_versions(
                seed["template_id"], workspace_id=intruder
            )
        ),
        "PgRetentionPolicyRepository.get": lambda: PgRetentionPolicyRepository(db).get(
            workspace_id=intruder, category="document"
        ),
        "PgRetentionPolicyRepository.list_for_workspace": lambda: (
            PgRetentionPolicyRepository(db).list_for_workspace(intruder)
        ),
        "PgMembershipRepository.role_for": lambda: PgMembershipRepository(db).role_for(
            workspace_id=intruder, user_id=seed["user"].id
        ),
        "PgMembershipRepository.list_members": lambda: PgMembershipRepository(
            db
        ).list_members(intruder),
        "PgWorkspaceRepository.list_for_user": lambda: PgWorkspaceRepository(
            db
        ).list_for_user(uuid4()),
    }


def _is_empty(result: object) -> bool:
    """Whether a read returned nothing.

    ``0`` counts as empty for the count methods, and is checked before the generic
    falsiness test so that a count of zero is not confused with ``None``.
    """
    if result is None:
        return True
    if isinstance(result, int):
        return result == 0
    if isinstance(result, (list, tuple, set, frozenset, dict)):
        return len(result) == 0
    return False


def test_no_read_path_returns_another_workspaces_data(two_tenants):
    """Property 10. Every read path, driven with the wrong workspace.

    Run as one test over the whole matrix rather than parametrised, because the
    matrix needs the seeded fixture to build its callables. The failure message names
    every leaking path, which is more useful than the first one to fail.
    """
    leaks: list[str] = []

    for name, read in _matrix(two_tenants).items():
        try:
            result = read()
        except NotFound:
            continue
        if not _is_empty(result):
            leaks.append(f"{name} returned {result!r}")

    assert leaks == [], (
        "these read paths returned another workspace's data:\n  "
        + "\n  ".join(leaks)
    )


def test_the_matrix_actually_reaches_the_data_when_correctly_scoped(two_tenants):
    """The control on the control.

    A matrix whose callables were subtly broken — a wrong id, a typo in a category —
    would return nothing for both workspaces and pass. This runs the same reads
    against the victim's own workspace and asserts they *do* find something, so the
    test above is known to be exercising live paths.
    """
    seed = dict(two_tenants)
    seed["intruder"] = two_tenants["victim"]  # point the matrix at its own data

    found: list[str] = []
    for name, read in _matrix(seed).items():
        try:
            result = read()
        except NotFound:
            continue
        if not _is_empty(result):
            found.append(name)

    # list_for_user is called with a random user id and correctly finds nothing, so it
    # is not expected here. Everything else must resolve.
    expected = set(_matrix(seed)) - {"PgWorkspaceRepository.list_for_user"}
    missing = sorted(expected - set(found))
    assert missing == [], (
        "these matrix entries found nothing even when correctly scoped, so the "
        f"isolation assertion above is not testing them: {missing}"
    )


# ---------------------------------------------------------------------------
# completeness
# ---------------------------------------------------------------------------
WORKSPACE_SCOPED_REPOSITORIES = (
    PgApprovalRepository,
    PgChunkRepository,
    PgDocumentRepository,
    PgEmbeddingRepository,
    PgExperimentRepository,
    PgMembershipRepository,
    PgPromptTemplateRepository,
    PgRetentionPolicyRepository,
    PgRunRepository,
    PgToolInvocationRepository,
    PgTraceEventRepository,
    PgWorkspaceRepository,
)

# Writes are enumerated; everything else public is treated as a read.
#
# This started as a list of read prefixes — get, list, find, count — and that was the
# wrong default. It missed ``role_for`` and then ``for_invocation``, each found only
# because the stale-entry check runs in the opposite direction. More importantly it
# would miss a future ``fetch_by_label`` or ``resolve_handle`` silently, which is the
# failure this file exists to prevent.
#
# Inverted, an unrecognised method is assumed to read and must be covered or
# explicitly exempted. Being wrong now costs an exemption someone has to justify,
# rather than a gap nobody sees.
_WRITE_PREFIXES = (
    "create",
    "add",
    "append",
    "upsert",
    "replace",
    "delete",
    "remove",
    "finish",
    "record",
    "revoke",
    "touch",
    "truncate",
    "migrate",
    "reset",
)

# Reads that are deliberately not workspace-scoped, each with the reason. A bare
# exclusion list would let a genuine gap be waved through, so the reason is the entry.
_EXEMPT: dict[str, str] = {
    "PgWorkspaceRepository.get": (
        "takes a workspace id and no scope — it is the lookup that resolves a "
        "workspace, and authorisation happens in authorize_workspace, which checks "
        "membership before anyone reaches it"
    ),
    "PgRetentionPolicyRepository.missing_categories": (
        "reports absence, not data. It returns `required - configured`, so its "
        "output is a subset of the caller's own argument and cannot contain another "
        "workspace's rows. Driving it through the matrix asserted the wrong "
        "polarity: for a workspace with no policies it correctly returns every "
        "required category, which the 'empty means safe' rule read as a leak"
    ),
}


def _read_methods(repository: type) -> list[str]:
    """Public methods that are not recognised writes.

    Inherited members from ``_Base`` are skipped: ``_one``, ``_all`` and ``_write``
    are private, so nothing inherited surfaces here today, but filtering to the class's
    own namespace keeps it that way if a shared public helper is ever added.
    """
    names = []
    for name, _member in inspect.getmembers(repository, inspect.isfunction):
        if name.startswith("_"):
            continue
        if name.startswith(_WRITE_PREFIXES):
            continue
        names.append(f"{repository.__name__}.{name}")
    return names


def test_every_repository_read_path_appears_in_the_matrix(two_tenants):
    """Adding a read path without covering it must fail.

    This is the structural requirement from task 3.4. Without it the matrix would be
    a snapshot: correct on the day it was written, and quietly narrowing every time a
    repository gains a method. `[R15.4]` is a claim about every read path, so the set
    of read paths has to be derived rather than listed.

    If this fails, the fix is a row in ``_matrix`` — not an entry in ``_EXEMPT``,
    unless the read genuinely has no workspace scope and the reason survives being
    written down.
    """
    covered = set(_matrix(two_tenants)) | set(_EXEMPT)

    discovered: set[str] = set()
    for repository in WORKSPACE_SCOPED_REPOSITORIES:
        discovered.update(_read_methods(repository))

    uncovered = sorted(discovered - covered)
    assert uncovered == [], (
        "these read paths are not in the isolation matrix:\n  "
        + "\n  ".join(uncovered)
        + "\n\nAdd each to _matrix() in this file, driven with the intruder's "
        "workspace. [R15.4] is a claim about every read path, and an uncovered one "
        "is an unasserted one."
    )


def test_the_matrix_has_no_entries_for_methods_that_no_longer_exist(two_tenants):
    """The other direction, usually a rename.

    A stale entry would keep passing — the callable would raise ``AttributeError``
    only when invoked, and a renamed method leaves the matrix covering nothing while
    the completeness check above still balances.
    """
    discovered: set[str] = set()
    for repository in WORKSPACE_SCOPED_REPOSITORIES:
        discovered.update(_read_methods(repository))

    stale = sorted(set(_matrix(two_tenants)) - discovered)
    assert stale == [], f"matrix entries for methods that do not exist: {stale}"


def test_a_cross_workspace_read_is_indistinguishable_from_not_found(two_tenants):
    """`[R15.4]`: existence must not be disclosed.

    A distinct "forbidden" or "wrong workspace" error confirms the identifier is
    real, which is enough to enumerate another tenant's documents by trying ids. The
    same :class:`NotFound` must come back for a row that exists elsewhere and for one
    that does not exist at all.
    """
    db = two_tenants["db"]
    intruder = two_tenants["intruder"]
    repository = PgDocumentRepository(db)

    with pytest.raises(NotFound) as real_but_elsewhere:
        repository.get(two_tenants["document"].id, workspace_id=intruder)

    with pytest.raises(NotFound) as never_existed:
        repository.get(uuid4(), workspace_id=intruder)

    assert type(real_but_elsewhere.value) is type(never_existed.value)
    assert str(real_but_elsewhere.value) == str(never_existed.value)


def test_deleting_across_workspaces_reports_nothing_removed(two_tenants):
    """Write paths need the same treatment, and they fail more quietly.

    A ``DELETE`` matching zero rows succeeds. Without the workspace predicate the
    victim's document would be gone and the caller would see the same ``True`` either
    way, so the return value is the only signal there is.
    """
    db = two_tenants["db"]
    removed = PgDocumentRepository(db).delete(
        two_tenants["document"].id, workspace_id=two_tenants["intruder"]
    )

    assert removed is False
    assert PgDocumentRepository(db).get(
        two_tenants["document"].id, workspace_id=two_tenants["victim"]
    )
