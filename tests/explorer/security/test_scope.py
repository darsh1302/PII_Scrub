"""Login, session resolution and workspace scoping — tasks 3.1 and 3.3.

Against a real database, because the point of these paths is what they do with stored
state: a revoked row, an expired row, a membership that does not exist.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from explorer.security.identity.authorization import Capability, NotPermitted
from explorer.security.identity.kdf import hash_password
from explorer.security.identity.scope import (
    AuthenticationFailed,
    authenticate_password,
    authorize_workspace,
    resolve_session,
)
from explorer.security.identity.sessions import build_session
from explorer.storage.engine import Database
from explorer.storage.postgres import (
    PgMembershipRepository,
    PgSessionRepository,
    PgUserRepository,
    PgWorkspaceRepository,
)
from explorer.storage.protocols import NotFound
from explorer.storage.records import Role, User
from tests.explorer.conftest import requires_database
from tests.explorer.storage import builders

pytestmark = requires_database

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
PASSWORD = "a reasonable passphrase"


@pytest.fixture
def account(db: Database, workspace_id, other_workspace_id):
    """One user, member of ``workspace_id`` as an author, not of the other."""
    PgWorkspaceRepository(db).create(builders.workspace(workspace_id, name="mine"))
    PgWorkspaceRepository(db).create(
        builders.workspace(other_workspace_id, name="theirs")
    )

    person = User(
        id=uuid4(),
        email="lena@example.test",
        password_verifier=hash_password(PASSWORD),
        created_at=NOW,
    )
    PgUserRepository(db).create(person)
    PgMembershipRepository(db).add(
        builders.membership(workspace_id, person.id, role=Role.AUTHOR)
    )
    return person


# ---------------------------------------------------------------------------
# password authentication
# ---------------------------------------------------------------------------
def test_correct_credentials_return_the_user_id(db: Database, account):
    assert authenticate_password(
        email="lena@example.test", password=PASSWORD, users=PgUserRepository(db)
    ) == account.id


def test_the_email_lookup_is_case_insensitive(db: Database, account):
    assert authenticate_password(
        email="LENA@Example.TEST", password=PASSWORD, users=PgUserRepository(db)
    ) == account.id


def test_a_wrong_password_and_an_unknown_account_fail_identically(db: Database, account):
    """`[R15.1]`, and the reason the error carries no detail.

    Distinguishing the two turns the login form into an account-existence oracle,
    which is the first step of credential stuffing: confirm which addresses are real,
    then spend the guesses only on those.
    """
    users = PgUserRepository(db)

    with pytest.raises(AuthenticationFailed) as wrong_password:
        authenticate_password(
            email="lena@example.test", password="not it", users=users
        )
    with pytest.raises(AuthenticationFailed) as no_account:
        authenticate_password(
            email="nobody@example.test", password=PASSWORD, users=users
        )

    assert type(wrong_password.value) is type(no_account.value)


def test_a_disabled_account_cannot_authenticate(db: Database):
    person = User(
        id=uuid4(),
        email="suspended@example.test",
        password_verifier=hash_password(PASSWORD),
        created_at=NOW,
        disabled=True,
    )
    PgUserRepository(db).create(person)

    with pytest.raises(AuthenticationFailed):
        authenticate_password(
            email="suspended@example.test",
            password=PASSWORD,
            users=PgUserRepository(db),
        )


def test_an_unknown_account_still_costs_a_derivation(db: Database):
    """The timing half of the identical-error property.

    Returning early for an unknown address makes the response time answer the question
    the error message refuses to. Asserted as a ratio rather than an absolute, and
    generously, because this machine's wall-clock variance is high — the assertion is
    that work happens at all, not that the two are indistinguishable to a stopwatch.
    """
    import time

    users = PgUserRepository(db)
    person = User(
        id=uuid4(),
        email="present@example.test",
        password_verifier=hash_password(PASSWORD),
        created_at=NOW,
    )
    users.create(person)

    def elapsed(email: str) -> float:
        start = time.perf_counter()
        with pytest.raises(AuthenticationFailed):
            authenticate_password(email=email, password="wrong", users=users)
        return time.perf_counter() - start

    known = min(elapsed("present@example.test") for _ in range(3))
    unknown = min(elapsed("absent@example.test") for _ in range(3))

    assert unknown > known / 4, (
        f"an unknown account took {unknown:.4f}s against {known:.4f}s for a known "
        f"one — the early return has reopened the timing channel"
    )


# ---------------------------------------------------------------------------
# session resolution
# ---------------------------------------------------------------------------
def test_a_fresh_token_resolves_to_its_user(db: Database, account):
    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)

    identity = resolve_session(token=issued.token, sessions=sessions, now=NOW)
    assert identity.user_id == account.id
    assert identity.session_id == issued.session_id


def test_an_unknown_token_is_refused(db: Database, account):
    with pytest.raises(AuthenticationFailed, match="no such session"):
        resolve_session(token="not a real token", sessions=PgSessionRepository(db))


def test_a_revoked_session_stops_working_immediately(db: Database, account):
    """The reason sessions are server-side rather than signed tokens.

    A signed token cannot be revoked before it expires, so disabling an account or
    removing a role would take effect only at the next issue — and `[R15.2]` makes
    role a gate on approval authority.
    """
    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)

    assert sessions.revoke(issued.session_id, at=NOW) is True

    with pytest.raises(AuthenticationFailed, match="expired or revoked"):
        resolve_session(token=issued.token, sessions=sessions, now=NOW)


def test_revoking_all_sessions_for_a_user_ends_every_one(db: Database, account):
    """Needed by three flows that mean the same thing: password change, account
    disabled, suspected compromise."""
    sessions = PgSessionRepository(db)
    tokens = []
    for _ in range(3):
        issued, record = build_session(user_id=account.id, now=NOW)
        sessions.create(record)
        tokens.append(issued.token)

    assert sessions.count_live_for_user(account.id, now=NOW) == 3
    assert sessions.revoke_all_for_user(account.id, at=NOW) == 3
    assert sessions.count_live_for_user(account.id, now=NOW) == 0

    for token in tokens:
        with pytest.raises(AuthenticationFailed):
            resolve_session(token=token, sessions=sessions, now=NOW)


def test_revoking_twice_keeps_the_first_revocation_time(db: Database, account):
    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)

    sessions.revoke(issued.session_id, at=NOW)
    assert sessions.revoke(issued.session_id, at=NOW + timedelta(hours=1)) is False
    assert sessions.get(issued.session_id).revoked_at == NOW


def test_resolving_a_session_updates_last_seen_but_not_expiry(db: Database, account):
    """Sliding the absolute lifetime would make a frequently used session permanent."""
    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)

    later = NOW + timedelta(minutes=30)
    resolve_session(token=issued.token, sessions=sessions, now=later)

    stored = sessions.get(issued.session_id)
    assert stored.last_seen_at == later
    assert stored.expires_at == record.expires_at


def test_an_expired_session_is_refused(db: Database, account):
    sessions = PgSessionRepository(db)
    issued, record = build_session(
        user_id=account.id, now=NOW, lifetime=timedelta(minutes=5)
    )
    sessions.create(record)

    with pytest.raises(AuthenticationFailed, match="expired or revoked"):
        resolve_session(
            token=issued.token, sessions=sessions, now=NOW + timedelta(minutes=6)
        )


def test_expired_sessions_are_removable_by_the_sweeper(db: Database, account):
    """Retention, not tidiness. A session row names a person and when they were
    active, which is exactly what `[R14.3]` wants a clock on."""
    sessions = PgSessionRepository(db)
    _, expired = build_session(user_id=account.id, now=NOW, lifetime=timedelta(hours=1))
    sessions.create(expired)
    _, live = build_session(
        user_id=account.id, now=NOW + timedelta(hours=2), lifetime=timedelta(hours=12)
    )
    sessions.create(live)

    removed = sessions.delete_expired(before=NOW + timedelta(hours=2))
    assert removed == 1
    assert sessions.get(live.id)


# ---------------------------------------------------------------------------
# workspace scoping
# ---------------------------------------------------------------------------
def test_a_member_gets_a_scope_carrying_their_role_and_capabilities(
    db: Database, account, workspace_id
):
    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)
    identity = resolve_session(token=issued.token, sessions=sessions, now=NOW)

    scope = authorize_workspace(
        identity, workspace_id, memberships=PgMembershipRepository(db)
    )

    assert scope.workspace_id == workspace_id
    assert scope.role is Role.AUTHOR
    assert scope.permits(Capability.WRITE_CONTENT)
    assert not scope.permits(Capability.APPROVE)


def test_a_non_member_gets_not_found_rather_than_forbidden(
    db: Database, account, other_workspace_id
):
    """`[R15.4]`: existence must not be disclosed.

    "Forbidden" would confirm the workspace is real, which is enough to enumerate
    tenants by trying identifiers. This is why ``authorize_workspace`` raises
    ``NotFound`` and not ``NotPermitted``.
    """
    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)
    identity = resolve_session(token=issued.token, sessions=sessions, now=NOW)

    with pytest.raises(NotFound):
        authorize_workspace(
            identity, other_workspace_id, memberships=PgMembershipRepository(db)
        )


def test_a_workspace_that_does_not_exist_is_also_not_found(db: Database, account):
    """Same failure for a fabricated id, so the two are indistinguishable."""
    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)
    identity = resolve_session(token=issued.token, sessions=sessions, now=NOW)

    with pytest.raises(NotFound):
        authorize_workspace(
            identity, uuid4(), memberships=PgMembershipRepository(db)
        )


def test_the_scope_refuses_a_capability_the_role_lacks(
    db: Database, account, workspace_id
):
    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)
    identity = resolve_session(token=issued.token, sessions=sessions, now=NOW)
    scope = authorize_workspace(
        identity, workspace_id, memberships=PgMembershipRepository(db)
    )

    scope.require(Capability.WRITE_CONTENT)  # held, no raise
    with pytest.raises(NotPermitted):
        scope.require(Capability.REVERSE_TOKENIZATION)


def test_the_same_person_gets_different_capabilities_in_two_workspaces(
    db: Database, account, workspace_id, other_workspace_id
):
    """`[R15.2]`, end to end.

    The reason role lives on membership rather than on the user. A role on the user
    could not express this, and the approval gate would then be workspace-blind.
    """
    memberships = PgMembershipRepository(db)
    memberships.add(
        builders.membership(other_workspace_id, account.id, role=Role.APPROVER)
    )

    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)
    identity = resolve_session(token=issued.token, sessions=sessions, now=NOW)

    here = authorize_workspace(identity, workspace_id, memberships=memberships)
    there = authorize_workspace(identity, other_workspace_id, memberships=memberships)

    assert here.permits(Capability.WRITE_CONTENT)
    assert not here.permits(Capability.APPROVE)
    assert there.permits(Capability.APPROVE)
    assert not there.permits(Capability.WRITE_CONTENT)


def test_a_scope_carries_no_way_to_change_its_workspace(
    db: Database, account, workspace_id
):
    """Frozen, so a scope cannot be re-pointed after the membership check.

    A mutable scope would let a later line move it to another workspace while every
    read still looked correctly parameterised.
    """
    import dataclasses

    sessions = PgSessionRepository(db)
    issued, record = build_session(user_id=account.id, now=NOW)
    sessions.create(record)
    identity = resolve_session(token=issued.token, sessions=sessions, now=NOW)
    scope = authorize_workspace(
        identity, workspace_id, memberships=PgMembershipRepository(db)
    )

    with pytest.raises(dataclasses.FrozenInstanceError):
        scope.workspace_id = uuid4()  # type: ignore[misc]
