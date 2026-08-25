"""The authenticated workspace scope — task 3.3.

`[R15.3]` requires the workspace predicate to be in the query rather than applied to
results. The repositories already do that. What is missing is the step before it:
deciding *which* workspace a caller may name.

:class:`WorkspaceScope` is that step, and it can only be obtained by presenting an
authenticated identity together with a workspace the caller has named. Membership is
checked at that moment, and the resulting object carries the workspace id and the
capabilities that follow from the role.

Why a scope object rather than a decorator or middleware
--------------------------------------------------------

Middleware that stashes the workspace somewhere ambient would remove a parameter from
every call site. It would also mean that reading the code tells you nothing about
which workspace a query ran against, and the answer would depend on what some earlier
frame did. `[R15.4]` asks for a cross-workspace read to be impossible, and that is not
assertable when the scope is invisible at the point of use.

The scope is a value that has to be passed. Its ``workspace_id`` is what goes into the
query. A function without one cannot read anything.

What this is not
----------------

Not a repository wrapper. It deliberately does not proxy the repositories, because a
proxy invites the assumption that going through it is what makes a query safe — and
then a caller that reaches a repository directly looks like a shortcut rather than a
bug. Repositories require ``workspace_id`` regardless; the scope is where that value
is *legitimately obtained*.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from explorer.security.identity.authorization import (
    Capability,
    NotPermitted,
    capabilities_for,
    require,
)
from explorer.security.identity.kdf import verify
from explorer.security.identity.sessions import (
    DEFAULT_IDLE_TIMEOUT,
    Authenticated,
    AuthenticationFailed,
    token_digest,
)
from explorer.storage.protocols import NotFound
from explorer.storage.records import Role, SessionRecord


@dataclass(frozen=True)
class WorkspaceScope:
    """An authenticated identity, scoped to one workspace it belongs to.

    Constructed only by :func:`authorize_workspace`. Holding one is proof that
    membership was checked; it is not proof of any particular capability, which is
    what :meth:`require` is for.
    """

    user_id: UUID
    session_id: UUID
    workspace_id: UUID
    role: Role
    capabilities: frozenset[Capability]

    def permits(self, capability: Capability) -> bool:
        return capability in self.capabilities

    def require(self, capability: Capability) -> None:
        """Raise :class:`NotPermitted` unless the capability is held."""
        require(self.role, capability)


def authenticate_password(
    *,
    email: str,
    password: str,
    users,
    now: datetime | None = None,
) -> UUID:
    """Verify credentials, returning the user id.

    Every failure raises the same :class:`AuthenticationFailed`. Distinguishing an
    unknown address from a wrong password turns the form into an account-existence
    oracle.

    A wasted derivation runs when the account does not exist, so a missing address and
    a wrong password take comparable time. Without it, the response time answers the
    question the identical error message refuses to.
    """
    del now  # accepted for symmetry with the rest of the module
    user = users.find_by_email(email)

    if user is None:
        # Deliberate work against a fixed verifier. The result is discarded.
        verify(password, _TIMING_EQUALISER)
        raise AuthenticationFailed(f"no account for {email!r}")

    if not verify(password, user.password_verifier):
        raise AuthenticationFailed(f"wrong password for user {user.id}")

    if user.disabled:
        # Checked after verification, so a disabled account is not distinguishable
        # from a wrong password by timing either.
        raise AuthenticationFailed(f"account {user.id} is disabled")

    return user.id


def resolve_session(
    *,
    token: str,
    sessions,
    now: datetime | None = None,
    idle_timeout: timedelta = DEFAULT_IDLE_TIMEOUT,
) -> Authenticated:
    """Turn a bearer token into an authenticated identity.

    Looks up by digest, never by token. Expiry, revocation and idle timeout are all
    checked here rather than left to the query, so a repository that forgets a
    predicate cannot produce a usable session.
    """
    moment = now or datetime.now(UTC)
    record: SessionRecord | None = sessions.find_by_token_digest(token_digest(token))

    if record is None:
        raise AuthenticationFailed("no such session")
    if not record.is_usable(now=moment, idle_timeout=idle_timeout):
        raise AuthenticationFailed(f"session {record.id} is expired or revoked")

    sessions.touch(record.id, seen_at=moment)
    return Authenticated(user_id=record.user_id, session_id=record.id)


def authorize_workspace(
    identity: Authenticated,
    workspace_id: UUID,
    *,
    memberships,
) -> WorkspaceScope:
    """Check membership and build a scope.

    A non-member raises :class:`NotFound`, not :class:`NotPermitted`. `[R15.4]`
    requires a cross-workspace attempt to be indistinguishable from not-found, and
    "forbidden" would confirm the workspace exists — which is enough to enumerate
    tenants by trying identifiers.
    """
    role = memberships.role_for(workspace_id=workspace_id, user_id=identity.user_id)
    if role is None:
        raise NotFound("no such workspace")

    return WorkspaceScope(
        user_id=identity.user_id,
        session_id=identity.session_id,
        workspace_id=workspace_id,
        role=role,
        capabilities=capabilities_for(role),
    )


# A fixed verifier of a value no password will match, used only to spend comparable
# time when an account does not exist. Generated at import so the parameters track
# DEFAULT_N automatically; a hardcoded string would silently stop matching the real
# cost after the first time those parameters are raised, and the timing channel would
# quietly reopen.
def _build_timing_equaliser() -> str:
    from explorer.security.identity.kdf import hash_password

    import secrets as _secrets

    return hash_password(_secrets.token_urlsafe(32))


_TIMING_EQUALISER = _build_timing_equaliser()

__all__ = [
    "AuthenticationFailed",
    "Capability",
    "NotPermitted",
    "WorkspaceScope",
    "authenticate_password",
    "authorize_workspace",
    "resolve_session",
]
