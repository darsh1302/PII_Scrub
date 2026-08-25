"""Server-side sessions — task 3.1.

The token is generated once, returned once, and never stored. What is stored is its
SHA-256. A database read — a backup, a slow-query log, an errant ``SELECT *`` — must
not yield anything that can be replayed as a live session.

Two clocks, not one. ``expires_at`` is an absolute lifetime; idle timeout is a
separate check against ``last_seen_at``. Collapsing them gives either a session that
never re-authenticates or an active user thrown out mid-task, and the usual response
to the latter is to extend the absolute lifetime until it stops mattering.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from explorer.storage.records import SessionRecord

TOKEN_BYTES = 32
"""256 bits of CSPRNG output. No structure, so no dictionary — which is why the
stored form is a plain digest rather than a KDF."""

DEFAULT_LIFETIME = timedelta(hours=12)
DEFAULT_IDLE_TIMEOUT = timedelta(hours=1)


class AuthenticationFailed(Exception):
    """A session could not be established or resolved.

    One exception for every cause: unknown user, wrong password, disabled account,
    expired session, revoked session, unknown token. The reason is logged, never
    returned. Distinguishing "no such account" from "wrong password" turns the login
    form into an account-existence oracle, which is the first step of a credential
    stuffing run.
    """


@dataclass(frozen=True)
class IssuedSession:
    """A new session. ``token`` exists only here and only once.

    Separate from the stored record on purpose: there is no type in the system that
    holds both a live token and a persisted row, so no code path can accidentally
    save one or log the other.
    """

    session_id: UUID
    user_id: UUID
    token: str
    expires_at: datetime


@dataclass(frozen=True)
class Authenticated:
    """The result of resolving a session token.

    Deliberately carries no workspace. An authenticated identity is not a scope —
    :mod:`explorer.security.identity.scope` turns this into one, and only by checking
    membership for a workspace the caller names.
    """

    user_id: UUID
    session_id: UUID


def generate_token() -> str:
    """A bearer token. URL-safe so it survives a cookie and a header unchanged."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def token_digest(token: str) -> str:
    """The stored form. Lowercase hex, matching the ``CHAR(64)`` column."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def build_session(
    *,
    user_id: UUID,
    now: datetime | None = None,
    lifetime: timedelta = DEFAULT_LIFETIME,
    user_agent: str | None = None,
    created_ip: str | None = None,
) -> tuple[IssuedSession, SessionRecord]:
    """Mint a session, returning the token and the row to store.

    Returns both halves rather than writing anything, so this stays testable without a
    database and so the caller decides the transaction boundary. The token appears in
    the first value and the digest in the second; there is no object holding both.
    """
    moment = now or datetime.now(UTC)
    token = generate_token()
    session_id = uuid4()
    expires_at = moment + lifetime

    issued = IssuedSession(
        session_id=session_id,
        user_id=user_id,
        token=token,
        expires_at=expires_at,
    )
    record = SessionRecord(
        id=session_id,
        user_id=user_id,
        token_sha256=token_digest(token),
        created_at=moment,
        expires_at=expires_at,
        last_seen_at=moment,
        user_agent=user_agent,
        created_ip=created_ip,
    )
    return issued, record
