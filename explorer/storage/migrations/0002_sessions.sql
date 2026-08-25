-- 0002_sessions — server-side sessions.  Task 3.1.
--
-- Server-side rather than a signed token carrying claims.  A signed token cannot be
-- revoked before it expires: disabling an account, removing a membership or changing
-- a role would all take effect only at the token's next issue.  [R15.2] makes role a
-- gate on approval authority and on tokenization reversal, and a gate that keeps
-- letting someone through for the rest of an hour is not a gate.
--
-- The cookie carries `id` and nothing else.  Everything about who the session belongs
-- to is looked up here, so a stolen cookie discloses no identity by itself and a
-- tampered one simply fails to resolve.
--
-- No workspace_id column, deliberately.  A session authenticates a person, not a
-- scope.  Storing "the current workspace" on the session is how a request ends up
-- reading whatever the last one touched -- the workspace has to arrive as a parameter
-- and be checked against membership on every call.

CREATE TABLE user_session (
    id            UUID PRIMARY KEY,
    user_id       UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,

    -- The SHA-256 of the bearer token, never the token.  A database read -- a
    -- backup, a log of a slow query, an errant SELECT -- must not yield anything
    -- that can be presented as a live session.
    --
    -- Plain SHA-256 rather than a KDF, unlike passwords: the token is 256 bits of
    -- CSPRNG output with no structure to guess, so there is no dictionary to slow
    -- down.  Stretching it would cost time on every authenticated request and buy
    -- nothing.
    token_sha256  CHAR(64) NOT NULL UNIQUE,

    created_at    TIMESTAMPTZ NOT NULL,
    expires_at    TIMESTAMPTZ NOT NULL,

    -- Set when the session is deliberately ended.  Kept rather than deleted so that
    -- "this session was revoked at 14:02" stays answerable; the sweeper removes rows
    -- once they are past retention.
    revoked_at    TIMESTAMPTZ,

    -- Last use, for idle timeout.  Separate from expires_at: a session has both an
    -- absolute lifetime and an idle one, and collapsing them means either a
    -- long-lived session that never re-authenticates or an active user thrown out
    -- mid-task.
    last_seen_at  TIMESTAMPTZ NOT NULL,

    -- Recorded for the audit trail, not used for authentication.  Binding a session
    -- to an address breaks every mobile network and every corporate egress pool, and
    -- the usual workaround is to disable the check.
    user_agent    TEXT,
    created_ip    TEXT,

    CONSTRAINT session_expires_after_creation CHECK (expires_at > created_at)
);

CREATE INDEX user_session_user_idx ON user_session (user_id);
CREATE INDEX user_session_expiry_idx ON user_session (expires_at);
