"""Password verification, sessions and authorization — tasks 3.1 and 3.2.

No database. Everything here is a pure function or a value object, which is the point
of keeping identity beneath the API rather than inside it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from explorer.security.identity import kdf
from explorer.security.identity.authorization import (
    Capability,
    NotPermitted,
    capabilities_for,
    permits,
    require,
    roles_with,
)
from explorer.security.identity.sessions import (
    DEFAULT_IDLE_TIMEOUT,
    build_session,
    generate_token,
    token_digest,
)
from explorer.storage.records import Role, SessionRecord

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# KDF
# ---------------------------------------------------------------------------
def test_a_password_verifies_against_its_own_hash():
    verifier = kdf.hash_password("a long enough passphrase")
    assert kdf.verify("a long enough passphrase", verifier) is True


def test_a_wrong_password_does_not_verify():
    verifier = kdf.hash_password("correct")
    assert kdf.verify("Correct", verifier) is False
    assert kdf.verify("correct ", verifier) is False
    assert kdf.verify("", verifier) is False


def test_the_same_password_hashes_differently_every_time():
    """Per-password salt, which is the whole value of salting.

    Equal verifiers for equal passwords would let one derivation be reused across
    every account that shares a common password, and would disclose which accounts
    those are by inspection of the table.
    """
    first = kdf.hash_password("shared")
    second = kdf.hash_password("shared")
    assert first != second
    assert kdf.verify("shared", first)
    assert kdf.verify("shared", second)


def test_the_verifier_records_its_own_parameters():
    """What makes raising the cost factor a gradual migration.

    Parameters in the row rather than in a module constant means an old verifier is
    checked at the parameters it was made with. In a constant, raising the cost would
    invalidate every stored password at once.
    """
    verifier = kdf.hash_password("x" * 20)
    assert verifier.startswith("scrypt$n=")
    assert kdf.describe(verifier) == f"scrypt n={kdf.DEFAULT_N} r=8 p=1"


def test_describe_never_reveals_the_salt_or_digest():
    """A health panel should be able to answer "which KDF" without a credential."""
    verifier = kdf.hash_password("secret value")
    salt_field, digest_field = verifier.split("$")[4], verifier.split("$")[5]

    described = kdf.describe(verifier)
    assert salt_field not in described
    assert digest_field not in described


def test_a_verifier_at_weaker_parameters_is_flagged_for_rehash():
    weak = kdf.hash_password("x" * 20, parameters=kdf.KdfParameters(n=1 << 14))
    current = kdf.hash_password("x" * 20)

    assert kdf.needs_rehash(weak) is True
    assert kdf.needs_rehash(current) is False
    # And it still verifies, at its own parameters. Otherwise raising the cost factor
    # would lock everyone out rather than upgrading them.
    assert kdf.verify("x" * 20, weak) is True


@pytest.mark.parametrize(
    "broken",
    [
        "",
        "scrypt$n=1$r=1$p=1",
        "bcrypt$n=1$r=1$p=1$c2FsdA==$ZGlnZXN0",
        "scrypt$n=notanumber$r=8$p=1$c2FsdA==$ZGlnZXN0",
        "scrypt$n=1024$r=8$p=1$!!!notbase64$ZGlnZXN0",
        "scrypt$n=1024$r=8$p=1$$ZGlnZXN0",
    ],
)
def test_a_malformed_verifier_raises_rather_than_failing_the_login(broken):
    """Corruption must not look like a typo.

    Reporting a malformed stored verifier as "wrong password" would let a truncating
    column or a bad migration hide indefinitely behind users blaming themselves.
    """
    with pytest.raises(kdf.InvalidVerifier):
        kdf.verify("anything", broken)


def test_an_over_length_password_is_refused_on_hash_and_rejected_on_verify():
    """Fixed KDF cost still leaves reading and hashing a huge input to pay for."""
    huge = "p" * (kdf.MAX_PASSWORD_BYTES + 1)
    with pytest.raises(ValueError, match="exceeds"):
        kdf.hash_password(huge)

    # On verify it returns False rather than raising: length is attacker-controlled,
    # so raising would turn a request into a 500 and make the limit a noise generator.
    verifier = kdf.hash_password("normal")
    assert kdf.verify(huge, verifier) is False


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------
def test_tokens_are_unique_and_urlsafe():
    tokens = {generate_token() for _ in range(200)}
    assert len(tokens) == 200
    assert all(("/" not in t and "+" not in t) for t in tokens)


def test_the_stored_record_holds_a_digest_and_not_the_token():
    """The property the whole scheme rests on.

    A database read — a backup, a slow-query log, an errant SELECT — must yield
    nothing that can be replayed.
    """
    issued, record = build_session(user_id=uuid4(), now=NOW)

    assert record.token_sha256 == token_digest(issued.token)
    assert issued.token not in record.token_sha256
    # And no field of the record contains it.
    assert all(issued.token != str(value) for value in vars(record).values())


def test_the_issued_session_and_the_record_agree_on_identity():
    issued, record = build_session(user_id=uuid4(), now=NOW)
    assert issued.session_id == record.id
    assert issued.user_id == record.user_id
    assert issued.expires_at == record.expires_at


def test_a_fresh_session_is_usable():
    _, record = build_session(user_id=uuid4(), now=NOW)
    assert record.is_usable(now=NOW, idle_timeout=DEFAULT_IDLE_TIMEOUT)


def test_an_expired_session_is_not_usable():
    _, record = build_session(user_id=uuid4(), now=NOW, lifetime=timedelta(hours=1))
    assert not record.is_usable(
        now=NOW + timedelta(hours=1, seconds=1), idle_timeout=DEFAULT_IDLE_TIMEOUT
    )


def test_an_idle_session_is_not_usable_even_before_it_expires():
    """Two clocks, deliberately.

    Collapsing absolute lifetime and idle timeout gives either a session that never
    re-authenticates or an active user thrown out mid-task.
    """
    _, record = build_session(user_id=uuid4(), now=NOW, lifetime=timedelta(hours=12))
    later = NOW + timedelta(hours=2)

    assert later < record.expires_at
    assert not record.is_usable(now=later, idle_timeout=timedelta(hours=1))


def test_a_revoked_session_is_not_usable_regardless_of_its_clocks():
    _, record = build_session(user_id=uuid4(), now=NOW)
    revoked = SessionRecord(**{**vars(record), "revoked_at": NOW})

    assert not revoked.is_usable(now=NOW, idle_timeout=DEFAULT_IDLE_TIMEOUT)


def test_a_zero_lifetime_session_is_refused_at_construction():
    with pytest.raises(ValueError, match="zero lifetime"):
        SessionRecord(
            id=uuid4(),
            user_id=uuid4(),
            token_sha256="f" * 64,
            created_at=NOW,
            expires_at=NOW,
            last_seen_at=NOW,
        )


def test_a_truncated_digest_is_refused_at_construction():
    """Two different tokens must not be able to collide through a short column."""
    with pytest.raises(ValueError, match="64 hex characters"):
        SessionRecord(
            id=uuid4(),
            user_id=uuid4(),
            token_sha256="f" * 32,
            created_at=NOW,
            expires_at=NOW + timedelta(hours=1),
            last_seen_at=NOW,
        )


# ---------------------------------------------------------------------------
# authorization
# ---------------------------------------------------------------------------
def test_a_non_member_has_no_capabilities():
    """The important case. A default role here would grant access to everyone."""
    assert capabilities_for(None) == frozenset()
    assert not permits(None, Capability.READ)


def test_every_role_may_read():
    for role in Role:
        assert permits(role, Capability.READ), role


def test_only_admin_may_reverse_tokenization():
    """`[R13.5]`. Asserted against the grant table rather than restating it.

    Restating the expected set here would let the assertion drift from the
    implementation while continuing to pass.
    """
    assert roles_with(Capability.REVERSE_TOKENIZATION) == frozenset({Role.ADMIN})


def test_a_reader_cannot_run_an_experiment_or_approve():
    assert not permits(Role.READER, Capability.RUN_EXPERIMENT)
    assert not permits(Role.READER, Capability.APPROVE)


def test_an_author_cannot_approve_and_an_approver_cannot_write():
    """Separation of duty, enforced rather than audited afterwards.

    Someone who both prepares a request and approves it has defeated the gate. This is
    also why the grant table is explicit per role: with an ordered enum, approver would
    inherit author's write capability automatically and this test would be impossible
    to satisfy.
    """
    assert not permits(Role.AUTHOR, Capability.APPROVE)
    assert not permits(Role.APPROVER, Capability.WRITE_CONTENT)


def test_deleting_content_is_not_an_authors_to_do():
    """Cascade deletion is irreversible `[R14.5]`, so it sits with admin."""
    assert roles_with(Capability.DELETE_CONTENT) == frozenset({Role.ADMIN})


def test_require_names_the_role_and_the_capability_when_it_refuses():
    with pytest.raises(NotPermitted, match="reader may not approve"):
        require(Role.READER, Capability.APPROVE)

    with pytest.raises(NotPermitted, match="non-member may not read"):
        require(None, Capability.READ)


def test_every_capability_is_granted_to_at_least_one_role():
    """An unreachable capability is either dead code or a missing grant.

    Both are worth finding: the second means a feature nobody can use, and it
    presents as a permission bug reported by a user.
    """
    unreachable = [c for c in Capability if not roles_with(c)]
    assert unreachable == []
