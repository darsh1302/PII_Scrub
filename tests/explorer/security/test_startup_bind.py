"""The conditional non-loopback bind — task 3.5, `[R15.5]`.

The requirement lifts an absolute refusal into a conditional one. The risk in that
change is a condition that is satisfied by the code existing rather than by
authentication being in force, so most of these tests assert refusal.
"""

from __future__ import annotations

import pytest

from explorer.security.identity.startup import (
    DEFAULT_BIND_ADDRESS,
    evaluate_bind,
    evaluate_bind_from_database,
    is_loopback,
)
from explorer.security.identity.kdf import hash_password
from explorer.storage.engine import Database
from explorer.storage.postgres import PgUserRepository
from explorer.storage.records import User
from tests.explorer.conftest import requires_database
from tests.explorer.storage import builders


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "127.0.0.53", "::1", "localhost", ""],
)
def test_loopback_addresses_are_recognised(address):
    assert is_loopback(address) is True


@pytest.mark.parametrize(
    "address",
    ["0.0.0.0", "10.0.0.5", "192.168.1.10", "::", "2001:db8::1"],
)
def test_non_loopback_addresses_are_recognised(address):
    assert is_loopback(address) is False


@pytest.mark.parametrize("address", ["example.com", "not an address", "10.0.0.999"])
def test_an_unparseable_address_is_treated_as_non_loopback(address):
    """A name this cannot reason about must not be assumed safe.

    DNS can point a friendly hostname anywhere, so "I could not parse it" has to fall
    on the cautious side. Defaulting the other way would make ``internal.corp`` bypass
    the whole check.
    """
    assert is_loopback(address) is False


def test_a_loopback_bind_is_always_permitted():
    decision = evaluate_bind(address=DEFAULT_BIND_ADDRESS)
    assert decision.permitted is True
    assert decision.is_loopback is True
    assert decision.blockers == ()


def test_a_loopback_bind_needs_no_authentication_at_all():
    """Local development must not require an account to start.

    If it did, the first thing anyone would do is set the bypass — and then it would be
    set in the one environment where it matters.
    """
    decision = evaluate_bind(
        address="127.0.0.1",
        auth_enabled=False,
        sessions_table_present=False,
        account_count=0,
    )
    assert decision.permitted is True


def test_a_non_loopback_bind_is_refused_by_default():
    """The important default. Every input omitted means refusal."""
    decision = evaluate_bind(address="0.0.0.0")
    assert decision.permitted is False
    assert len(decision.blockers) == 3


def test_a_non_loopback_bind_is_refused_when_auth_is_not_enabled():
    decision = evaluate_bind(
        address="10.0.0.5",
        auth_enabled=False,
        sessions_table_present=True,
        account_count=5,
    )
    assert decision.permitted is False
    assert any("AUTH_ENABLED" in b for b in decision.blockers)


def test_a_non_loopback_bind_is_refused_without_the_sessions_table():
    """Authentication enabled but unmigrated is authentication that cannot record
    a login."""
    decision = evaluate_bind(
        address="10.0.0.5",
        auth_enabled=True,
        sessions_table_present=False,
        account_count=5,
    )
    assert decision.permitted is False
    assert any("user_session" in b for b in decision.blockers)


def test_a_non_loopback_bind_is_refused_with_no_accounts():
    """The condition most likely to be argued about.

    An empty user table with a first-run setup flow is a common pattern and a common
    breach: the setup flow is reachable by whoever finds the port first.
    """
    decision = evaluate_bind(
        address="10.0.0.5",
        auth_enabled=True,
        sessions_table_present=True,
        account_count=0,
    )
    assert decision.permitted is False
    assert any("no accounts exist" in b for b in decision.blockers)


def test_a_non_loopback_bind_is_permitted_when_all_three_hold():
    decision = evaluate_bind(
        address="10.0.0.5",
        auth_enabled=True,
        sessions_table_present=True,
        account_count=1,
    )
    assert decision.permitted is True
    assert decision.blockers == ()
    assert "authentication enabled" in decision.message()


def test_the_refusal_message_names_every_outstanding_condition():
    """An operator should be able to fix this without reading the source."""
    decision = evaluate_bind(address="0.0.0.0")
    message = decision.message()

    assert "Refusing to bind 0.0.0.0" in message
    assert "R15.5" in message
    assert DEFAULT_BIND_ADDRESS in message
    for blocker in decision.blockers:
        assert blocker in message


def test_environment_variables_are_read_when_arguments_are_omitted(monkeypatch):
    monkeypatch.setenv("EXPLORER_BIND_ADDRESS", "0.0.0.0")
    monkeypatch.setenv("EXPLORER_AUTH_ENABLED", "true")

    decision = evaluate_bind(sessions_table_present=True, account_count=1)
    assert decision.address == "0.0.0.0"
    assert decision.permitted is True


@pytest.mark.parametrize("value", ["", "false", "yes", "1", "True "])
def test_only_the_exact_string_true_enables_authentication(monkeypatch, value):
    """``yes`` and ``1`` are not accepted, deliberately.

    A permissive parse means a typo in a deployment variable silently opens the port.
    ``True `` with trailing whitespace is stripped and lowercased, so it does pass —
    which is why it is listed here as the one exception worth knowing about.
    """
    monkeypatch.setenv("EXPLORER_AUTH_ENABLED", value)
    decision = evaluate_bind(
        address="10.0.0.5", sessions_table_present=True, account_count=1
    )
    assert decision.permitted is (value.strip().lower() == "true")


@requires_database
def test_the_database_variant_refuses_an_empty_user_table(migrated_database: Database):
    database = migrated_database
    database.truncate_all()

    decision = evaluate_bind_from_database(database, address="0.0.0.0")
    assert decision.permitted is False
    assert any("no accounts exist" in b for b in decision.blockers)


@requires_database
def test_the_database_variant_counts_only_enabled_accounts(
    migrated_database: Database, monkeypatch
):
    """A disabled account is not a way in, so it does not satisfy the condition.

    Otherwise suspending the only account would leave the port open with nobody able
    to log in — the worst of both.
    """
    monkeypatch.setenv("EXPLORER_AUTH_ENABLED", "true")
    database = migrated_database
    database.truncate_all()

    users = PgUserRepository(database)
    users.create(
        User(
            id=builders.uuid4(),
            email="suspended@example.test",
            password_verifier=hash_password("irrelevant"),
            created_at=builders.NOW,
            disabled=True,
        )
    )

    decision = evaluate_bind_from_database(database, address="0.0.0.0")
    assert decision.permitted is False

    users.create(
        User(
            id=builders.uuid4(),
            email="active@example.test",
            password_verifier=hash_password("irrelevant"),
            created_at=builders.NOW,
        )
    )
    assert evaluate_bind_from_database(database, address="0.0.0.0").permitted is True


@requires_database
def test_a_loopback_bind_queries_nothing(migrated_database: Database):
    """Local development must not need a reachable database to decide to start.

    Asserted by handing it an object that raises if touched.
    """

    class Exploding:
        def table_names(self):
            raise AssertionError("a loopback bind must not query the database")

        def execute_scalar(self, *_args, **_kwargs):
            raise AssertionError("a loopback bind must not query the database")

    decision = evaluate_bind_from_database(Exploding(), address="127.0.0.1")
    assert decision.permitted is True
