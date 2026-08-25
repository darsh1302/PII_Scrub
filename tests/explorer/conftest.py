"""Explorer test fixtures, including the database.

The skip decision, and the guard on it
--------------------------------------

Storage tests need a real PostgreSQL. Where ``EXPLORER_TEST_DATABASE_URL`` is unset
they skip, so a contributor who has not run ``tools_dev/pg_local.py install`` is not
blocked from running the rest of the suite.

That is a dangerous accommodation, because the isolation matrix `[R15.4]` is among
the tests it would skip, and a skipped security test is indistinguishable from a
passing one in a summary line. ``tests/explorer/test_ci_configuration.py`` therefore
fails when ``CI`` is set and the URL is not. Locally the skip is a convenience; in
CI it is a failure.

That guard deliberately lives in a test *file*. pytest does not collect test
functions from ``conftest.py``, so putting it here would have produced exactly the
kind of assertion that never runs while appearing to — the same failure mode as a
renamed no-LLM test that no longer imports anything.

``load_dotenv`` runs at import time rather than in ``pytest_configure``, because
``requires_database`` below is evaluated when this module is imported. In
``pytest_configure`` it would run *after* that decision, leaving every storage test
skipped on a machine that is correctly configured — and skipped tests do not
announce themselves.

Migrations run once per session. Per-test DDL would make the suite dominated by
schema work; ``truncate_all`` between tests is fast and still gives each test an
empty database.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from uuid import uuid4

import pytest

try:  # pragma: no cover - dotenv is pinned, this is belt and braces
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

from explorer.storage import config
from explorer.storage.engine import Database


def database_available() -> bool:
    """Whether a test database is configured. Public, so the CI guard can use it."""
    return config.is_configured(testing=True)


def ci_is_set() -> bool:
    return bool(os.environ.get("CI"))


requires_database = pytest.mark.skipif(
    not database_available(),
    reason=(
        "EXPLORER_TEST_DATABASE_URL is not set. Run:\n"
        "  python tools_dev/pg_local.py install\n"
        "  python tools_dev/pg_local.py start"
    ),
)


@pytest.fixture(scope="session")
def migrated_database() -> Database:
    """A database with the schema applied, once for the session."""
    if not database_available():
        pytest.skip("EXPLORER_TEST_DATABASE_URL is not set")

    database = Database.from_env(testing=True)
    database.migrate()
    return database


@pytest.fixture
def db(migrated_database: Database) -> Iterator[Database]:
    """An empty database for one test.

    Truncated before rather than after, so a failing test leaves its rows behind for
    inspection while the next test still starts clean.
    """
    migrated_database.truncate_all()
    yield migrated_database


@pytest.fixture
def workspace_id():
    return uuid4()


@pytest.fixture
def other_workspace_id():
    """A second workspace, for the isolation assertions.

    Every read test taking this fixture asserts that data seeded under
    ``workspace_id`` is unreachable with this one.
    """
    return uuid4()


@pytest.fixture
def object_store_root(tmp_path: Path) -> Path:
    return tmp_path / "object_store"
