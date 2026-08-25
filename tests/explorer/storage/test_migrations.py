"""Migration discovery and the checksum guard — task 2.2."""

from __future__ import annotations

import pytest

from explorer.storage.engine import Database, MigrationError
from explorer.storage.migrations import Migration, discover
from tests.explorer.conftest import requires_database


def test_migrations_are_discovered_in_order():
    migrations = discover()
    assert migrations, "no migrations found"
    numbers = [m.number for m in migrations]
    assert numbers == sorted(numbers)


def test_migration_numbers_are_unique():
    numbers = [m.number for m in discover()]
    assert len(numbers) == len(set(numbers))


def test_checksum_ignores_line_endings():
    """Git may hand a contributor CRLF for a file committed with LF.

    A checksum sensitive to that would refuse a correct migration on Windows, and
    the practical result is someone disabling the check.
    """
    lf = Migration(number=1, name="x", path=discover()[0].path, sql="a\nb\n")
    crlf = Migration(number=1, name="x", path=discover()[0].path, sql="a\r\nb\r\n")
    assert lf.checksum == crlf.checksum


def test_checksum_changes_with_content():
    first = Migration(number=1, name="x", path=discover()[0].path, sql="a\n")
    second = Migration(number=1, name="x", path=discover()[0].path, sql="b\n")
    assert first.checksum != second.checksum


@requires_database
def test_migrate_is_idempotent(migrated_database: Database):
    """Safe to call on every startup, which is the only way it gets called."""
    applied_again = migrated_database.migrate()
    assert applied_again == []


@requires_database
def test_applied_migrations_are_recorded(migrated_database: Database):
    recorded = migrated_database.applied_migrations()
    expected = [m.identifier for m in discover()]
    assert recorded == sorted(expected)


@requires_database
def test_an_edited_applied_migration_is_refused(migrated_database, monkeypatch):
    """The check the runner exists for.

    Editing an already-applied migration is the most common way two machines
    diverge while both believe they are current, and the failures it produces appear
    nowhere near the cause.
    """
    real = discover()
    tampered = [
        Migration(
            number=real[0].number,
            name=real[0].name,
            path=real[0].path,
            sql=real[0].sql + "\n-- an innocent-looking edit\n",
        ),
        *real[1:],
    ]
    monkeypatch.setattr("explorer.storage.engine.discover", lambda: tampered)

    with pytest.raises(MigrationError, match="files have since changed"):
        migrated_database.migrate()


@requires_database
def test_a_recorded_migration_with_no_file_is_refused(migrated_database, monkeypatch):
    """The same divergence from the other side, usually a branch switch."""
    monkeypatch.setattr("explorer.storage.engine.discover", lambda: [])

    with pytest.raises(MigrationError, match="no corresponding file"):
        migrated_database.migrate()
