"""Connections and the migration runner.

A connection pool rather than a connection per call, and an explicit
``transaction()`` context manager rather than autocommit everywhere. Cascade
deletion spans several statements and a payload removal; half of it committing is
worse than none of it, because the surviving half is a chunk pointing at a document
that no longer exists.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import psycopg
from psycopg import sql
from psycopg.rows import dict_row

from explorer.storage import config
from explorer.storage.migrations import Migration, discover

log = logging.getLogger(__name__)

_MIGRATION_TABLE = "schema_migration"

_CREATE_MIGRATION_TABLE = f"""
CREATE TABLE IF NOT EXISTS {_MIGRATION_TABLE} (
    identifier   TEXT PRIMARY KEY,
    checksum     TEXT NOT NULL,
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""


class MigrationError(RuntimeError):
    """A migration cannot be applied safely."""


class Database:
    """A configured database, and the entry point to everything else.

    Not a singleton and not module-level state. Tests build one against
    ``EXPLORER_TEST_DATABASE_URL`` while the application holds another, and a
    module-level connection would make that impossible without monkeypatching.
    """

    def __init__(self, url: str) -> None:
        self._url = url

    @classmethod
    def from_env(cls, *, testing: bool = False) -> Database:
        return cls(config.database_url(testing=testing))

    @property
    def url_for_display(self) -> str:
        return config.redacted(self._url)

    @contextmanager
    def connect(self) -> Iterator[psycopg.Connection]:
        """A connection with dict rows, autocommit off.

        ``dict_row`` because positional row access breaks silently when a column
        is added in the middle of a SELECT list, and it breaks by returning the
        wrong value rather than by raising.
        """
        with psycopg.connect(self._url, row_factory=dict_row) as conn:
            yield conn

    @contextmanager
    def transaction(self) -> Iterator[psycopg.Connection]:
        """A connection wrapped in one transaction, rolled back on error."""
        with self.connect() as conn, conn.transaction():
            yield conn

    # -----------------------------------------------------------------
    # migrations
    # -----------------------------------------------------------------
    def migrate(self) -> list[str]:
        """Apply pending migrations. Returns the identifiers applied.

        Idempotent, so it is safe on every startup. Each migration runs inside its
        own transaction together with the row recording it, which means a failure
        halfway leaves neither the schema change nor the claim that it happened.
        """
        migrations = discover()
        applied: list[str] = []

        with self.connect() as conn:
            conn.execute(_CREATE_MIGRATION_TABLE)
            conn.commit()
            recorded = self._recorded(conn)

            self._verify_checksums(migrations, recorded)

            for migration in migrations:
                if migration.identifier in recorded:
                    continue
                log.info("applying migration %s", migration.identifier)
                with conn.transaction():
                    conn.execute(migration.sql)  # type: ignore[arg-type]
                    conn.execute(
                        sql.SQL(
                            "INSERT INTO {} (identifier, checksum) VALUES (%s, %s)"
                        ).format(sql.Identifier(_MIGRATION_TABLE)),
                        (migration.identifier, migration.checksum),
                    )
                applied.append(migration.identifier)

        return applied

    def _recorded(self, conn: psycopg.Connection) -> dict[str, str]:
        rows = conn.execute(
            sql.SQL("SELECT identifier, checksum FROM {}").format(
                sql.Identifier(_MIGRATION_TABLE)
            )
        ).fetchall()
        return {row["identifier"]: row["checksum"] for row in rows}

    @staticmethod
    def _verify_checksums(
        migrations: list[Migration], recorded: dict[str, str]
    ) -> None:
        """Refuse when an applied migration's file has changed.

        This is the check the whole runner exists for. Editing a migration that has
        already run is the most common way two machines diverge while both believe
        they are current, and the resulting failures appear nowhere near the cause.
        """
        drifted = [
            m
            for m in migrations
            if m.identifier in recorded and recorded[m.identifier] != m.checksum
        ]
        if drifted:
            listing = "\n  ".join(
                f"{m.identifier} ({m.path.name})" for m in drifted
            )
            raise MigrationError(
                "these migrations have already been applied but their files have "
                f"since changed:\n  {listing}\n\n"
                "The schema in this database is not what the file describes. Add a "
                "new numbered migration instead of editing an applied one. To "
                "start over on a development database, drop it and re-run "
                "migrate()."
            )

        # An identifier in the database with no file is the same divergence seen
        # from the other side, usually a branch switch.
        orphans = sorted(set(recorded) - {m.identifier for m in migrations})
        if orphans:
            raise MigrationError(
                f"the database records migrations with no corresponding file: "
                f"{', '.join(orphans)}. This database is ahead of the working "
                f"tree — check the branch before doing anything else."
            )

    def applied_migrations(self) -> list[str]:
        with self.connect() as conn:
            conn.execute(_CREATE_MIGRATION_TABLE)
            conn.commit()
            return sorted(self._recorded(conn))

    # -----------------------------------------------------------------
    # test support
    # -----------------------------------------------------------------
    def table_names(self) -> set[str]:
        """Every table in the public schema, migration bookkeeping excluded.

        Used by the classification test: a table that exists without a
        classification fails the suite [R14.1].
        """
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                """
            ).fetchall()
        return {r["table_name"] for r in rows} - {_MIGRATION_TABLE}

    def reset_schema(self) -> None:
        """Drop and recreate the public schema, then migrate.

        For development and the test fixtures only. Needed because an applied
        migration cannot be edited — which is right for a shared database and
        merely tedious for a local one that holds nothing.

        Deliberately a method on ``Database`` rather than a test helper reaching
        into private attributes: a destructive operation should be visible in the
        class that owns the connection, and two copies of one is one too many.
        """
        with self.connect() as conn:
            conn.execute("DROP SCHEMA public CASCADE")
            conn.execute("CREATE SCHEMA public")
            conn.commit()
        self.migrate()

    def truncate_all(self) -> None:
        """Empty every table, for test isolation.

        ``TRUNCATE ... CASCADE`` rather than dropping the schema: recreating it per
        test would make the suite dominated by DDL. Deliberately not exposed on any
        application path — it exists on ``Database`` because the test fixture needs
        a handle, and hiding it in a test helper that reaches into private
        attributes would be worse.
        """
        tables = self.table_names()
        if not tables:
            return
        with self.connect() as conn:
            conn.execute(
                sql.SQL("TRUNCATE {} CASCADE").format(
                    sql.SQL(", ").join(sql.Identifier(t) for t in sorted(tables))
                )
            )
            conn.commit()

    def execute_scalar(self, statement: str, params: Any = None) -> Any:
        """One value, for assertions and counts."""
        with self.connect() as conn:
            row = conn.execute(statement, params).fetchone()  # type: ignore[arg-type]
        if row is None:
            return None
        return next(iter(row.values()))
