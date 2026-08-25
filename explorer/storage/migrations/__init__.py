"""Numbered SQL migrations, applied in order and checksummed.

Plain ``.sql`` files rather than a migration framework. The schema is the security
boundary — ``workspace_id NOT NULL``, the cascade graph, the ``run`` terminal-state
check — and those are things a reviewer should read as SQL rather than infer from
model declarations and a generated diff.

The checksum is the part that earns its keep. Editing an already-applied migration
is the most common way a schema diverges between two machines while both believe
they are up to date, and it produces failures nowhere near the cause. Applying a
file whose contents no longer match what was recorded is refused.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

MIGRATIONS_DIR = Path(__file__).resolve().parent

_NAME = re.compile(r"^(\d{4})_([a-z0-9_]+)\.sql$")


@dataclass(frozen=True)
class Migration:
    """One migration file."""

    number: int
    name: str
    path: Path
    sql: str

    @property
    def checksum(self) -> str:
        """SHA-256 of the file, newline-normalised.

        Normalised because Git may hand a contributor CRLF for the same file the
        original author committed with LF. A checksum that changes with line
        endings would refuse a correct migration on Windows, which teaches people
        to disable the check.
        """
        normalised = self.sql.replace("\r\n", "\n").encode("utf-8")
        return hashlib.sha256(normalised).hexdigest()

    @property
    def identifier(self) -> str:
        return f"{self.number:04d}_{self.name}"


def discover() -> list[Migration]:
    """Every migration, in application order.

    A file that does not match ``NNNN_name.sql`` raises rather than being skipped.
    A silently ignored migration is a schema that is missing a table for reasons
    nobody can see.
    """
    found: list[Migration] = []
    seen_numbers: dict[int, str] = {}

    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        match = _NAME.match(path.name)
        if not match:
            raise ValueError(
                f"migration file {path.name!r} does not match NNNN_name.sql — "
                f"rename it rather than leaving it to be skipped"
            )
        number = int(match.group(1))
        if number in seen_numbers:
            raise ValueError(
                f"duplicate migration number {number:04d}: "
                f"{seen_numbers[number]} and {path.name}. Two files claiming the "
                f"same position apply in an order that depends on the filesystem."
            )
        seen_numbers[number] = path.name
        found.append(
            Migration(
                number=number,
                name=match.group(2),
                path=path,
                sql=path.read_text(encoding="utf-8"),
            )
        )

    # A gap is an error, not a warning. Gaps mean a migration was deleted or never
    # committed, and applying 1, 2 and 4 leaves a schema matching no version anyone
    # can name — while the runner reports success.
    numbers = [m.number for m in found]
    if numbers and numbers != list(range(1, len(numbers) + 1)):
        raise ValueError(
            f"migration numbers must be consecutive from 0001; found {numbers}. "
            f"A gap usually means a file was deleted or never committed."
        )

    return found
