"""Append-only, hash-chained audit for the platform — task 4.4, `[R14.6]`.

Why this is not a database table
--------------------------------

`[R14.6]` requires a deletion record to survive the data it describes. A row in a
table the application can write to fails that twice over: it can be rewritten by the
same code that wrote it, and if it were foreign-keyed to the thing being deleted the
cascade would take it. Files on disk with each record carrying its predecessor's hash
give tamper *evidence* and outlive any cascade.

This is evidence, not prevention. Someone with write access to the directory can
rewrite the entire chain. Preventing that needs an append-only medium or external
anchoring, which is out of scope and recorded here as a residual risk rather than
implied away.

Why this duplicates ``pii_agent.session.audit_sink``
----------------------------------------------------

Because dependency rule D2 permits ``explorer`` to reach ``pii_agent`` only through
``explorer.security.pii_service``, and a deletion audit is not a PII operation. The
design also rejected a ``shared/`` package on the grounds that it becomes the place
coupling hides.

So the cost of D1 and D2 here is a second implementation of hash chaining. That cost
is paid deliberately, and it is bounded by
``tests/explorer/observability/test_audit_chain_format.py``, which asserts both
implementations produce byte-identical canonical form and identical hashes for the same
record. The formats are pinned to each other by test rather than by shared code, so a
trail exported from either product verifies with either verifier — and a drift in one
fails immediately rather than being discovered when someone tries to verify an old
trail.

Records are PII-free by construction. Identifiers and counts only, enforced at write
time rather than trusted to review, because the failure is silent and permanent.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64

# Deliberately the same set as the PII agent's sink, plus the platform's own risks.
# Kept as a literal rather than imported, per D2; the contract test asserts the shared
# members have not diverged.
_FORBIDDEN_FIELDS = frozenset(
    {
        "text",
        "content",
        "raw_content",
        "value",
        "matched_text",
        "entity_text",
        "sanitized",
        "excerpt",
        "source_identifier",
        # Platform additions. An audit trail is a plausible place for someone to log
        # "the prompt that was deleted" or "the chunk text", and both would put
        # content into the one file designed to outlive every retention policy.
        "payload",
        "prompt",
        "body",
        "vector",
        "embedding",
        "password",
        "token",
        "verifier",
    }
)


class AuditIntegrityError(RuntimeError):
    """A record was rejected, or the chain failed verification."""


def canonical(record: dict[str, Any]) -> str:
    """Deterministic serialization for hashing.

    Sorted keys, no insignificant whitespace, so the same logical record always hashes
    the same regardless of construction order.
    """
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def compute_record_hash(record: dict[str, Any]) -> str:
    """Hash a record's content, excluding its own hash field."""
    payload = {k: v for k, v in record.items() if k != "record_hash"}
    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


def assert_audit_safe(record: dict[str, Any], path: str = "") -> None:
    """Recursively reject forbidden field names.

    Walks nested structures. A check that only looked at the top level would pass a
    record whose payload was one dictionary deep, which is exactly how content ends up
    in a log.
    """
    for key, value in record.items():
        here = f"{path}.{key}" if path else key
        if key in _FORBIDDEN_FIELDS:
            raise AuditIntegrityError(
                f"audit record field {here!r} can carry sensitive content and is "
                f"not permitted in the audit trail — record identifiers and counts "
                f"instead"
            )
        if isinstance(value, dict):
            assert_audit_safe(value, here)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    assert_audit_safe(item, here)


class AuditChain:
    """Append-only hash-chained JSONL, one file per UTC day.

    Thread-safe. A torn write corrupts the chain from that point on, and the corruption
    is not visible until someone verifies.
    """

    def __init__(self, audit_dir: Path, *, prefix: str = "explorer-audit") -> None:
        self._dir = Path(audit_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._prefix = prefix
        self._lock = threading.Lock()

    def _path_for(self, when: datetime) -> Path:
        return self._dir / f"{self._prefix}-{when.strftime('%Y-%m-%d')}.jsonl"

    def _all_files(self) -> list[Path]:
        return sorted(self._dir.glob(f"{self._prefix}-*.jsonl"))

    def _last_hash(self) -> str:
        for path in reversed(self._all_files()):
            last_line = None
            try:
                with path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.strip():
                            last_line = line
            except OSError:
                continue
            if last_line:
                try:
                    return json.loads(last_line).get("record_hash", GENESIS_HASH)
                except json.JSONDecodeError:
                    return GENESIS_HASH
        return GENESIS_HASH

    def append(self, record: dict[str, Any]) -> str:
        """Append a record and return its hash.

        Flushed and fsync'd before returning. A deletion must not be reported as done
        before the record of it is durable — otherwise a crash between the two leaves
        data gone with no evidence of who removed it.
        """
        assert_audit_safe(record)

        with self._lock:
            now = datetime.now(UTC)
            entry = dict(record)
            entry.setdefault("timestamp", now.isoformat())
            entry["prev_hash"] = self._last_hash()
            entry["record_hash"] = compute_record_hash(entry)

            path = self._path_for(now)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(canonical(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

            return entry["record_hash"]

    def read_all(self) -> Iterator[dict[str, Any]]:
        """Every record, in chain order."""
        for path in self._all_files():
            try:
                with path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.strip():
                            yield json.loads(line)
            except OSError:  # pragma: no cover - filesystem edge
                continue

    def verify_chain(self) -> tuple[bool, str | None]:
        """Verify integrity, returning ``(ok, first_bad_record_hash)``.

        A record fails if its stored hash does not match its content — edited in
        place — or if its ``prev_hash`` does not match the preceding record, which
        means one was removed or reordered.
        """
        expected_prev = GENESIS_HASH
        for record in self.read_all():
            identifier = record.get("record_hash", "<no hash>")

            if record.get("record_hash") != compute_record_hash(record):
                return False, identifier
            if record.get("prev_hash") != expected_prev:
                return False, identifier

            expected_prev = record["record_hash"]
        return True, None

    def records_of_type(self, event: str) -> list[dict[str, Any]]:
        return [r for r in self.read_all() if r.get("event") == event]

    def count(self) -> int:
        return sum(1 for _ in self.read_all())
