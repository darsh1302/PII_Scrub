"""Durable, append-only, hash-chained audit sink.

Guardrail G20, correctness Property 13.

The original design held audit records in ``st.session_state`` — an in-memory
list destroyed on browser refresh. That is not an audit trail. Requirements 41.3
and 41.5 need records that survive the session, so this writes JSONL to disk
before returning control to the caller.

Each record carries the hash of its predecessor. Editing or deleting a
historical record breaks the chain at that point, which ``verify_chain`` detects
and localises. This gives tamper *evidence*, not tamper *prevention* — an
attacker with write access to the sink can rewrite the whole chain. Preventing
that needs an append-only medium or external anchoring, which is out of MVP
scope and recorded as a residual risk.

Records are PII-free by construction: ``_FORBIDDEN_FIELDS`` is rejected at write
time so a future change cannot quietly start logging entity values.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

GENESIS_HASH = "0" * 64

# Field names that must never appear in an audit record. Enforced at write time
# rather than trusted to review, because the failure is silent and permanent.
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
        "source_identifier",  # must be hashed — see AuditRecord
    }
)


class AuditIntegrityError(RuntimeError):
    """Raised when a record is rejected or the chain fails verification."""


def _canonical(record: dict[str, Any]) -> str:
    """Deterministic serialization for hashing.

    Sorted keys and no insignificant whitespace, so the same logical record
    always produces the same hash regardless of construction order.
    """
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def compute_record_hash(record: dict[str, Any]) -> str:
    """Hash a record's content, excluding its own hash field."""
    payload = {k: v for k, v in record.items() if k != "record_hash"}
    return hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _assert_pii_free(record: dict[str, Any], path: str = "") -> None:
    """Recursively reject forbidden field names."""
    for key, value in record.items():
        here = f"{path}.{key}" if path else key
        if key in _FORBIDDEN_FIELDS:
            raise AuditIntegrityError(
                f"audit record field '{here}' can carry sensitive content "
                "and is not permitted in the audit trail"
            )
        if isinstance(value, dict):
            _assert_pii_free(value, here)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    _assert_pii_free(item, here)


class AuditSink:
    """Append-only JSONL audit sink, one file per UTC day.

    Thread-safe: Streamlit may run callbacks on multiple threads within a
    process, and a torn write would corrupt the chain.
    """

    def __init__(self, audit_dir: Path, session_id: str | None = None) -> None:
        self._dir = Path(audit_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        self._session_id = session_id
        self._lock = threading.Lock()

    def _path_for(self, when: datetime) -> Path:
        return self._dir / f"audit-{when.strftime('%Y-%m-%d')}.jsonl"

    def _all_files(self) -> list[Path]:
        return sorted(self._dir.glob("audit-*.jsonl"))

    def _last_hash(self) -> str:
        """Hash of the most recent record across all files, or genesis."""
        files = self._all_files()
        if not files:
            return GENESIS_HASH
        for path in reversed(files):
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

        Flushed and fsync'd before returning: the result must not reach the user
        before the audit entry is durable (Requirement 41.3).
        """
        _assert_pii_free(record)

        with self._lock:
            now = datetime.now(timezone.utc)
            entry = dict(record)
            entry.setdefault("timestamp", now.isoformat())
            if self._session_id is not None:
                entry.setdefault(
                    "session_hash",
                    hashlib.sha256(self._session_id.encode("utf-8")).hexdigest()[:16],
                )
            entry["prev_hash"] = self._last_hash()
            entry["record_hash"] = compute_record_hash(entry)

            path = self._path_for(now)
            with path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(entry) + "\n")
                fh.flush()
                os.fsync(fh.fileno())

            return entry["record_hash"]

    def read_all(self) -> Iterator[dict[str, Any]]:
        """Yield every record in chain order."""
        for path in self._all_files():
            try:
                with path.open("r", encoding="utf-8") as fh:
                    for line in fh:
                        if line.strip():
                            yield json.loads(line)
            except OSError:  # pragma: no cover - filesystem edge
                continue

    def verify_chain(self) -> tuple[bool, str | None]:
        """Verify chain integrity.

        Returns ``(ok, first_bad_request_id)``. A record fails if its stored
        hash does not match its content (edited in place) or if its ``prev_hash``
        does not match the preceding record's hash (record removed or reordered).
        """
        expected_prev = GENESIS_HASH
        for record in self.read_all():
            rid = record.get("request_id", "<unknown>")

            if record.get("record_hash") != compute_record_hash(record):
                return False, rid
            if record.get("prev_hash") != expected_prev:
                return False, rid

            expected_prev = record["record_hash"]
        return True, None

    def export(self) -> str:
        """Export the full trail as JSONL text (Requirement 41.7)."""
        return "\n".join(_canonical(r) for r in self.read_all())

    def count(self) -> int:
        return sum(1 for _ in self.read_all())
