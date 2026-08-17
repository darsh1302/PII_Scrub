"""Server-side content storage addressed by opaque handles.

This module is the structural control behind guardrails G1 and G16, and behind
correctness Property 9 ("no content in reasoning context").

The reasoning loop is treated as an untrusted component. It receives a *handle*
and never the bytes. That matters for two independent reasons:

1. Security — the agent ingests attacker-writable content by design (log files,
   cloud events). Content placed in the reasoning context can carry
   instructions, so raw content must never enter it (SEC-01, SEC-03).
2. Correctness — an LLM asked to transcribe integer character offsets between
   pipeline steps will occasionally get them wrong, applying a scrub to the
   wrong span and leaving the PII in place. Keeping records server-side removes
   the model from the data path entirely (SEC-02).

Handles are ``{session_ns}:{128-bit hex}``. The session namespace is checked on
every resolution, so a handle issued in one session cannot be resolved in
another even though Streamlit shares one process across all browser sessions
(SEC-06).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from utils.config import CONTENT_HANDLE_ENTROPY_BYTES

if TYPE_CHECKING:  # pragma: no cover - typing only
    from models.coverage import CoverageLedger
    from models.entities import Entity


class HandleNotFoundError(KeyError):
    """Raised when a handle is unknown, expired, or belongs to another session.

    Deliberately does not distinguish between those cases: telling a caller that
    a handle "exists but is not yours" would confirm the existence of another
    session's data.
    """


@dataclass
class ContentRecord:
    """A stored unit of content plus everything derived from it.

    ``content`` never leaves the process. ``entities`` is populated by the
    deterministic pipeline and is the ONLY accepted source of entity positions
    for the applier (Requirement 12.9).
    """

    handle: str
    content: str
    source_type: str
    source_identifier: str
    bytes_total: int
    entities: list["Entity"] = field(default_factory=list)
    coverage: "CoverageLedger | None" = None
    profile_name: str | None = None
    profile_version: str | None = None
    engine_versions: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)
    is_sanitized: bool = False
    verified_clean: bool = False

    def __repr__(self) -> str:  # pragma: no cover - defensive
        """Never render content in a repr — this object holds raw PII."""
        return (
            f"ContentRecord(handle={self.handle!r}, "
            f"source_type={self.source_type!r}, "
            f"bytes_total={self.bytes_total}, "
            f"entities={len(self.entities)}, "
            f"is_sanitized={self.is_sanitized}, "
            f"verified_clean={self.verified_clean})"
        )

    def source_identifier_hash(self) -> str:
        """Stable hash of the source identifier, for audit records.

        Audit records must not contain raw source identifiers, which can
        themselves be sensitive (Requirement 41.6).
        """
        return hashlib.sha256(self.source_identifier.encode("utf-8")).hexdigest()


class ContentStore:
    """Per-session content store. Never instantiate as a module singleton.

    Owned by SessionContext (guardrail G15). One instance per browser session.
    """

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        self._namespace = self._derive_namespace(session_id)
        self._records: dict[str, ContentRecord] = {}

    @staticmethod
    def _derive_namespace(session_id: str) -> str:
        """Short, non-reversible namespace derived from the session id.

        Hashed rather than used directly so a handle does not disclose the
        session identifier itself.
        """
        return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:12]

    @property
    def namespace(self) -> str:
        return self._namespace

    def _new_handle(self) -> str:
        return f"{self._namespace}:{secrets.token_hex(CONTENT_HANDLE_ENTROPY_BYTES)}"

    def _owns(self, handle: str) -> bool:
        """Constant-time namespace comparison."""
        prefix, _, _ = handle.partition(":")
        return hmac.compare_digest(prefix, self._namespace)

    def put(
        self,
        content: str,
        *,
        source_type: str,
        source_identifier: str,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Store content and return its handle."""
        handle = self._new_handle()
        self._records[handle] = ContentRecord(
            handle=handle,
            content=content,
            source_type=source_type,
            source_identifier=source_identifier,
            bytes_total=len(content.encode("utf-8")),
            metadata=metadata or {},
        )
        return handle

    def get(self, handle: str) -> ContentRecord:
        """Resolve a handle to its record.

        Raises HandleNotFoundError for unknown handles and for handles belonging
        to another session — indistinguishably.
        """
        if not self._owns(handle) or handle not in self._records:
            raise HandleNotFoundError("handle not found")
        return self._records[handle]

    def exists(self, handle: str) -> bool:
        return self._owns(handle) and handle in self._records

    def find_by_label(self, label: str) -> ContentRecord | None:
        """Resolve a human-visible name to an already-loaded record.

        Uploaded and pasted content has no path inside a scan root, so the only
        way to reach it is by handle. The agent is told the label, not the
        handle, so without this an upload is unreachable: the label falls through
        to the filesystem loader and is refused for being outside the scan roots.

        Matching is exact and case-insensitive against the stored display name.
        Sanitized output is excluded — asking to scan "sample.txt" means the
        original, not the cleaned copy derived from it.

        This grants no new reach. Every candidate was already ingested in this
        session by explicit user action, and the namespace check still applies.
        """
        wanted = label.strip().lower()
        if not wanted:
            return None

        # Most recent wins: re-uploading a name should supersede the earlier one.
        for record in reversed(list(self._records.values())):
            if record.is_sanitized:
                continue
            display = str(record.metadata.get("display_name", "")).strip().lower()
            if display and display == wanted:
                return record
        return None

    def loaded_sources(self) -> list[ContentRecord]:
        """Non-sanitized records, oldest first, for discovery listings."""
        return [r for r in self._records.values() if not r.is_sanitized]

    def put_sanitized(self, content: str, source: ContentRecord) -> str:
        """Store sanitized output derived from an existing record."""
        handle = self._new_handle()
        self._records[handle] = ContentRecord(
            handle=handle,
            content=content,
            source_type=source.source_type,
            source_identifier=source.source_identifier,
            bytes_total=len(content.encode("utf-8")),
            profile_name=source.profile_name,
            profile_version=source.profile_version,
            engine_versions=dict(source.engine_versions),
            metadata={"derived_from": source.handle},
            is_sanitized=True,
        )
        return handle

    def delete(self, handle: str) -> None:
        if self._owns(handle):
            self._records.pop(handle, None)

    def clear(self) -> None:
        """Drop all records. Called on session teardown."""
        self._records.clear()

    def __len__(self) -> int:
        return len(self._records)
