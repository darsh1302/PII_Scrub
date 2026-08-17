"""Session- and profile-scoped false-positive allowlist.

Requirement 39, guardrail G15.

Scoping is the security-relevant part. An allowlist entry added while working
with DEFAULT_PII must not silently suppress detection under HEALTHCARE, and an
entry added by one user must not affect another. Both would turn a convenience
feature into a detection bypass.

Values are stored as salted digests rather than plaintext: the allowlist is a
list of things the user said were safe, but "safe in this context" is not the
same as "safe to persist in cleartext".
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class AllowlistEntry:
    value_hash: str
    entity_type: str
    profile: str
    added_at: str
    label: str  # truncated, masked preview for UI confirmation only


class AllowlistStore:
    """Per-session allowlist keyed by (profile, value)."""

    def __init__(self, session_id: str) -> None:
        self._session_id = session_id
        # Per-instance salt: digests are not comparable across sessions even
        # for identical values.
        self._salt = secrets.token_bytes(16)
        self._entries: dict[tuple[str, str], AllowlistEntry] = {}

    def _hash(self, value: str) -> str:
        return hashlib.sha256(self._salt + value.encode("utf-8")).hexdigest()

    @staticmethod
    def _label(value: str) -> str:
        """Masked preview — enough to confirm, not enough to disclose."""
        if len(value) <= 4:
            return "*" * len(value)
        return f"{value[:2]}{'*' * (len(value) - 4)}{value[-2:]}"

    def add(self, value: str, entity_type: str, profile: str) -> AllowlistEntry:
        entry = AllowlistEntry(
            value_hash=self._hash(value),
            entity_type=entity_type,
            profile=profile,
            added_at=datetime.now(timezone.utc).isoformat(),
            label=self._label(value),
        )
        self._entries[(profile, entry.value_hash)] = entry
        return entry

    def contains(self, value: str, profile: str) -> bool:
        """True if ``value`` is allowlisted for ``profile`` specifically."""
        return (profile, self._hash(value)) in self._entries

    def filter_entities(self, entities: list, profile: str) -> tuple[list, int]:
        """Drop allowlisted entities.

        Returns ``(kept, suppressed_count)``. The count is logged for audit so a
        suppression is visible without disclosing the value (Requirement 39.5).
        """
        kept = []
        suppressed = 0
        for entity in entities:
            text = getattr(entity, "text", None)
            if text is not None and self.contains(text, profile):
                suppressed += 1
            else:
                kept.append(entity)
        return kept, suppressed

    def entries_for(self, profile: str) -> tuple[AllowlistEntry, ...]:
        return tuple(e for (p, _), e in self._entries.items() if p == profile)

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)
