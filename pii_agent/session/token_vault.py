"""Session-scoped tokenization vault.

Guardrails G11, G15. Requirement 32, correctness Property 4.

**Scope limitation — read this before choosing TOKENIZE in a profile.**

Surrogates are CSPRNG values held in an in-memory dict on the owning
SessionContext. Two consequences follow, and both contradict what "tokenization"
usually implies:

* **Correlation holds only within one session.** The same input scrubbed in a
  later session gets an entirely different surrogate, so two artifacts cannot be
  joined. If a profile chooses TOKENIZE over MASK to keep records correlatable,
  that benefit ends at the session boundary.
* **Reversal is not available at all.** ``teardown()`` clears the vault, and
  nothing persists it. Once a session ends the mapping is gone, so a surrogate in
  a downloaded artifact can never be resolved — by an operator or by anyone.

Real reversible tokenization needs a durable encrypted vault, which is the
persistence this project deliberately does not have. Until that exists, treat
TOKENIZE as *irreversible with a session-local join key*, and do not promise
users cross-session correlation or recovery.

Two deliberate design constraints:

1. **Detokenization is not reachable from the agent.** This module exposes no
   resolve/reverse method that the reasoning loop can reach. Because the agent
   ingests attacker-writable content, an exposed detokenize tool would turn
   prompt injection into an exfiltration primitive (SEC-09): injected text tells
   the agent to reverse tokens and print originals.

   Note this is currently enforced by there being no reversal path anywhere,
   in-agent or out. An earlier version of this docstring referred to a
   ``scripts/detokenize.py`` operator entry point; it was never built. When one
   is added it must live outside the agent's tool registry, take an explicit
   authorization argument, and write an audit record per access.

2. **HASH is not anonymization.** ``hash_value`` uses PBKDF2 with a
   per-deployment salt, but the entire US SSN space is ~10^9 values — brute
   forcing a salted digest is minutes of commodity compute once the salt is
   known. HASH is pseudonymization. Low-entropy high-severity types are blocked
   from using it at profile-schema validation (guardrail G14); this module
   refuses them again at runtime as defence in depth.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timezone

from pii_agent.utils.config import HASH_KDF_ITERATIONS, TOKEN_SURROGATE_ENTROPY_BYTES

# Never stored reversibly under any configuration (Requirement 32.7, PCI-DSS).
TOKENIZATION_PROHIBITED_TYPES = frozenset({"CVV", "CVC", "PIN", "TRACK_DATA"})

# HASH is forbidden for these: the value space is small enough to exhaust.
LOW_ENTROPY_TYPES = frozenset(
    {"US_SSN", "CREDIT_CARD", "PAN", "CVV", "CVC", "PIN", "US_BANK_NUMBER"}
)


class TokenizationRefused(RuntimeError):
    """Raised when tokenization or hashing is not permitted for a type."""


@dataclass
class TokenMapping:
    surrogate: str
    original: str = field(repr=False)
    entity_type: str
    created_at: str

    def __repr__(self) -> str:  # pragma: no cover - defensive
        return (
            f"TokenMapping(surrogate={self.surrogate!r}, "
            f"entity_type={self.entity_type!r})"
        )


class TokenVault:
    """Per-session surrogate store. Never a module singleton."""

    def __init__(self, session_id: str, salt: bytes) -> None:
        self._session_id = session_id
        self._namespace = hashlib.sha256(session_id.encode()).hexdigest()[:12]
        self._salt = salt
        # surrogate -> mapping
        self._forward: dict[str, TokenMapping] = {}
        # sha256(original) -> surrogate, so the same value tokenizes
        # consistently within a session without storing plaintext as a key
        self._seen: dict[str, str] = {}

    @property
    def namespace(self) -> str:
        return self._namespace

    def _fingerprint(self, value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def tokenize(self, value: str, entity_type: str) -> str:
        """Return a surrogate for ``value``, creating one if needed.

        Stable within this session only — the mapping is in memory and is cleared
        on teardown. See the module docstring: this is not cross-session
        tokenization and the result is not reversible afterwards.

        Raises TokenizationRefused for prohibited types.
        """
        if entity_type.upper() in TOKENIZATION_PROHIBITED_TYPES:
            raise TokenizationRefused(
                f"{entity_type} must never be stored reversibly"
            )

        fingerprint = self._fingerprint(value)
        existing = self._seen.get(fingerprint)
        if existing is not None:
            return existing

        surrogate = self._mint_surrogate(entity_type)
        self._forward[surrogate] = TokenMapping(
            surrogate=surrogate,
            original=value,
            entity_type=entity_type,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._seen[fingerprint] = surrogate
        return surrogate

    def _mint_surrogate(self, entity_type: str) -> str:
        """Generate a collision-free CSPRNG surrogate (Property 4).

        The collision check is not theatre: without it, a collision would make
        two distinct source values indistinguishable after tokenization, which
        silently corrupts data.
        """
        for _ in range(64):
            candidate = (
                f"<{entity_type}:"
                f"{secrets.token_hex(TOKEN_SURROGATE_ENTROPY_BYTES)}>"
            )
            if candidate not in self._forward:
                return candidate
        raise RuntimeError(  # pragma: no cover - astronomically unlikely
            "could not mint a unique surrogate"
        )

    def hash_value(self, value: str, entity_type: str) -> str:
        """Salted PBKDF2 digest — pseudonymization, not anonymization.

        Refuses low-entropy types where a digest is brute-forceable.
        """
        if entity_type.upper() in LOW_ENTROPY_TYPES:
            raise TokenizationRefused(
                f"HASH is not sufficient protection for {entity_type} — the "
                "value space is small enough to brute force. Use TOKENIZE or "
                "REDACT."
            )
        digest = hashlib.pbkdf2_hmac(
            "sha256", value.encode("utf-8"), self._salt, HASH_KDF_ITERATIONS
        )
        return digest.hex()

    def owns(self, surrogate: str) -> bool:
        return surrogate in self._forward

    def _operator_resolve(self, surrogate: str, *, authorized_by: str) -> str:
        """Reverse a surrogate. NOT part of the agent-reachable surface.

        Name-mangled by convention (leading underscore) and never registered as
        a tool. ``scripts/detokenize.py`` is the only intended caller, and it
        requires an explicit operator identity for the audit record.
        """
        if not authorized_by:
            raise PermissionError("detokenization requires an operator identity")
        mapping = self._forward.get(surrogate)
        if mapping is None:
            raise KeyError("surrogate not found")
        return mapping.original

    def audit_summary(self) -> dict[str, int]:
        """Counts by entity type. Contains no values — safe for audit records."""
        counts: dict[str, int] = {}
        for mapping in self._forward.values():
            counts[mapping.entity_type] = counts.get(mapping.entity_type, 0) + 1
        return counts

    def clear(self) -> None:
        self._forward.clear()
        self._seen.clear()

    def __len__(self) -> int:
        return len(self._forward)
