"""TokenVault — Property 4 (uniqueness) and the HASH/TOKENIZE refusals.

The refusals here are the runtime half of guardrail G14. Profile schema
validation is the primary gate; this is defence in depth for values that reach
the vault by another path.
"""

from __future__ import annotations

import pytest

from session.token_vault import (
    LOW_ENTROPY_TYPES,
    TOKENIZATION_PROHIBITED_TYPES,
    TokenizationRefused,
    TokenVault,
)


@pytest.fixture
def vault() -> TokenVault:
    return TokenVault("session-a", b"test-salt")


def test_same_value_tokenizes_consistently_within_session(vault: TokenVault):
    a = vault.tokenize("alice@example.com", "EMAIL_ADDRESS")
    b = vault.tokenize("alice@example.com", "EMAIL_ADDRESS")
    assert a == b
    assert len(vault) == 1


def test_different_values_get_different_surrogates(vault: TokenVault):
    a = vault.tokenize("alice@example.com", "EMAIL_ADDRESS")
    b = vault.tokenize("bob@example.com", "EMAIL_ADDRESS")
    assert a != b


def test_surrogates_are_unique_across_many_values(vault: TokenVault):
    """Property 4 — a collision would silently merge two distinct values."""
    surrogates = {
        vault.tokenize(f"user{i}@example.com", "EMAIL_ADDRESS")
        for i in range(2000)
    }
    assert len(surrogates) == 2000


def test_surrogate_does_not_contain_the_original(vault: TokenVault):
    original = "alice@example.com"
    surrogate = vault.tokenize(original, "EMAIL_ADDRESS")
    assert original not in surrogate
    assert "alice" not in surrogate


def test_surrogate_carries_type_for_readability(vault: TokenVault):
    surrogate = vault.tokenize("alice@example.com", "EMAIL_ADDRESS")
    assert surrogate.startswith("<EMAIL_ADDRESS:")


@pytest.mark.parametrize("entity_type", sorted(TOKENIZATION_PROHIBITED_TYPES))
def test_prohibited_types_cannot_be_tokenized(vault: TokenVault, entity_type: str):
    """CVV and PIN must never be stored reversibly (PCI-DSS, Requirement 32.7)."""
    with pytest.raises(TokenizationRefused):
        vault.tokenize("123", entity_type)


@pytest.mark.parametrize("entity_type", sorted(LOW_ENTROPY_TYPES))
def test_hash_refused_for_low_entropy_types(vault: TokenVault, entity_type: str):
    """The SSN space is ~10^9 — a salted digest is brute-forceable (SEC-12)."""
    with pytest.raises(TokenizationRefused) as exc:
        vault.hash_value("123-45-6789", entity_type)
    assert "brute force" in str(exc.value)


def test_hash_permitted_for_high_entropy_types(vault: TokenVault):
    digest = vault.hash_value("alice@example.com", "EMAIL_ADDRESS")
    assert len(digest) == 64
    assert "alice" not in digest


def test_hash_is_deterministic_for_a_given_salt(vault: TokenVault):
    a = vault.hash_value("alice@example.com", "EMAIL_ADDRESS")
    b = vault.hash_value("alice@example.com", "EMAIL_ADDRESS")
    assert a == b


def test_hash_differs_across_salts():
    """Per-deployment salt must actually change the output."""
    v1 = TokenVault("s", b"salt-one")
    v2 = TokenVault("s", b"salt-two")
    assert v1.hash_value("a@b.com", "EMAIL_ADDRESS") != v2.hash_value(
        "a@b.com", "EMAIL_ADDRESS"
    )


def test_detokenization_requires_operator_identity(vault: TokenVault):
    surrogate = vault.tokenize("alice@example.com", "EMAIL_ADDRESS")
    with pytest.raises(PermissionError):
        vault._operator_resolve(surrogate, authorized_by="")


def test_operator_resolve_returns_original(vault: TokenVault):
    surrogate = vault.tokenize("alice@example.com", "EMAIL_ADDRESS")
    assert (
        vault._operator_resolve(surrogate, authorized_by="ops@example.com")
        == "alice@example.com"
    )


def test_vault_exposes_no_public_reverse_method(vault: TokenVault):
    """Guardrail G11 — no agent-reachable detokenization surface.

    An exposed reverse method would turn prompt injection into an exfiltration
    primitive (SEC-09).
    """
    public = {n for n in dir(vault) if not n.startswith("_")}
    for name in ("detokenize", "resolve", "reverse", "lookup", "original"):
        assert name not in public


def test_mapping_repr_does_not_leak_original(vault: TokenVault):
    vault.tokenize("alice@example.com", "EMAIL_ADDRESS")
    mapping = next(iter(vault._forward.values()))
    assert "alice@example.com" not in repr(mapping)


def test_audit_summary_contains_counts_not_values(vault: TokenVault):
    vault.tokenize("alice@example.com", "EMAIL_ADDRESS")
    vault.tokenize("bob@example.com", "EMAIL_ADDRESS")
    vault.tokenize("123 Main St", "LOCATION")

    summary = vault.audit_summary()
    assert summary == {"EMAIL_ADDRESS": 2, "LOCATION": 1}
    assert "alice@example.com" not in str(summary)
