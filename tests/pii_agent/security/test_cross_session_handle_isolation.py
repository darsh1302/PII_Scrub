"""Guardrail G15/G16, Property 6 — session isolation.

The reviewed design claimed session isolation but could not deliver it: tools
were module singletons and the token vault was instance state on a shared tool,
while Streamlit shares one process across every browser session. These tests
prove the SessionContext ownership model actually isolates.
"""

from __future__ import annotations

import pytest

from pii_agent.session.content_store import ContentStore, HandleNotFoundError
from pii_agent.session.context import get_session_context
from pii_agent.utils.config import Settings


def test_handle_from_one_session_not_resolvable_in_another(settings: Settings):
    a = get_session_context("session-a", settings)
    b = get_session_context("session-b", settings)

    handle = a.content_store.put(
        "SSN 123-45-6789", source_type="TEXT", source_identifier="pasted"
    )

    # Owning session resolves it.
    assert a.content_store.get(handle).content == "SSN 123-45-6789"

    # Foreign session cannot, and cannot tell that it exists.
    with pytest.raises(HandleNotFoundError):
        b.content_store.get(handle)
    assert b.content_store.exists(handle) is False


def test_sessions_share_no_store_objects(settings: Settings):
    a = get_session_context("session-a", settings)
    b = get_session_context("session-b", settings)

    assert a.content_store is not b.content_store
    assert a.token_vault is not b.token_vault
    assert a.allowlist is not b.allowlist
    assert a.preferences is not b.preferences


def test_token_vault_does_not_resolve_across_sessions(settings: Settings):
    a = get_session_context("session-a", settings)
    b = get_session_context("session-b", settings)

    surrogate = a.token_vault.tokenize("alice@example.com", "EMAIL_ADDRESS")

    assert a.token_vault.owns(surrogate) is True
    assert b.token_vault.owns(surrogate) is False


def test_allowlist_is_not_shared_across_sessions(settings: Settings):
    a = get_session_context("session-a", settings)
    b = get_session_context("session-b", settings)

    a.allowlist.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")

    assert a.allowlist.contains("10.0.0.1", "DEFAULT_PII") is True
    assert b.allowlist.contains("10.0.0.1", "DEFAULT_PII") is False


def test_allowlist_is_scoped_per_profile(settings: Settings):
    """An entry added under one profile must not suppress under another.

    Otherwise a convenience feature becomes a detection bypass: values marked
    safe for generic PII work would silently disappear from HEALTHCARE scans.
    """
    ctx = get_session_context("session-a", settings)
    ctx.allowlist.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")

    assert ctx.allowlist.contains("10.0.0.1", "DEFAULT_PII") is True
    assert ctx.allowlist.contains("10.0.0.1", "HEALTHCARE") is False


def test_handles_are_unguessable(settings: Settings):
    """128 bits of CSPRNG entropy, distinct across calls (guardrail G16)."""
    store = ContentStore("session-a")
    handles = {
        store.put("x", source_type="TEXT", source_identifier="s") for _ in range(200)
    }
    assert len(handles) == 200

    sample = next(iter(handles))
    namespace, _, random_part = sample.partition(":")
    assert len(namespace) == 12
    assert len(random_part) == 32  # 16 bytes hex


def test_handle_does_not_disclose_session_id(settings: Settings):
    """The namespace is hashed, so a handle does not leak the session id."""
    session_id = "very-distinctive-session-identifier"
    store = ContentStore(session_id)
    handle = store.put("x", source_type="TEXT", source_identifier="s")
    assert session_id not in handle


def test_teardown_clears_all_session_state(settings: Settings):
    ctx = get_session_context("session-a", settings)
    ctx.content_store.put("x", source_type="TEXT", source_identifier="s")
    ctx.token_vault.tokenize("a@b.com", "EMAIL_ADDRESS")
    ctx.allowlist.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")
    temp = ctx.temp_dir
    assert temp.exists()

    ctx.teardown()

    assert len(ctx.content_store) == 0
    assert len(ctx.token_vault) == 0
    assert len(ctx.allowlist) == 0
    assert not temp.exists()


def test_content_record_repr_never_leaks_content(settings: Settings):
    """A repr in a log line or traceback must not disclose PII."""
    ctx = get_session_context("session-a", settings)
    secret = "SSN 123-45-6789 and card 4532890123456789"
    handle = ctx.content_store.put(
        secret, source_type="TEXT", source_identifier="pasted"
    )
    record = ctx.content_store.get(handle)

    rendered = repr(record)
    assert "123-45-6789" not in rendered
    assert "4532890123456789" not in rendered
    assert handle in rendered
