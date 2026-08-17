"""Session retention: idle sweeping, and the true scope of TOKENIZE.

Both of these are about a gap between what the system implies and what it does.

**Retention.** Streamlit gives no reliable browser-close signal, so without a
sweep every session that ever existed keeps its ContentStore — and that store
holds the original file content. In a long-running process that is indefinite
retention of exactly the data this tool exists to remove. The sweep is therefore
a security control, not memory hygiene.

**Tokenization.** FINANCIAL and PAYMENT_PCI choose TOKENIZE over MASK on the
stated grounds that records stay correlatable. That holds only inside one session:
surrogates are CSPRNG values in an in-memory dict, cleared on teardown. These
tests pin the real behaviour so the limitation cannot be quietly forgotten again.
"""

from __future__ import annotations

import time

import pytest

from core.file_source import load_upload
from session.context import (
    SessionContext,
    active_session_ids,
    drop_session_context,
    get_session_context,
    sweep_idle_sessions,
)
from utils.config import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"retention-salt",
        scan_roots=(),
        audit_dir=tmp_path / "audit",
    )


@pytest.fixture(autouse=True)
def _cleanup():
    yield
    for session_id in active_session_ids():
        if session_id.startswith("retention-"):
            drop_session_context(session_id)


# ---------------------------------------------------------------------------
# Idle sweeping
# ---------------------------------------------------------------------------
def test_idle_session_is_swept_and_its_content_released(settings):
    ctx = get_session_context("retention-idle", settings)
    loaded = load_upload(b"ssn 482-71-9053\n", "notes.log", ctx)
    assert ctx.content_store.exists(loaded.handle)

    # Make it look untouched without waiting an hour.
    ctx.last_touched = time.monotonic() - 10_000

    swept = sweep_idle_sessions()

    assert "retention-idle" in swept
    assert "retention-idle" not in active_session_ids()
    # The content is gone, which is the point — not merely the registry entry.
    assert not ctx.content_store.exists(loaded.handle)
    assert len(ctx.content_store) == 0


def test_active_session_is_not_swept(settings):
    ctx = get_session_context("retention-active", settings)
    loaded = load_upload(b"ssn 482-71-9053\n", "notes.log", ctx)

    swept = sweep_idle_sessions()

    assert "retention-active" not in swept
    assert ctx.content_store.exists(loaded.handle)


def test_accessing_a_session_keeps_it_alive(settings):
    """"Idle" must mean no activity, not merely old.

    A long scan reaches its session repeatedly; if age alone decided, a scan
    could have its own content swept out from under it.
    """
    ctx = get_session_context("retention-touch", settings)
    ctx.last_touched = time.monotonic() - 10_000

    # Reaching it again should reset the clock.
    same = get_session_context("retention-touch", settings)
    assert same is ctx

    assert "retention-touch" not in sweep_idle_sessions()


def test_sweep_respects_an_explicit_limit(settings):
    ctx = get_session_context("retention-limit", settings)
    ctx.last_touched = time.monotonic() - 5

    assert "retention-limit" not in sweep_idle_sessions(max_idle_seconds=60)
    assert "retention-limit" in sweep_idle_sessions(max_idle_seconds=1)


def test_sweep_is_safe_with_no_sessions():
    for session_id in active_session_ids():
        drop_session_context(session_id)
    assert sweep_idle_sessions() == ()


def test_sessions_track_when_they_were_last_touched(settings):
    ctx = SessionContext("retention-stamp", settings)
    assert ctx.last_touched > 0


# ---------------------------------------------------------------------------
# What TOKENIZE actually delivers
# ---------------------------------------------------------------------------
def test_tokens_are_stable_within_a_session(settings):
    """The documented benefit — a join key — holds this far and no further."""
    ctx = get_session_context("retention-tok-a", settings)

    first = ctx.token_vault.tokenize("4532015112830366", "CREDIT_CARD")
    second = ctx.token_vault.tokenize("4532015112830366", "CREDIT_CARD")

    assert first == second


def test_tokens_are_not_stable_across_sessions(settings):
    """Pins the limitation the profiles previously overstated.

    If this ever starts passing as "equal", someone has made surrogates
    deterministic — which reintroduces the brute-forcing weakness that G14 blocks
    HASH for. It would need to be a deliberate, reviewed change.
    """
    one = get_session_context("retention-tok-b", settings)
    two = get_session_context("retention-tok-c", settings)

    assert one.token_vault.tokenize("4532015112830366", "CREDIT_CARD") != (
        two.token_vault.tokenize("4532015112830366", "CREDIT_CARD")
    )


def test_teardown_destroys_the_mapping_irrecoverably(settings):
    """There is no reversal path, in the agent or out of it."""
    ctx = get_session_context("retention-tok-d", settings)
    token = ctx.token_vault.tokenize("4532015112830366", "CREDIT_CARD")

    ctx.teardown()

    # Nothing in the vault can resolve the surrogate afterwards.
    assert not any(
        "4532015112830366" in str(value)
        for value in vars(ctx.token_vault).values()
    )
    assert token.startswith("<CREDIT_CARD:")
