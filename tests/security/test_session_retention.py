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



# ---------------------------------------------------------------------------
# Bounded result retention
# ---------------------------------------------------------------------------
def test_results_are_bounded_and_evicted_content_is_deleted(settings):
    """The UI redraws every retained result, so the list cannot grow forever.

    Eviction deletes the artifact's content too: it is unreachable from the UI
    once evicted, and keeping sanitized copies alive for results nobody can see
    is retention without a purpose.
    """
    from utils.config import MAX_SESSION_RESULTS

    ctx = get_session_context("retention-results", settings)

    class FakeResult:
        def __init__(self, request_id: str, handle: str) -> None:
            self.request_id = request_id
            self.sanitized_handle = handle

    handles = []
    for index in range(MAX_SESSION_RESULTS + 3):
        handle = ctx.content_store.put(
            f"cleaned {index}",
            source_type="FILE",
            source_identifier=f"f{index}.log",
        )
        handles.append(handle)
        ctx.record_result(FakeResult(f"req-{index}", handle))

    assert len(ctx.results()) == MAX_SESSION_RESULTS

    # The three oldest were evicted, and their content went with them.
    for handle in handles[:3]:
        assert not ctx.content_store.exists(handle)
    for handle in handles[3:]:
        assert ctx.content_store.exists(handle)


def test_recording_the_same_request_twice_does_not_consume_capacity(settings):
    ctx = get_session_context("retention-results-dup", settings)

    class FakeResult:
        def __init__(self) -> None:
            self.request_id = "same"
            self.sanitized_handle = None

    for _ in range(5):
        ctx.record_result(FakeResult())

    assert len(ctx.results()) == 1


# ---------------------------------------------------------------------------
# The shared NLP pass must fail loudly
# ---------------------------------------------------------------------------
def test_shared_nlp_failure_is_recorded_not_silent(monkeypatch):
    """It depends on a private Presidio method, so a version bump can break it.

    The only symptom would otherwise be everything quietly running ~20% slower.
    """
    from core import detector

    detector.reset_shared_nlp_failure()
    assert detector.shared_nlp_failure() is None

    class Boom:
        def _doc_to_nlp_artifact(self, doc, language):
            raise AttributeError("presidio internals moved")

    class FakeAnalyzer:
        nlp_engine = Boom()

    monkeypatch.setattr(detector, "get_analyzer", lambda: FakeAnalyzer())

    doc, artifacts = detector.build_shared_nlp("Dana Reyes in London")

    assert doc is not None          # detection still works
    assert artifacts is None       # Presidio will do its own pass
    recorded = detector.shared_nlp_failure()
    assert recorded and "AttributeError" in recorded
    assert "slower" in recorded

    detector.reset_shared_nlp_failure()


def test_healthy_shared_nlp_reports_no_failure():
    from core import detector

    detector.reset_shared_nlp_failure()
    doc, artifacts = detector.build_shared_nlp("Dana Reyes in London")

    assert doc is not None
    assert artifacts is not None
    assert detector.shared_nlp_failure() is None
