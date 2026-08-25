"""Per-session ownership of all mutable state.

Guardrail G15, correctness Property 6.

The reviewed design claimed session isolation but could not deliver it: tools
were module-level singletons, the token vault was instance state on a shared
tool, and Streamlit shares one process across every browser session
(``@st.cache_resource`` shares deliberately). Token mappings, allowlists and
content handles would have leaked between users.

The fix is ownership. Everything mutable and everything sensitive hangs off a
SessionContext keyed by session id. Only genuinely stateless, expensive engines
(the Presidio analyzer, the loaded spaCy model) are shared, and those are reached
through an explicit read-only accessor so the sharing is visible at the call
site rather than implicit.
"""

from __future__ import annotations

import shutil
import tempfile
import threading
import time
from pathlib import Path

from pii_agent.session.allowlist import AllowlistStore
from pii_agent.session.audit_sink import AuditSink
from pii_agent.session.content_store import ContentStore
from pii_agent.session.token_vault import TokenVault
from pii_agent.utils.config import (
    ORPHAN_TEMP_DIR_MAX_AGE_HOURS,
    TEMP_DIR_PREFIX,
    Settings,
    load_settings,
)


class SessionContext:
    """Owns every per-session store. One instance per browser session."""

    def __init__(self, session_id: str, settings: Settings | None = None) -> None:
        self.session_id = session_id
        self.settings = settings or load_settings()

        # Last time this session was reached. Drives idle sweeping — see
        # sweep_idle_sessions. Monotonic so a clock adjustment cannot make a live
        # session look ancient and have its content dropped mid-scan.
        self.last_touched = time.monotonic()

        self.content_store = ContentStore(session_id)
        self.token_vault = TokenVault(session_id, self.settings.token_vault_salt)
        self.allowlist = AllowlistStore(session_id)
        self.audit_sink = AuditSink(self.settings.audit_dir, session_id)

        # Deterministic per-session temp dir so reruns reuse one directory
        # instead of leaking a new mkdtemp on every Streamlit interaction
        # (OPS-05).
        self._temp_dir: Path | None = None

        # Results produced this session, oldest first, so the UI can offer the
        # download for a cleaned copy. Server-side because the artifact itself
        # must not pass through the reasoning context, and because Streamlit
        # reruns the script on every interaction — a result held only in a local
        # variable would vanish before it could be rendered.
        self._results: list[object] = []

        self.preferences: dict[str, object] = {
            "profile": "DEFAULT_PII",
            "confidence_threshold": None,  # resolved from config at use site
            "requested_action": None,
            "destination": None,
            "locale": "en",
        }

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------
    def record_result(self, result: object) -> None:
        """Publish a pipeline result for the UI to render.

        Keeps the newest entry for a given request id rather than appending a
        duplicate, so a scan followed by a scrub of the same request presents one
        outcome — the later, more complete one.

        Bounded to MAX_SESSION_RESULTS. The UI redraws every retained result on
        every rerun, each with a download button holding its cleaned content, so an
        unbounded list grows both render time and memory across a long session.
        Evicting also deletes the evicted artifact's content: it is no longer
        reachable from the UI, and keeping sanitized copies alive for results
        nobody can see is retention without a purpose.
        """
        from pii_agent.utils.config import MAX_SESSION_RESULTS

        request_id = getattr(result, "request_id", None)
        if request_id is not None:
            self._results = [
                r for r in self._results
                if getattr(r, "request_id", None) != request_id
            ]
        self._results.append(result)

        while len(self._results) > MAX_SESSION_RESULTS:
            evicted = self._results.pop(0)
            handle = getattr(evicted, "sanitized_handle", None)
            if handle:
                self.content_store.delete(handle)

    def results(self) -> list[object]:
        """Results produced this session, oldest first."""
        return list(self._results)

    @property
    def latest_result(self) -> object | None:
        return self._results[-1] if self._results else None

    # ------------------------------------------------------------------
    # Temp directory
    # ------------------------------------------------------------------
    @property
    def temp_dir(self) -> Path:
        """Session-owned temp directory, created lazily.

        Prefer holding uploads in memory. Where a temp file is unavoidable it
        lives here so teardown can remove it deterministically. Deletion is
        hygiene, not sanitisation: overwrite-before-delete is largely
        ineffective on SSDs, CoW filesystems and shadow-copied volumes, so it is
        not treated as a security control.
        """
        if self._temp_dir is None:
            self._temp_dir = Path(
                tempfile.mkdtemp(prefix=f"{TEMP_DIR_PREFIX}{self.session_id[:8]}_")
            )
        return self._temp_dir

    def teardown(self) -> None:
        """Release all session state. Idempotent."""
        self.content_store.clear()
        self.token_vault.clear()
        self.allowlist.clear()
        self._results.clear()
        if self._temp_dir is not None and self._temp_dir.exists():
            shutil.rmtree(self._temp_dir, ignore_errors=True)
        self._temp_dir = None


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------
_contexts: dict[str, SessionContext] = {}
_registry_lock = threading.Lock()


def get_session_context(
    session_id: str, settings: Settings | None = None
) -> SessionContext:
    """Return the SessionContext for ``session_id``, creating it if needed."""
    with _registry_lock:
        ctx = _contexts.get(session_id)
        if ctx is None:
            ctx = SessionContext(session_id, settings)
            _contexts[session_id] = ctx
        else:
            # Touch on every access, so "idle" means no activity rather than
            # merely old. A long scan keeps its own session alive.
            ctx.last_touched = time.monotonic()
        return ctx


def drop_session_context(session_id: str) -> None:
    """Tear down and forget a session."""
    with _registry_lock:
        ctx = _contexts.pop(session_id, None)
    if ctx is not None:
        ctx.teardown()


def active_session_ids() -> tuple[str, ...]:
    with _registry_lock:
        return tuple(_contexts)


def reset_all_sessions() -> None:
    """Tear down every session. Test-support and shutdown hook."""
    for session_id in active_session_ids():
        drop_session_context(session_id)


def sweep_idle_sessions(max_idle_seconds: float | None = None) -> tuple[str, ...]:
    """Tear down sessions untouched for longer than the timeout.

    A retention control rather than memory hygiene. Streamlit gives no reliable
    browser-close signal, so without this every session that ever existed keeps
    its ContentStore — which holds the original file content. In a long-running
    process that is indefinite retention of exactly the data this tool exists to
    remove.

    Returns the ids swept, so a caller can log or surface the count.

    Teardown happens outside the registry lock: it removes a temp directory and
    clears several stores, and holding the lock across filesystem work would
    block every other session's lookup.
    """
    from pii_agent.utils.config import SESSION_IDLE_TIMEOUT_SECONDS

    limit = (
        SESSION_IDLE_TIMEOUT_SECONDS
        if max_idle_seconds is None
        else max_idle_seconds
    )
    now = time.monotonic()

    with _registry_lock:
        stale = [
            session_id
            for session_id, ctx in _contexts.items()
            if now - ctx.last_touched > limit
        ]
        contexts = [_contexts.pop(session_id) for session_id in stale]

    for ctx in contexts:
        ctx.teardown()

    return tuple(stale)


# ----------------------------------------------------------------------
# Shared read-only engines
# ----------------------------------------------------------------------
_shared_engines: dict[str, object] = {}
_engine_lock = threading.Lock()


def get_shared_engine(name: str, factory) -> object:
    """Get-or-create a process-wide, read-only engine.

    Only for stateless, expensive objects (Presidio AnalyzerEngine, loaded spaCy
    model). Anything holding session state must live on SessionContext instead.
    Callers must treat the result as immutable.
    """
    with _engine_lock:
        engine = _shared_engines.get(name)
        if engine is None:
            engine = factory()
            _shared_engines[name] = engine
        return engine


def reset_shared_engines() -> None:
    """Drop cached engines. Test-support only."""
    with _engine_lock:
        _shared_engines.clear()


# ----------------------------------------------------------------------
# Orphan sweep
# ----------------------------------------------------------------------
def sweep_orphan_temp_dirs(max_age_hours: int = ORPHAN_TEMP_DIR_MAX_AGE_HOURS) -> int:
    """Remove temp directories left behind by earlier runs (Requirement 44.6).

    A crashed or force-killed process cannot run its own cleanup, so orphans
    accumulate. Returns the number removed.
    """
    root = Path(tempfile.gettempdir())
    cutoff = time.time() - (max_age_hours * 3600)
    removed = 0
    try:
        candidates = list(root.glob(f"{TEMP_DIR_PREFIX}*"))
    except OSError:  # pragma: no cover - filesystem edge
        return 0

    for path in candidates:
        if not path.is_dir():
            continue
        try:
            if path.stat().st_mtime < cutoff:
                shutil.rmtree(path, ignore_errors=True)
                removed += 1
        except OSError:  # pragma: no cover - race with other cleanup
            continue
    return removed
