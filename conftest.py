"""Pytest configuration and shared fixtures."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

# Ensure the project root is importable when pytest is invoked from anywhere.
ROOT = Path(__file__).parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from pii_agent.session.context import reset_all_sessions, reset_shared_engines  # noqa: E402
from pii_agent.utils.config import Settings  # noqa: E402

# Presidio logs a warning per non-English recognizer it declines to register,
# on every engine construction. Dozens of lines that say nothing about our code.
logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)


@pytest.fixture(autouse=True)
def _isolate_sessions():
    """Reset per-session state between tests.

    Deliberately does NOT reset shared detection engines. Those are the Presidio
    AnalyzerEngine and the loaded spaCy model, both read-only by contract (see
    ``get_shared_engine``), so rebuilding them provides no isolation.

    It provides no isolation and costs a great deal: measured at 3.1s per
    rebuild against 0.011s for the detection work it enables — a 276x overhead
    that accounted for roughly ten of the suite's twelve minutes. Tests that
    genuinely need a fresh engine can request the ``fresh_engines`` fixture.
    """
    reset_all_sessions()
    yield
    reset_all_sessions()


@pytest.fixture
def fresh_engines():
    """Force detection engines to be rebuilt for this test.

    Only needed when a test alters how an engine is *constructed* — patching
    ``_build_analyzer`` or ``_build_spacy``. Tests that patch the accessors
    (``get_analyzer``, ``get_spacy``) bypass the cache already and do not need
    this.
    """
    reset_shared_engines()
    yield
    reset_shared_engines()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Valid settings pointing at a temp audit dir and scan root."""
    scan_root = tmp_path / "scan"
    scan_root.mkdir()
    return Settings(
        openai_api_key="sk-test-not-a-real-key",
        token_vault_salt=b"test-salt",
        scan_roots=(scan_root.resolve(),),
        bind_address="127.0.0.1",
        allow_remote=False,
        audit_dir=tmp_path / "audit",
    )
