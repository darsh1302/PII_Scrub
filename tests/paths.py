"""Anchors for paths that tests need, resolved once.

Several tests previously computed the repository root by counting ``.parent``
levels — ``Path(__file__).parent.parent.parent``. That is correct until a test
moves directory, at which point it silently resolves somewhere else and the
failure looks like a missing file rather than a wrong path. Moving the suites under
``tests/pii_agent/`` broke exactly that in three places.

Anchoring on a marker file instead means a test can move without its paths
changing.
"""

from __future__ import annotations

from pathlib import Path


def _find_repo_root() -> Path:
    """Walk upward to the directory holding pyproject.toml."""
    for candidate in [Path(__file__).resolve(), *Path(__file__).resolve().parents]:
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise RuntimeError(
        "could not locate the repository root — no pyproject.toml found above "
        f"{Path(__file__).resolve()}"
    )


REPO_ROOT = _find_repo_root()

PII_AGENT_DIR = REPO_ROOT / "pii_agent"
PROFILES_DIR = PII_AGENT_DIR / "profiles"
REQUIREMENTS_TXT = REPO_ROOT / "requirements.txt"
DATA_SAMPLES = REPO_ROOT / "data" / "samples"
