"""Every dependency must be exact-pinned (guardrail G21).

Engine versions are recorded in every ProcessingResult and AuditRecord. A
floating version would silently change detection output and make a historical
compliance claim non-reproducible, so pinning is a correctness requirement
rather than housekeeping.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.paths import REQUIREMENTS_TXT

REQUIREMENTS = REQUIREMENTS_TXT


def _requirement_lines() -> list[str]:
    lines = []
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return lines


def test_requirements_file_exists():
    assert REQUIREMENTS.is_file()


def test_every_dependency_is_exact_pinned():
    unpinned = [
        line
        for line in _requirement_lines()
        # "==" is an exact pin; "@" is a pinned direct URL (the spaCy wheel).
        if "==" not in line and " @ " not in line
    ]
    assert unpinned == [], f"unpinned dependencies: {unpinned}"


def test_no_inequality_specifiers():
    """>=, <=, ~=, > and < all permit drift."""
    loose = [
        line
        for line in _requirement_lines()
        if any(op in line.split(";")[0] for op in (">=", "<=", "~=", "!="))
    ]
    assert loose == [], f"loose version specifiers: {loose}"


@pytest.mark.parametrize(
    "package",
    [
        "presidio-analyzer",
        "presidio-anonymizer",
        "spacy",
        "defusedxml",
        "langgraph",
        "langchain-openai",
        "streamlit",
        "PyYAML",
        "hypothesis",
    ],
)
def test_required_package_present(package: str):
    text = REQUIREMENTS.read_text(encoding="utf-8")
    assert package in text, f"{package} missing from requirements.txt"


def test_spacy_model_pinned_by_wheel_url():
    """`spacy download` resolves a floating version — the wheel URL does not."""
    text = REQUIREMENTS.read_text(encoding="utf-8")
    assert "en_core_web_lg" in text
    assert "en_core_web_lg-3.8.0-py3-none-any.whl" in text


def test_installed_versions_match_pins():
    """The running environment must match what audit records will claim."""
    from pii_agent.utils.config import verify_engine_versions

    assert verify_engine_versions() == []
