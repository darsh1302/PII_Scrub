"""Golden-result regression tests.

Task 9.5. Guardrails G18, G21.

Detection output is the product. A refactor that quietly changes which entities
are found, or what policy resolves them to, is the most dangerous class of
regression here: everything still passes, the pipeline still reports success, and
the difference only shows up as data that leaked or data that was destroyed.

These tests compare against committed snapshots of type, span, confidence,
detecting engine and resolved action for a set of fixture/profile pairs.

**Version keying.** Every golden carries the engine-version tuple that produced
it. When the installed tuple differs the comparison is meaningless rather than
wrong, so the test fails with an explicit instruction rather than reporting a
false regression. That is deliberate: silently skipping would let a version bump
disable the whole suite unnoticed.

Regenerate with ``python tools_dev/make_goldens.py`` — and only when the change
in output was intended.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from pii_agent.core.file_source import load_file
from pii_agent.core.pipeline import ScanOptions, scan
from pii_agent.models.enums import Destination
from pii_agent.models.results import EngineVersions
from pii_agent.session.context import get_session_context
from pii_agent.utils.config import Settings

FIXTURES = Path(__file__).parent / "fixtures"
GOLDEN_DIR = FIXTURES / "golden"

# Must match tools_dev/make_goldens.py, or tokens will not reproduce.
GOLDEN_SALT = b"golden-fixed-salt-for-reproducibility"

GOLDEN_FILES = sorted(GOLDEN_DIR.glob("*.json")) if GOLDEN_DIR.is_dir() else []


@pytest.fixture
def golden_session(tmp_path):
    settings = Settings(
        openai_api_key="sk-golden",
        token_vault_salt=GOLDEN_SALT,
        scan_roots=(FIXTURES.resolve(),),
        audit_dir=tmp_path / "audit",
    )
    return get_session_context(f"golden-{tmp_path.name}", settings)


def _ids(path: Path) -> str:
    return path.stem


def test_golden_directory_is_populated():
    """A missing golden set would make every case below vacuously pass."""
    assert GOLDEN_FILES, (
        "no golden files found — run: python tools_dev/make_goldens.py"
    )


def _version_key(metadata: dict) -> tuple:
    """The subset of engine metadata that can change detection output.

    Profile name and version are excluded: they are part of the case identity
    rather than the environment, and are asserted separately.
    """
    return (
        metadata.get("presidio_analyzer"),
        metadata.get("presidio_anonymizer"),
        metadata.get("spacy"),
        metadata.get("spacy_model"),
    )


@pytest.mark.parametrize("golden_path", GOLDEN_FILES, ids=_ids)
def test_detection_matches_golden(golden_path: Path, golden_session):
    golden = json.loads(golden_path.read_text(encoding="utf-8"))
    fixture = golden["fixture"]
    profile = golden["profile"]

    expected_versions = _version_key(golden["engine_versions"])
    actual_versions = _version_key(
        EngineVersions.detect(profile).to_metadata()
    )
    if expected_versions != actual_versions:
        pytest.fail(
            f"{golden_path.name} was produced with engine versions "
            f"{expected_versions} but the installed environment is "
            f"{actual_versions}. Detection output is not comparable across "
            f"versions. If the upgrade was intended, regenerate with "
            f"python tools_dev/make_goldens.py and review the diff."
        )

    result = scan(
        load_file(str(FIXTURES / fixture), golden_session).handle,
        golden_session,
        ScanOptions(
            profile_names=(profile,), destination=Destination.INTERNAL_SIEM
        ),
    )

    # Aggregates first: a failure here localises the change faster than a
    # 40-element span diff.
    assert result.status == golden["status"], f"{fixture}/{profile}: status"
    assert result.entity_count == golden["entity_count"], (
        f"{fixture}/{profile}: entity count "
        f"{result.entity_count} vs golden {golden['entity_count']}"
    )
    assert result.entity_breakdown() == golden["entity_breakdown"], (
        f"{fixture}/{profile}: entity breakdown changed"
    )
    assert result.severity_breakdown() == golden["severity_breakdown"], (
        f"{fixture}/{profile}: severity breakdown changed"
    )
    assert result.decisions.action_counts() == golden["action_counts"], (
        f"{fixture}/{profile}: resolved actions changed — a policy change is "
        f"the most consequential kind of regression here"
    )
    assert result.coverage.coverage_percent == golden["coverage_percent"]

    # Then the exact spans.
    actions = {
        (d.entity.type, d.entity.start, d.entity.end): d.applied_action.value
        for d in result.decisions
    }
    actual = sorted(
        (
            {
                "type": e.type,
                "start": e.start,
                "end": e.end,
                "confidence": round(float(e.confidence), 4),
                "detected_by": sorted(e.detected_by),
                "action": actions.get((e.type, e.start, e.end), "NONE"),
            }
            for e in result.entities
        ),
        key=lambda e: (e["start"], e["end"], e["type"]),
    )

    assert actual == golden["entities"], (
        f"{fixture}/{profile}: entity spans, confidences, detectors or actions "
        f"differ from the golden snapshot"
    )


@pytest.mark.parametrize("golden_path", GOLDEN_FILES, ids=_ids)
def test_golden_files_contain_no_entity_text(golden_path: Path):
    """A golden must not become a second copy of the PII in the fixture.

    Spans and counts are enough to detect a regression. Values would duplicate
    sensitive data into a file that looks like test metadata.
    """
    raw = golden_path.read_text(encoding="utf-8")
    for value in (
        "482-71-9053",
        "4532015112830366",
        "dana.reyes@example.com",
        "sk-ant-api03",
        "Tr0ub4dor",
        "021000021",
    ):
        assert value not in raw, (
            f"{golden_path.name} contains the literal value {value!r} — "
            f"goldens record spans, never entity text"
        )
