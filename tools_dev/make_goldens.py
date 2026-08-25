"""Generate golden detection results for the regression suite.

Task 9.5. Guardrails G18, G21.

    venv\\Scripts\\python tools_dev\\make_goldens.py

Run this **deliberately**, never as a fix for a failing test. A golden file
changing means detection output changed; the question is always whether that
change was intended. Regenerating to make a red test go green destroys the only
evidence that anything moved.

Goldens record type, span, rounded confidence, detecting engine and resolved
action — never entity text. The fixtures are committed, so storing values would
duplicate PII into a second file for no benefit.

Each file carries the engine-version tuple that produced it. The regression test
skips with a loud message when the installed tuple differs, because a comparison
across versions is meaningless rather than failing.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from pii_agent.core.file_source import load_file  # noqa: E402
from pii_agent.core.pipeline import ScanOptions, scan  # noqa: E402
from pii_agent.models.enums import Destination  # noqa: E402
from pii_agent.models.results import EngineVersions  # noqa: E402
from pii_agent.session.context import get_session_context  # noqa: E402
from pii_agent.utils.config import Settings  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures"
GOLDEN_DIR = FIXTURES / "golden"

# (fixture, profile). Chosen to cover each profile against content it should have
# opinions about, plus a clean file to catch false positives appearing.
CASES: list[tuple[str, str]] = [
    ("sample_clean.txt", "DEFAULT_PII"),
    ("sample_log.txt", "DEFAULT_PII"),
    ("sample_log.txt", "BASE_SECURITY"),
    ("sample_pii.json", "DEFAULT_PII"),
    ("sample_adversarial.txt", "DEFAULT_PII"),
    ("sample_healthcare.csv", "DEFAULT_PII"),
    # sample_pem_straddle.txt (69 KB) and sample_deep.json (60 KB) are
    # deliberately excluded. Together they were ~4 of the 5 minutes this suite
    # took, and what they exercise — a PEM block spanning a chunk boundary, deep
    # nesting — already has dedicated tests. Goldens exist to catch detection
    # drift, and drift shows up just as clearly on a small dense fixture.
    ("golden_financial.log", "FINANCIAL"),
    ("golden_financial.log", "PAYMENT_PCI"),
    ("golden_ai_trace.log", "AI_SAAS"),
    ("golden_ai_trace.log", "DEFAULT_PII"),
]


def build_session(root: Path):
    settings = Settings(
        openai_api_key="sk-golden",
        token_vault_salt=b"golden-fixed-salt-for-reproducibility",
        scan_roots=(root.resolve(),),
        audit_dir=ROOT / "var" / "audit",
    )
    return get_session_context("golden-generator", settings)


def snapshot(fixture: str, profile: str, session) -> dict:
    result = scan(
        load_file(str(FIXTURES / fixture), session).handle,
        session,
        ScanOptions(
            profile_names=(profile,), destination=Destination.INTERNAL_SIEM
        ),
    )

    actions = {
        (d.entity.type, d.entity.start, d.entity.end): d.applied_action.value
        for d in result.decisions
    }

    entities = [
        {
            "type": e.type,
            "start": e.start,
            "end": e.end,
            "confidence": round(float(e.confidence), 4),
            "detected_by": sorted(e.detected_by),
            "action": actions.get((e.type, e.start, e.end), "NONE"),
        }
        for e in result.entities
    ]
    # Sorted so the file is stable regardless of detection ordering.
    entities.sort(key=lambda e: (e["start"], e["end"], e["type"]))

    return {
        "fixture": fixture,
        "profile": profile,
        "engine_versions": EngineVersions.detect(profile).to_metadata(),
        "entity_count": result.entity_count,
        "entity_breakdown": result.entity_breakdown(),
        "severity_breakdown": result.severity_breakdown(),
        "action_counts": result.decisions.action_counts(),
        "coverage_percent": result.coverage.coverage_percent,
        "status": result.status,
        "refusal": result.refusal.value if result.refusal else None,
        "entities": entities,
    }


def main() -> int:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    session = build_session(FIXTURES)

    written = 0
    for fixture, profile in CASES:
        if not (FIXTURES / fixture).is_file():
            print(f"  SKIP  {fixture} (missing)")
            continue

        data = snapshot(fixture, profile, session)
        out = GOLDEN_DIR / f"{Path(fixture).stem}__{profile}.json"
        out.write_text(
            json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(
            f"  {out.name:44} {data['entity_count']:4} entities  "
            f"status={data['status']}"
        )
        written += 1

    print(f"\n{written} golden files in {GOLDEN_DIR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
