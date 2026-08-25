"""Regenerate docs/05-data-statement.md from the classification registry.

    python tools_dev/build_data_statement.py

Requirement 14.8 asks for a statement of what is stored and where, "maintained as part
of the deliberable rather than as tribal knowledge". Generating it is what makes that
true: a hand-written document about data placement is out of date the first time someone
adds a table, and it still reads as authoritative, which is worse than not having one.

``tests/explorer/storage/test_data_statement.py`` fails when the file on disk differs
from what this script produces, so a registry change that skips the regeneration does
not merge quietly.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from explorer.storage.classification import render_data_statement  # noqa: E402

OUTPUT = REPO_ROOT / "docs" / "05-data-statement.md"


def main() -> int:
    rendered = render_data_statement()
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    # newline="\n" explicitly. Windows would otherwise write CRLF, the test compares
    # against the rendered string with LF, and the failure would look like a content
    # difference rather than a line-ending one.
    with OUTPUT.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(rendered)

    print(f"wrote {OUTPUT.relative_to(REPO_ROOT)} ({len(rendered):,} chars)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
