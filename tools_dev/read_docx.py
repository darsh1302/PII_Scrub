"""Extract plain text from a .docx, including tables.

    venv\\Scripts\\python tools_dev\\read_docx.py <path-to.docx>

Stdlib only — a .docx is a zip containing ``word/document.xml``, so no dependency
is needed and none is added to requirements.txt for a dev-only tool.

Written because requirements documents arrive as Word files and pasting one into a
chat loses the bytes. Reading it from disk is lossless.
"""

from __future__ import annotations

import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree

W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"


def _paragraph_text(node) -> str:
    """Concatenate the runs in a paragraph, honouring explicit breaks."""
    parts: list[str] = []
    for child in node.iter():
        if child.tag == f"{W}t":
            parts.append(child.text or "")
        elif child.tag in (f"{W}tab",):
            parts.append("\t")
        elif child.tag in (f"{W}br", f"{W}cr"):
            parts.append("\n")
    return "".join(parts)


def _style(node) -> str:
    """Paragraph style name, used to reconstruct heading levels."""
    style = node.find(f"{W}pPr/{W}pStyle")
    return style.get(f"{W}val", "") if style is not None else ""


def extract(path: Path) -> str:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if "word/document.xml" not in names:
            raise SystemExit(
                f"{path.name} has no word/document.xml — is it really a .docx? "
                f"(entries: {', '.join(names[:5])}...)"
            )
        xml = archive.read("word/document.xml")

    root = ElementTree.fromstring(xml)
    body = root.find(f"{W}body")
    if body is None:
        raise SystemExit("no document body found")

    lines: list[str] = []
    for node in body:
        if node.tag == f"{W}p":
            text = _paragraph_text(node).strip()
            if not text:
                continue
            style = _style(node)
            if style.startswith("Heading"):
                level = style.replace("Heading", "").strip() or "1"
                try:
                    hashes = "#" * min(int(level), 6)
                except ValueError:
                    hashes = "#"
                lines.append(f"\n{hashes} {text}")
            elif style.startswith("ListParagraph"):
                lines.append(f"- {text}")
            else:
                lines.append(text)

        elif node.tag == f"{W}tbl":
            # Rendered as a pipe table so requirement tables stay readable.
            for row in node.findall(f"{W}tr"):
                cells = [
                    " ".join(
                        _paragraph_text(p).strip()
                        for p in cell.findall(f"{W}p")
                    ).strip()
                    for cell in row.findall(f"{W}tc")
                ]
                if any(cells):
                    lines.append("| " + " | ".join(cells) + " |")
            lines.append("")

    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    path = Path(sys.argv[1]).expanduser()
    if not path.is_file():
        print(f"not found: {path}")
        return 1

    text = extract(path)

    # Written before printing. A Windows console defaults to cp1252 and raises
    # UnicodeEncodeError on the curly quotes and dashes Word inserts, which would
    # otherwise lose the extraction after doing all the work.
    out = path.with_suffix(".extracted.md")
    out.write_text(text, encoding="utf-8", newline="\n")

    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    print(text)
    print(f"\n---\n{len(text):,} characters written to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
