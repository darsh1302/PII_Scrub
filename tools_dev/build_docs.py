"""Render the project Markdown docs to standalone styled HTML.

Run:  venv\\Scripts\\python tools_dev\\build_docs.py

Kept as a build step rather than hand-written HTML so the two never drift: the
Markdown is the source, and the HTML is generated from it. Uses markdown-it-py,
which arrives as a Streamlit dependency, so nothing new is added to
requirements.txt for a dev-only tool.

Fenced ``mermaid`` blocks are turned into ``<pre class="mermaid">`` and rendered
client-side, matching the existing design dashboard.
"""

from __future__ import annotations

import html
import re
import sys
from pathlib import Path

from markdown_it import MarkdownIt

ROOT = Path(__file__).resolve().parent.parent

# (source, output, nav title)
#
# All generated HTML lands in docs/dashboards/, so the repository root stays
# readable and one directory holds every artifact this script produces.
DASHBOARDS = ROOT / "docs" / "dashboards"

PAGES: list[tuple[Path, Path, str]] = [
    (ROOT / "README.md", DASHBOARDS / "README.html", "Overview"),
    (
        ROOT / "docs/01-how-it-works.md",
        DASHBOARDS / "01-how-it-works.html",
        "How it works",
    ),
    (
        ROOT / "docs/02-architecture-and-flow.md",
        DASHBOARDS / "02-architecture-and-flow.html",
        "Architecture",
    ),
    (ROOT / "docs/03-setup.md", DASHBOARDS / "03-setup.html", "Setup"),
    (
        ROOT / "docs/04-functionality-and-prompts.md",
        DASHBOARDS / "04-functionality-and-prompts.html",
        "Functionality",
    ),
    (
        ROOT / "docs/05-data-statement.md",
        DASHBOARDS / "05-data-statement.html",
        "Data statement",
    ),
    (
        ROOT / "docs/demo-script.md",
        DASHBOARDS / "demo-script.html",
        "Demo script",
    ),
]

STYLE = """
:root {
  --bg: #0f1419;
  --panel: #161c24;
  --border: #2a333f;
  --text: #dbe4ee;
  --muted: #8b9bb0;
  --accent: #4db6ac;
  --accent-dim: #26706a;
  --code-bg: #0b0f14;
  --warn: #e6a23c;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font: 16px/1.65 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}
.wrap { display: flex; min-height: 100vh; }
nav {
  width: 240px;
  flex: 0 0 240px;
  background: var(--panel);
  border-right: 1px solid var(--border);
  padding: 28px 20px;
  position: sticky;
  top: 0;
  height: 100vh;
  overflow-y: auto;
}
nav .brand {
  font-weight: 700;
  font-size: 15px;
  letter-spacing: .02em;
  margin-bottom: 22px;
  color: #fff;
}
nav a {
  display: block;
  padding: 8px 10px;
  margin-bottom: 4px;
  border-radius: 6px;
  color: var(--muted);
  text-decoration: none;
  font-size: 14px;
}
nav a:hover { background: #1d252f; color: var(--text); }
nav a.active {
  background: var(--accent-dim);
  color: #fff;
  font-weight: 600;
}
main { flex: 1; min-width: 0; padding: 48px 56px 96px; max-width: 960px; }
h1, h2, h3, h4 { color: #fff; line-height: 1.25; }
h1 { font-size: 31px; margin: 0 0 26px; }
h2 {
  font-size: 22px;
  margin: 44px 0 14px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}
h3 { font-size: 17px; margin: 30px 0 10px; }
p { margin: 0 0 14px; }
a { color: var(--accent); }
ul, ol { margin: 0 0 14px; padding-left: 24px; }
li { margin-bottom: 6px; }
strong { color: #fff; }
code {
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-radius: 4px;
  padding: 1px 5px;
  font: 13.5px/1.5 "Cascadia Code", Consolas, ui-monospace, monospace;
  color: #9ad9d1;
}
pre {
  background: var(--code-bg);
  border: 1px solid var(--border);
  border-left: 3px solid var(--accent-dim);
  border-radius: 6px;
  padding: 14px 16px;
  overflow-x: auto;
  margin: 0 0 18px;
}
pre code { background: none; border: 0; padding: 0; color: #cfe3e0; }
table {
  border-collapse: collapse;
  width: 100%;
  margin: 0 0 20px;
  font-size: 14.5px;
  display: block;
  overflow-x: auto;
}
th, td {
  border: 1px solid var(--border);
  padding: 9px 12px;
  text-align: left;
  vertical-align: top;
}
th { background: #1d252f; color: #fff; font-weight: 600; }
tr:nth-child(even) td { background: #131922; }
blockquote {
  margin: 0 0 18px;
  padding: 10px 16px;
  border-left: 3px solid var(--warn);
  background: #1d1a14;
  color: #e8d9bd;
}
hr { border: 0; border-top: 1px solid var(--border); margin: 32px 0; }
pre.mermaid {
  background: #f7fbfa;
  border-left-color: var(--accent);
  text-align: center;
}
footer {
  margin-top: 56px;
  padding-top: 18px;
  border-top: 1px solid var(--border);
  color: var(--muted);
  font-size: 13px;
}
@media (max-width: 860px) {
  .wrap { flex-direction: column; }
  nav { width: 100%; flex: none; height: auto; position: static; }
  main { padding: 28px 20px 64px; }
}
"""

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · PII Scrubbing Agent</title>
<style>{style}</style>
</head>
<body>
<div class="wrap">
<nav>
  <div class="brand">🛡️ PII Scrubbing Agent</div>
{nav}
</nav>
<main>
{body}
<footer>Generated from {source} by <code>tools_dev/build_docs.py</code>. \
The Markdown is the source of truth.</footer>
</main>
</div>
<script type="module">
  import mermaid from "https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs";
  mermaid.initialize({{ startOnLoad: true, theme: "neutral" }});
</script>
</body>
</html>
"""

_MERMAID_BLOCK = re.compile(
    r'<pre><code class="language-mermaid">(.*?)</code></pre>', re.DOTALL
)


def _relative(target: Path, from_page: Path) -> str:
    """Link between generated pages, kept relative so the files stay portable."""
    import os

    return os.path.relpath(target, from_page.parent).replace("\\", "/")


def _nav(current: Path) -> str:
    items = []
    for _, out, label in PAGES:
        active = ' class="active"' if out == current else ""
        items.append(f'  <a href="{_relative(out, current)}"{active}>{label}</a>')
    return "\n".join(items)


def _fix_internal_links(body: str) -> str:
    """Point cross-document links at the generated HTML rather than the Markdown."""
    for source, out, _ in PAGES:
        body = body.replace(f'href="{source.name}"', f'href="{out.name}"')
        body = body.replace(
            f'href="docs/{source.name}"', f'href="docs/{out.name}"'
        )
    return body


def render(source: Path, out: Path, title: str) -> None:
    md = MarkdownIt("default").enable("table")
    body = md.render(source.read_text(encoding="utf-8"))

    # Mermaid must reach the browser unescaped, inside a plain <pre>.
    body = _MERMAID_BLOCK.sub(
        lambda m: f'<pre class="mermaid">{html.unescape(m.group(1))}</pre>', body
    )
    body = _fix_internal_links(body)

    out.write_text(
        TEMPLATE.format(
            title=title,
            style=STYLE,
            nav=_nav(out),
            body=body,
            source=source.name,
        ),
        encoding="utf-8",
    )
    print(f"  {source.name:38} -> {out.relative_to(ROOT)}")


def main() -> int:
    missing = [str(s) for s, _, _ in PAGES if not s.exists()]
    if missing:
        print("missing source files:", ", ".join(missing))
        return 1

    print("Building HTML docs:")
    for source, out, title in PAGES:
        out.parent.mkdir(parents=True, exist_ok=True)
        render(source, out, title)
    print(f"Done — {len(PAGES)} pages.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
