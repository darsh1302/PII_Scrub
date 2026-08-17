"""Hardened parsing for structured input.

Guardrail G12. Addresses review finding SEC-10.

The design supports ``.xml``, ``.json``, ``.jsonl`` and ``.csv``, and inspects
nested structure. Standard parsers make that a liability:

* **XXE** — an external entity in XML reads arbitrary local files or makes
  outbound requests. That turns a scan request into file disclosure, which is
  precisely what this tool exists to prevent.
* **Billion laughs** — nested entity expansion exhausts memory from a few
  hundred bytes of input.
* **Deep nesting** — ``json.loads`` recurses; ~10k levels exhausts the stack.

Everything here fails with a structured, content-free error rather than a raw
parser exception, because parser messages routinely quote the offending input.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from typing import Any, Iterator

# defusedxml disables entity resolution, DTD processing, and expansion.
from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from utils.config import (
    MAX_CSV_FIELDS,
    MAX_CSV_ROW_CHARS,
    MAX_JSON_DEPTH,
    MAX_JSON_NODES,
)


class ParseRefused(ValueError):
    """Raised when input exceeds a structural limit or is malformed.

    Never contains the offending content.
    """


@dataclass
class ExtractedField:
    """One scannable value found in a structured document.

    Both ``path`` and ``value`` are scanned: a key named ``password`` is a
    signal even when its value looks unremarkable (Requirement 14.4).
    """

    path: str
    value: str
    is_key: bool = False


@dataclass
class ParsedDocument:
    """Result of structured parsing."""

    fields: list[ExtractedField] = field(default_factory=list)
    node_count: int = 0
    max_depth: int = 0
    truncated: bool = False

    def scannable_text(self) -> str:
        """Flatten to text for detection, preserving field paths as context."""
        return "\n".join(f"{f.path}: {f.value}" for f in self.fields)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------
def _walk_json(
    node: Any,
    path: str,
    depth: int,
    state: dict[str, int],
    out: list[ExtractedField],
) -> None:
    """Recursive walk with depth and node budgets enforced as we go.

    Budgets are checked during traversal, not afterwards: the point is to stop
    before exhausting memory or stack, so a post-hoc check would be useless.
    """
    if depth > MAX_JSON_DEPTH:
        raise ParseRefused(
            f"structure nests deeper than {MAX_JSON_DEPTH} levels and was "
            "refused (protects against recursion exhaustion)"
        )

    state["nodes"] += 1
    if state["nodes"] > MAX_JSON_NODES:
        raise ParseRefused(
            f"structure contains more than {MAX_JSON_NODES:,} nodes and was "
            "refused"
        )
    state["depth"] = max(state["depth"], depth)

    if isinstance(node, dict):
        for key, value in node.items():
            child_path = f"{path}.{key}" if path else str(key)
            # Property names are themselves inspected.
            out.append(ExtractedField(path=child_path, value=str(key), is_key=True))
            _walk_json(value, child_path, depth + 1, state, out)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk_json(value, f"{path}[{index}]", depth + 1, state, out)
    elif node is not None:
        out.append(ExtractedField(path=path or "$", value=str(node)))


def parse_json(text: str) -> ParsedDocument:
    """Parse JSON with depth and node caps."""
    try:
        data = json.loads(text)
    except RecursionError:
        raise ParseRefused(
            "structure nests too deeply to parse safely and was refused"
        ) from None
    except json.JSONDecodeError as exc:
        raise ParseRefused(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}"
        ) from None

    fields: list[ExtractedField] = []
    state = {"nodes": 0, "depth": 0}
    _walk_json(data, "", 0, state, fields)
    return ParsedDocument(
        fields=fields, node_count=state["nodes"], max_depth=state["depth"]
    )


def parse_jsonl(text: str) -> ParsedDocument:
    """Parse newline-delimited JSON.

    A malformed line is recorded as raw text rather than aborting the document:
    log files routinely contain a truncated final line, and refusing the whole
    file over it would be unhelpful.
    """
    fields: list[ExtractedField] = []
    total_nodes = 0
    max_depth = 0

    for line_number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            data = json.loads(stripped)
        except (json.JSONDecodeError, RecursionError):
            fields.append(
                ExtractedField(path=f"line[{line_number}]", value=stripped)
            )
            continue

        state = {"nodes": 0, "depth": 0}
        line_fields: list[ExtractedField] = []
        _walk_json(data, f"line[{line_number}]", 0, state, line_fields)
        fields.extend(line_fields)
        total_nodes += state["nodes"]
        max_depth = max(max_depth, state["depth"])

    return ParsedDocument(
        fields=fields, node_count=total_nodes, max_depth=max_depth
    )


# ---------------------------------------------------------------------------
# XML
# ---------------------------------------------------------------------------
def _walk_xml(element, path: str, depth: int, state: dict[str, int], out: list) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ParseRefused(
            f"XML nests deeper than {MAX_JSON_DEPTH} levels and was refused"
        )

    state["nodes"] += 1
    if state["nodes"] > MAX_JSON_NODES:
        raise ParseRefused(
            f"XML contains more than {MAX_JSON_NODES:,} nodes and was refused"
        )
    state["depth"] = max(state["depth"], depth)

    tag = element.tag if isinstance(element.tag, str) else "?"
    node_path = f"{path}/{tag}" if path else tag

    for attr_name, attr_value in (element.attrib or {}).items():
        out.append(
            ExtractedField(
                path=f"{node_path}@{attr_name}", value=str(attr_name), is_key=True
            )
        )
        out.append(
            ExtractedField(path=f"{node_path}@{attr_name}", value=str(attr_value))
        )

    if element.text and element.text.strip():
        out.append(ExtractedField(path=node_path, value=element.text.strip()))

    for child in element:
        _walk_xml(child, node_path, depth + 1, state, out)

    if element.tail and element.tail.strip():
        out.append(
            ExtractedField(path=f"{node_path}#tail", value=element.tail.strip())
        )


def parse_xml(text: str) -> ParsedDocument:
    """Parse XML with defusedxml — no entities, no DTDs, no expansion."""
    try:
        root = SafeET.fromstring(text)
    except DefusedXmlException as exc:
        # An explicit attack signal, not an accident.
        raise ParseRefused(
            f"XML uses a construct that is disabled for security "
            f"({exc.__class__.__name__}). External entities, DTDs, and entity "
            f"expansion are not processed — they can read local files or "
            f"exhaust memory."
        ) from None
    except SafeET.ParseError as exc:
        raise ParseRefused(f"invalid XML: {exc.msg}") from None
    except RecursionError:
        raise ParseRefused(
            "XML nests too deeply to parse safely and was refused"
        ) from None

    fields: list[ExtractedField] = []
    state = {"nodes": 0, "depth": 0}
    _walk_xml(root, "", 0, state, fields)
    return ParsedDocument(
        fields=fields, node_count=state["nodes"], max_depth=state["depth"]
    )


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------
def parse_csv(text: str) -> ParsedDocument:
    """Parse CSV with field-count and row-length caps."""
    fields: list[ExtractedField] = []
    node_count = 0

    # csv has its own recursion-free parser but will happily build huge rows.
    try:
        sample = text[:8192]
        dialect = csv.Sniffer().sniff(sample) if sample.strip() else csv.excel
    except csv.Error:
        dialect = csv.excel

    reader = csv.reader(io.StringIO(text), dialect)
    header: list[str] = []

    for row_index, row in enumerate(reader):
        if len(row) > MAX_CSV_FIELDS:
            raise ParseRefused(
                f"row {row_index + 1} has {len(row)} fields, over the "
                f"{MAX_CSV_FIELDS} limit"
            )
        row_chars = sum(len(cell) for cell in row)
        if row_chars > MAX_CSV_ROW_CHARS:
            raise ParseRefused(
                f"row {row_index + 1} is {row_chars:,} characters, over the "
                f"{MAX_CSV_ROW_CHARS:,} limit"
            )

        if row_index == 0:
            header = [cell.strip() for cell in row]
            for cell in header:
                if cell:
                    fields.append(
                        ExtractedField(path="header", value=cell, is_key=True)
                    )
                    node_count += 1
            continue

        for col_index, cell in enumerate(row):
            if not cell.strip():
                continue
            column = (
                header[col_index]
                if col_index < len(header) and header[col_index]
                else f"col{col_index}"
            )
            fields.append(
                ExtractedField(path=f"row[{row_index}].{column}", value=cell)
            )
            node_count += 1

    return ParsedDocument(fields=fields, node_count=node_count, max_depth=2)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
_PARSERS = {
    ".json": parse_json,
    ".jsonl": parse_jsonl,
    ".xml": parse_xml,
    ".csv": parse_csv,
}


def is_structured(extension: str) -> bool:
    return extension.lower() in _PARSERS


def parse_structured(text: str, extension: str) -> ParsedDocument:
    """Parse by extension. Raises ParseRefused on limit or malformed input."""
    parser = _PARSERS.get(extension.lower())
    if parser is None:
        raise ParseRefused(f"no structured parser for '{extension}'")
    return parser(text)


def parse_or_fallback(text: str, extension: str) -> tuple[str, ParsedDocument | None]:
    """Parse structurally, falling back to plain text.

    Structure adds field-path context, which improves detection. When it is
    unavailable the content is still scanned as text — losing context is
    acceptable, losing coverage is not.
    """
    if not is_structured(extension):
        return text, None
    try:
        document = parse_structured(text, extension)
    except ParseRefused:
        return text, None
    return document.scannable_text(), document
