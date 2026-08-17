"""File source adapter.

Reads a sandboxed file, parses it if structured, stores content in the session
ContentStore, and returns a handle plus metadata. The content itself never
leaves the process (guardrail G1).

Decoding note: log files are frequently not valid UTF-8 — mixed encodings, or
binary fragments from a crash dump. Decoding with ``errors="replace"`` keeps
scanning possible rather than refusing the file, and the substitution count is
reported so the user knows the source was imperfect.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from models.enums import SourceType
from session.context import SessionContext
from utils.paths import PathRefused, ResolvedFile, open_verified
from utils.safe_parsers import ParsedDocument, parse_or_fallback


@dataclass
class LoadedSource:
    """Outcome of loading a source into the ContentStore."""

    handle: str
    source_type: SourceType
    display_name: str
    bytes_total: int
    char_total: int
    line_count: int
    extension: str
    structured: bool = False
    parsed_field_count: int = 0
    decode_substitutions: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_metadata(self) -> dict[str, object]:
        """Safe for the reasoning context — describes the file, not its content."""
        return {
            "handle": self.handle,
            "source_type": self.source_type.value,
            "name": self.display_name,
            "size_bytes": self.bytes_total,
            "size_mb": round(self.bytes_total / 1048576, 3),
            "characters": self.char_total,
            "lines": self.line_count,
            "extension": self.extension,
            "structured": self.structured,
            "parsed_fields": self.parsed_field_count,
            "warnings": list(self.warnings),
        }


def _decode(raw: bytes) -> tuple[str, int]:
    """Decode bytes to text, counting substitutions.

    Tries UTF-8 strictly first, then UTF-8 with replacement. A refusal here
    would block scanning of exactly the damaged logs most likely to contain
    accidentally-written secrets.
    """
    try:
        return raw.decode("utf-8"), 0
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
        return text, text.count("\ufffd")


def load_file(
    raw_path: str,
    session: SessionContext,
    *,
    max_size_mb: int | None = None,
) -> LoadedSource:
    """Load a local file into the session ContentStore.

    Raises PathRefused when the path is outside the sandbox, denylisted, an
    unsupported type, oversize, or substituted mid-open.
    """
    handle_io, resolved = open_verified(
        raw_path, session.settings, max_size_mb=max_size_mb
    )
    try:
        raw = handle_io.read()
    finally:
        handle_io.close()

    return _ingest(raw, resolved, session, SourceType.FILE)


def load_upload(
    data: bytes,
    filename: str,
    session: SessionContext,
) -> LoadedSource:
    """Load an uploaded file from memory.

    Uploads bypass the scan-root allowlist because the user supplied the bytes
    directly — there is no filesystem to escape. Size and type limits still
    apply.
    """
    from pathlib import Path

    from utils.config import MAX_FILE_SIZE_MB, SUPPORTED_FILE_EXTENSIONS

    extension = Path(filename).suffix.lower()
    if extension not in SUPPORTED_FILE_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_FILE_EXTENSIONS))
        raise PathRefused(
            f"unsupported file type '{extension or filename}'. "
            f"Supported: {supported}"
        )

    limit = MAX_FILE_SIZE_MB * 1024 * 1024
    if len(data) > limit:
        raise PathRefused(
            f"'{filename}' is {len(data) / 1048576:.1f} MB, over the "
            f"{MAX_FILE_SIZE_MB} MB limit"
        )

    resolved = ResolvedFile(
        display_path=Path(filename).name,
        real_path=Path(filename),
        size_bytes=len(data),
        extension=extension,
        inode_key=(0, 0),
    )
    return _ingest(data, resolved, session, SourceType.FILE)


def load_text(
    text: str,
    session: SessionContext,
    *,
    label: str = "pasted text",
) -> LoadedSource:
    """Load text pasted directly into chat."""
    from utils.config import MAX_TEXT_LENGTH_CHARS

    warnings: list[str] = []
    if len(text) > MAX_TEXT_LENGTH_CHARS:
        raise PathRefused(
            f"text is {len(text):,} characters, over the "
            f"{MAX_TEXT_LENGTH_CHARS:,} limit. Split it, or save it to a file "
            f"in a configured scan root."
        )

    handle = session.content_store.put(
        text,
        source_type=SourceType.TEXT.value,
        source_identifier=label,
        # display_name lets the agent reach this by the name the user sees,
        # which is the only route for content with no path in a scan root.
        metadata={"structured": False, "display_name": label},
    )
    return LoadedSource(
        handle=handle,
        source_type=SourceType.TEXT,
        display_name=label,
        bytes_total=len(text.encode("utf-8")),
        char_total=len(text),
        line_count=text.count("\n") + 1 if text else 0,
        extension="",
        warnings=warnings,
    )


def _ingest(
    raw: bytes,
    resolved: ResolvedFile,
    session: SessionContext,
    source_type: SourceType,
) -> LoadedSource:
    """Decode, optionally parse, and store."""
    text, substitutions = _decode(raw)
    warnings: list[str] = []

    if substitutions:
        warnings.append(
            f"{substitutions:,} byte sequence(s) could not be decoded as UTF-8 "
            "and were replaced. Detection still ran over the rest."
        )

    scannable, document = parse_or_fallback(text, resolved.extension)

    if document is None and resolved.extension in {".json", ".jsonl", ".xml", ".csv"}:
        warnings.append(
            f"Could not parse as {resolved.extension} — scanned as plain text "
            "instead. Field-name context is unavailable, so detection may be "
            "less precise."
        )

    # Store the scannable projection: for structured input this is the flattened
    # field view, which is what offsets will refer to.
    handle = session.content_store.put(
        scannable,
        source_type=source_type.value,
        source_identifier=str(resolved.real_path),
        metadata={
            "display_name": resolved.display_path,
            "extension": resolved.extension,
            "structured": document is not None,
            "original_char_count": len(text),
        },
    )

    return LoadedSource(
        handle=handle,
        source_type=source_type,
        display_name=resolved.display_path,
        bytes_total=resolved.size_bytes,
        char_total=len(scannable),
        line_count=text.count("\n") + 1 if text else 0,
        extension=resolved.extension,
        structured=document is not None,
        parsed_field_count=len(document.fields) if document else 0,
        decode_substitutions=substitutions,
        warnings=warnings,
    )
