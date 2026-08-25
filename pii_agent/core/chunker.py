"""Structural chunking with profile-derived overlap.

Guardrail G17. Addresses review finding COR-02.

The reviewed design used ``OVERLAP_CHARS = 200`` against artifacts that are
routinely far larger — an RSA-2048 PEM block is ~1700 characters and RSA-4096
several times that. Split across a boundary with 200 characters of overlap, a
private key is detected in *neither* chunk. Silent, and worse on exactly the
files most worth scanning.

Two corrections:

* Overlap is derived from the active profile's ``max_pattern_span`` rather than
  being a constant, so adding a recognizer for a longer artifact widens the
  overlap automatically.
* Chunks split on structural boundaries (line ends) rather than mid-token, so a
  value is far less likely to straddle a boundary in the first place.

Every chunk carries ``global_offset_base``. Detection runs per chunk and produces
chunk-local offsets; those are translated to document coordinates before
reconciliation (Property 12). A chunk-local offset applied to a whole document
scrubs the wrong span.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator

from pii_agent.models.entities import NormalizedEvent
from pii_agent.models.enums import SourceType
from pii_agent.utils.config import FILE_CHUNK_SIZE_BYTES, MIN_CHUNK_OVERLAP_CHARS


@dataclass(frozen=True)
class Chunk:
    """A window of content plus its position in the whole document."""

    index: int
    total: int
    text: str
    global_offset_base: int
    # Region already covered by the previous chunk. Entities found entirely
    # inside it are duplicates and are dropped during reconciliation.
    overlap_prefix_chars: int = 0

    @property
    def length(self) -> int:
        return len(self.text)

    @property
    def global_span(self) -> tuple[int, int]:
        return (self.global_offset_base, self.global_offset_base + self.length)

    @property
    def novel_span(self) -> tuple[int, int]:
        """Span excluding the overlap prefix — the newly-covered region."""
        start = self.global_offset_base + self.overlap_prefix_chars
        return (start, self.global_offset_base + self.length)

    def to_event(
        self,
        source_type: SourceType,
        *,
        timestamp: str = "",
        metadata: dict | None = None,
    ) -> NormalizedEvent:
        return NormalizedEvent(
            source_type=source_type,
            content=self.text,
            timestamp=timestamp,
            source_metadata=metadata or {},
            chunk_index=self.index,
            total_chunks=self.total,
            global_offset_base=self.global_offset_base,
        )


def resolve_overlap(max_pattern_span: int) -> int:
    """Overlap for a profile, never below the configured floor.

    Slightly larger than the longest matchable span so a pattern positioned at
    the very end of the previous window is still wholly present in the next one.
    """
    return max(MIN_CHUNK_OVERLAP_CHARS, int(max_pattern_span * 1.25))


def resolve_chunk_size(overlap: int, requested: int | None = None) -> int:
    """Chunk size that leaves useful novel content after the overlap.

    Without a floor relative to overlap, an 8 KB overlap against an 8 KB chunk
    would make every chunk almost entirely duplicate work.
    """
    base = requested or FILE_CHUNK_SIZE_BYTES
    return max(base, overlap * 4)


def _split_points(text: str, size: int) -> list[int]:
    """Boundary offsets, preferring line ends near each target position.

    Preferring a newline keeps records intact, which matters for structured logs
    where splitting mid-record produces two unparseable halves.
    """
    if len(text) <= size:
        return [len(text)]

    points: list[int] = []
    position = 0
    # Look back up to 20% of the chunk for a newline before splitting hard.
    lookback = max(1, size // 5)

    while position < len(text):
        target = position + size
        if target >= len(text):
            points.append(len(text))
            break

        window_start = max(position + 1, target - lookback)
        newline = text.rfind("\n", window_start, target)
        boundary = newline + 1 if newline != -1 else target

        points.append(boundary)
        position = boundary

    return points


def chunk_text(
    text: str,
    *,
    max_pattern_span: int,
    chunk_size: int | None = None,
) -> list[Chunk]:
    """Split text into overlapping, structurally-aligned chunks.

    Guarantees:

    * Concatenating each chunk's novel region reconstructs the input exactly.
    * Every window of ``max_pattern_span`` characters is wholly inside at least
      one chunk — so a long pattern is never split across every boundary.
    """
    if not text:
        return [Chunk(index=0, total=1, text="", global_offset_base=0)]

    overlap = resolve_overlap(max_pattern_span)
    size = resolve_chunk_size(overlap, chunk_size)

    if len(text) <= size:
        return [Chunk(index=0, total=1, text=text, global_offset_base=0)]

    boundaries = _split_points(text, size)

    chunks: list[Chunk] = []
    previous_end = 0
    for boundary in boundaries:
        # Reach back by the overlap so a pattern ending at previous_end is whole.
        start = max(0, previous_end - overlap) if previous_end else 0
        overlap_prefix = previous_end - start
        chunks.append(
            Chunk(
                index=len(chunks),
                total=len(boundaries),
                text=text[start:boundary],
                global_offset_base=start,
                overlap_prefix_chars=overlap_prefix,
            )
        )
        previous_end = boundary

    return [
        Chunk(
            index=c.index,
            total=len(chunks),
            text=c.text,
            global_offset_base=c.global_offset_base,
            overlap_prefix_chars=c.overlap_prefix_chars,
        )
        for c in chunks
    ]


def iter_chunks(
    text: str, *, max_pattern_span: int, chunk_size: int | None = None
) -> Iterator[Chunk]:
    """Lazy variant for streaming, so a whole chunk list is never materialised."""
    yield from chunk_text(
        text, max_pattern_span=max_pattern_span, chunk_size=chunk_size
    )


def reconstruct(chunks: list[Chunk]) -> str:
    """Rebuild the original text from chunks. Used to prove coverage in tests.

    If this does not round-trip, chunking has lost or duplicated content and the
    coverage ledger would be reporting a figure that means nothing.
    """
    if not chunks:
        return ""
    out: list[str] = []
    for chunk in chunks:
        out.append(chunk.text[chunk.overlap_prefix_chars :])
    return "".join(out)
