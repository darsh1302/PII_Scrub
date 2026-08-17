"""Guardrail G17 — chunk boundaries must not lose long secrets.

Addresses review finding COR-02. The reviewed design used a 200-character
overlap against artifacts that are routinely far larger: an RSA-2048 PEM block
is ~1700 characters, RSA-4096 several times that. Split across a boundary with
200 characters of overlap, a private key is present in neither chunk — detected
nowhere, silently, on exactly the files most worth scanning.

These tests use a stub detector so they run before real detection exists
(Phase 3) and are re-run against the real detectors afterwards.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from core.chunker import chunk_text, reconstruct, resolve_overlap
from core.profile_resolver import resolve_profile
from tests.fixtures.make_fixtures import PEM_KEY

FIXTURES = Path(__file__).parent.parent / "fixtures"

# Stand-in for the real PEM recognizer arriving in Phase 3.
PEM_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL,
)


def _detect_in_chunks(chunks) -> list[tuple[int, int]]:
    """Detect the pattern per chunk, returning document-coordinate spans.

    Mirrors the real pipeline: detect chunk-locally, then translate offsets
    (Property 12). Duplicates from overlap regions are collapsed.
    """
    spans: set[tuple[int, int]] = set()
    for chunk in chunks:
        for match in PEM_PATTERN.finditer(chunk.text):
            spans.add(
                (
                    match.start() + chunk.global_offset_base,
                    match.end() + chunk.global_offset_base,
                )
            )
    return sorted(spans)


def test_profile_overlap_accommodates_a_pem_block():
    """The profile must derive an overlap larger than the artifact."""
    profile = resolve_profile("DEFAULT_PII")
    overlap = resolve_overlap(profile.max_pattern_span)
    assert overlap > len(PEM_KEY), (
        f"overlap {overlap} must exceed the {len(PEM_KEY)}-char key block"
    )


def test_pem_key_detected_exactly_once_when_straddling_a_boundary():
    """The COR-02 regression case."""
    profile = resolve_profile("DEFAULT_PII")
    text = (FIXTURES / "sample_pem_straddle.txt").read_text(encoding="utf-8")

    # Confirm the fixture actually straddles a boundary, or it proves nothing.
    chunks = chunk_text(
        text, max_pattern_span=profile.max_pattern_span, chunk_size=16384
    )
    assert len(chunks) > 1, "fixture must produce multiple chunks"

    key_start = text.index("-----BEGIN")
    key_end = text.index("-----END") + len("-----END RSA PRIVATE KEY-----")
    # Split points are where novel coverage begins, not where the chunk's text
    # begins — the chunk reaches back by the overlap.
    split_points = [c.novel_span[0] for c in chunks[1:]]
    assert any(key_start < b < key_end for b in split_points), (
        f"fixture must place a split point inside the key block "
        f"[{key_start},{key_end}); splits at {split_points}"
    )

    spans = _detect_in_chunks(chunks)
    assert len(spans) == 1, f"expected exactly one detection, got {len(spans)}"
    assert spans[0] == (key_start, key_end)


def _text_with_key_at(offset: int, trailing_lines: int = 200) -> str:
    """Build text placing the PEM key so it starts near ``offset``.

    Line-aligned so the chunker's boundary preference behaves as it would on a
    real log file.
    """
    filler = "2026-08-16T09:00:00Z INFO  padding line for boundary placement\n"
    repeats = offset // len(filler)
    prefix = filler * repeats
    return prefix + PEM_KEY + "\n" + filler * trailing_lines


def test_small_overlap_demonstrates_the_original_defect():
    """Shows the failure the corrected overlap prevents.

    Reproduces the reviewed design's behaviour directly: a 200-character overlap
    against a 1686-character key. The key straddles the boundary and is present
    in neither chunk, so it is detected nowhere — silently.

    This test asserts the *defect* on purpose. It is the regression witness: if
    it ever starts finding the key, the setup no longer reproduces the original
    condition and the companion test above proves nothing.
    """
    import core.chunker as chunker_module

    chunk_size = 16384
    # Start the key ~400 chars before the split so the boundary lands inside it
    # but outside a 200-char overlap reaching back from it.
    text = _text_with_key_at(chunk_size - 400)

    original_floor = chunker_module.MIN_CHUNK_OVERLAP_CHARS
    try:
        chunker_module.MIN_CHUNK_OVERLAP_CHARS = 200
        chunks = chunk_text(text, max_pattern_span=160, chunk_size=chunk_size)
        spans = _detect_in_chunks(chunks)
        split_points = [c.novel_span[0] for c in chunks[1:]]
    finally:
        chunker_module.MIN_CHUNK_OVERLAP_CHARS = original_floor

    key_start = text.index("-----BEGIN")
    key_end = text.index("-----END") + len("-----END RSA PRIVATE KEY-----")

    assert any(key_start < b < key_end for b in split_points), (
        f"setup must straddle: key [{key_start},{key_end}), "
        f"splits {split_points}"
    )
    assert spans == [], (
        "expected the historical defect: a 200-char overlap loses a "
        f"{len(PEM_KEY)}-char key that straddles a boundary"
    )


def test_corrected_overlap_finds_the_same_key_the_small_overlap_lost():
    """The direct before/after comparison for COR-02.

    Same text, same chunk size — only the overlap differs.
    """
    profile = resolve_profile("DEFAULT_PII")
    chunk_size = 16384
    text = _text_with_key_at(chunk_size - 400)

    chunks = chunk_text(
        text, max_pattern_span=profile.max_pattern_span, chunk_size=chunk_size
    )
    spans = _detect_in_chunks(chunks)

    key_start = text.index("-----BEGIN")
    key_end = text.index("-----END") + len("-----END RSA PRIVATE KEY-----")
    assert spans == [(key_start, key_end)]


@pytest.mark.parametrize("chunk_size", [4096, 8192, 16384, 32768])
def test_key_found_regardless_of_chunk_size(chunk_size):
    """Detection must not depend on where boundaries happen to land."""
    profile = resolve_profile("DEFAULT_PII")
    text = (FIXTURES / "sample_pem_straddle.txt").read_text(encoding="utf-8")
    chunks = chunk_text(
        text, max_pattern_span=profile.max_pattern_span, chunk_size=chunk_size
    )
    assert len(_detect_in_chunks(chunks)) == 1


@pytest.mark.parametrize("offset", range(0, 4000, 373))
def test_key_found_at_every_position_relative_to_a_boundary(offset):
    """Sweep the key across boundary positions — no position may lose it."""
    profile = resolve_profile("DEFAULT_PII")
    filler = "2026-08-16T09:00:00Z INFO padding line for offset sweep\n"
    prefix = (filler * ((16384 + offset) // len(filler) + 1))[: 16384 + offset]
    text = prefix + PEM_KEY + "\n" + filler * 20

    chunks = chunk_text(
        text, max_pattern_span=profile.max_pattern_span, chunk_size=16384
    )
    spans = _detect_in_chunks(chunks)
    assert len(spans) == 1, f"lost the key at offset {offset}"


# ---------------------------------------------------------------------------
# Chunking correctness — coverage figures are meaningless without this
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "fixture",
    ["sample_log.txt", "sample_clean.txt", "sample_pem_straddle.txt"],
)
def test_chunks_reconstruct_the_source_exactly(fixture):
    """If chunking loses or duplicates content, the coverage ledger lies."""
    text = (FIXTURES / fixture).read_text(encoding="utf-8")
    chunks = chunk_text(text, max_pattern_span=8192, chunk_size=8192)
    assert reconstruct(chunks) == text


def test_empty_input_produces_one_empty_chunk():
    chunks = chunk_text("", max_pattern_span=8192)
    assert len(chunks) == 1
    assert chunks[0].text == ""


def test_short_input_produces_a_single_chunk():
    chunks = chunk_text("short line\n", max_pattern_span=8192)
    assert len(chunks) == 1
    assert chunks[0].overlap_prefix_chars == 0


def test_chunks_prefer_line_boundaries():
    """Splitting mid-record produces two unparseable halves.

    The split point is where novel coverage starts, not where the chunk's text
    starts — the chunk reaches back by the overlap.
    """
    text = "".join(f"line {i:04d} some content here\n" for i in range(2000))
    chunks = chunk_text(text, max_pattern_span=1024, chunk_size=8192)
    assert len(chunks) > 1, "test needs multiple chunks to be meaningful"

    for chunk in chunks[1:]:
        split_at = chunk.novel_span[0]
        assert text[split_at - 1] == "\n", (
            f"split at {split_at} lands mid-line: "
            f"{text[split_at - 20:split_at + 10]!r}"
        )


def test_novel_spans_tile_the_document_without_gaps():
    """Every byte must fall in exactly one novel region."""
    text = "".join(f"line {i:04d}\n" for i in range(3000))
    chunks = chunk_text(text, max_pattern_span=1024, chunk_size=8192)

    cursor = 0
    for chunk in chunks:
        start, end = chunk.novel_span
        assert start == cursor, f"gap or overlap at {cursor}"
        cursor = end
    assert cursor == len(text)


def test_total_chunk_count_is_consistent_on_every_chunk():
    text = "".join(f"line {i:04d}\n" for i in range(3000))
    chunks = chunk_text(text, max_pattern_span=1024, chunk_size=8192)
    assert all(c.total == len(chunks) for c in chunks)
