"""Property 12 — offset coordinate consistency.

Guardrails G17, G18. Requirements 27.3, 28.2, 28.5.

The property: **detection results must not depend on how the input was chunked.**

This matters because chunking is an implementation detail the user never sees. If
a file yields different findings at one chunk size than another, then some chunk
size is losing PII — and nothing in the output would reveal which.

Generative rather than example-based, because the failure mode is positional: a
bug appears only when an entity happens to land near a boundary. Hand-picked
cases systematically miss exactly that.
"""

from __future__ import annotations

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from pii_agent.core.chunker import chunk_text, reconstruct
from pii_agent.core.detector import detect_chunk
from pii_agent.core.reconciler import reconcile
from pii_agent.models.entities import Entity
from pii_agent.utils.normalization import normalize, strip_whitespace_runs

# Detection is slow relative to typical property tests, so example counts are
# modest and the slow-test health check is disabled deliberately.
DETECTION_SETTINGS = settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much],
)

STRUCTURAL_SETTINGS = settings(
    max_examples=200,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)

# Text built from fragments that produce real detections, so the property is
# exercised against actual entities rather than noise.
PII_FRAGMENTS = [
    "ssn 482-71-9053",
    "email alice.morgan@example.com",
    "card 4532015112830366",
    "call +1 (415) 555-0142",
    "api_key=sk-live-9fK2mQ7xR4tZ8vB1nH6jL0pW",
    "AKIAIOSFODNN7EXAMPLE",
    "password=hunter2",
    "from 203.0.113.42",
    "contact Jane Fairweather",
    "2026-08-16T09:15:44Z INFO request handled",
    "postgresql://svc:pw@db.internal:5432/records",
]


@st.composite
def log_like_text(draw, min_lines: int = 1, max_lines: int = 60):
    """Text resembling a log file, seeded with detectable entities."""
    lines = draw(
        st.lists(
            st.sampled_from(PII_FRAGMENTS)
            | st.text(
                alphabet=st.characters(
                    min_codepoint=32, max_codepoint=126, blacklist_characters="\r"
                ),
                min_size=0,
                max_size=80,
            ),
            min_size=min_lines,
            max_size=max_lines,
        )
    )
    return "\n".join(lines)


def _signature(entities: list[Entity]) -> set[tuple[str, int, int]]:
    """Position-and-type signature, independent of ordering."""
    return {(e.type, e.start, e.end) for e in entities}


def _detect_over_chunks(text: str, chunk_size: int, span: int) -> list[Entity]:
    """Full per-chunk detection with offset globalisation, as the pipeline does."""
    collected: list[Entity] = []
    for chunk in chunk_text(text, max_pattern_span=span, chunk_size=chunk_size):
        outcome = detect_chunk(chunk.text, threshold=0.3, use_spacy=False)
        # Chunk-local offsets become document coordinates here. Skipping this
        # step is the bug this property exists to catch.
        for entity in outcome.entities:
            collected.append(entity.shifted(chunk.global_offset_base))
    reconciled, _ = reconcile(collected)
    return reconciled


# ---------------------------------------------------------------------------
# Property 12 — the central invariant
# ---------------------------------------------------------------------------


@given(text=log_like_text(), chunk_size=st.integers(min_value=256, max_value=4096))
@DETECTION_SETTINGS
def test_detection_is_invariant_under_chunk_size(text: str, chunk_size: int):
    """Chunked detection must equal single-pass detection."""
    assume(text.strip())

    span = 512
    single = _detect_over_chunks(text, max(len(text), 1) + span, span)
    chunked = _detect_over_chunks(text, chunk_size, span)

    assert _signature(chunked) == _signature(single), (
        f"chunk_size={chunk_size} changed the result"
    )


@given(text=log_like_text(min_lines=5, max_lines=40))
@DETECTION_SETTINGS
def test_every_reported_span_matches_the_original_text(text: str):
    """A span must name the text it claims to.

    Guards against off-by-one and normalization-shift bugs: if an offset is
    wrong, the applier scrubs the wrong characters and leaves the PII in place.
    """
    assume(text.strip())

    for entity in _detect_over_chunks(text, 1024, 512):
        assert 0 <= entity.start < entity.end <= len(text)
        assert text[entity.start : entity.end] == entity.text


# ---------------------------------------------------------------------------
# Chunking structure
# ---------------------------------------------------------------------------


@given(
    text=st.text(min_size=0, max_size=20_000),
    span=st.integers(min_value=64, max_value=2048),
    chunk_size=st.integers(min_value=256, max_value=8192),
)
@STRUCTURAL_SETTINGS
def test_chunks_always_reconstruct_the_source(text, span, chunk_size):
    """If chunking loses or duplicates content, the coverage ledger lies."""
    chunks = chunk_text(text, max_pattern_span=span, chunk_size=chunk_size)
    assert reconstruct(chunks) == text


@given(
    text=st.text(min_size=1, max_size=20_000),
    span=st.integers(min_value=64, max_value=2048),
    chunk_size=st.integers(min_value=256, max_value=8192),
)
@STRUCTURAL_SETTINGS
def test_novel_spans_tile_without_gaps_or_overlaps(text, span, chunk_size):
    """Every character falls in exactly one novel region."""
    chunks = chunk_text(text, max_pattern_span=span, chunk_size=chunk_size)
    cursor = 0
    for chunk in chunks:
        start, end = chunk.novel_span
        assert start == cursor
        cursor = end
    assert cursor == len(text)


@given(
    text=st.text(min_size=1, max_size=20_000),
    span=st.integers(min_value=64, max_value=1024),
)
@STRUCTURAL_SETTINGS
def test_any_window_of_span_length_lies_wholly_in_some_chunk(text, span):
    """The guarantee that makes COR-02 impossible.

    If a pattern up to ``span`` characters long can always be found entirely
    within one chunk, no boundary can split it out of existence.
    """
    chunks = chunk_text(text, max_pattern_span=span, chunk_size=1024)
    if len(chunks) == 1:
        return

    step = max(1, span // 4)
    for window_start in range(0, max(1, len(text) - span), step):
        window_end = min(window_start + span, len(text))
        assert any(
            c.global_offset_base <= window_start
            and window_end <= c.global_offset_base + c.length
            for c in chunks
        ), f"window [{window_start},{window_end}) is split across every chunk"


# ---------------------------------------------------------------------------
# Normalization offset mapping
# ---------------------------------------------------------------------------


@given(text=st.text(min_size=0, max_size=2000))
@STRUCTURAL_SETTINGS
def test_normalization_never_grows_the_text(text: str):
    """One normalized character must have exactly one original source."""
    result = normalize(text)
    assert len(result.text) <= len(text)
    assert len(result.index_map.positions) == len(result.text)


@given(text=st.text(min_size=1, max_size=2000))
@STRUCTURAL_SETTINGS
def test_index_map_positions_are_strictly_increasing(text: str):
    """Monotonic mapping — required for span translation to be well defined."""
    positions = normalize(text).index_map.positions
    assert all(b > a for a, b in zip(positions, positions[1:]))


@given(text=st.text(min_size=1, max_size=2000))
@STRUCTURAL_SETTINGS
def test_index_map_positions_are_within_the_original(text: str):
    result = normalize(text)
    assert all(0 <= p < len(text) for p in result.index_map.positions)


@given(
    text=st.text(min_size=1, max_size=1000),
    start=st.integers(min_value=0, max_value=999),
    length=st.integers(min_value=1, max_value=50),
)
@STRUCTURAL_SETTINGS
def test_span_translation_stays_in_bounds(text, start, length):
    """Translated spans must always be valid slices of the original."""
    result = normalize(text)
    assume(result.text)

    norm_start = min(start, len(result.text) - 1)
    norm_end = min(norm_start + length, len(result.text))
    assume(norm_end > norm_start)

    orig_start, orig_end = result.index_map.to_original(norm_start, norm_end)
    assert 0 <= orig_start <= orig_end <= len(text)


@given(text=st.text(min_size=1, max_size=500))
@STRUCTURAL_SETTINGS
def test_whitespace_stripping_map_is_consistent(text: str):
    stripped, index_map = strip_whitespace_runs(text)
    assert len(index_map.positions) == len(stripped)
    for i, char in enumerate(stripped):
        assert text[index_map.positions[i]] == char
