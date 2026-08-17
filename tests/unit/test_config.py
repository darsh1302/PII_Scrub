"""Configuration invariants — action priority ordering and version pinning."""

from __future__ import annotations

import pytest

from utils.config import (
    ACTION_PRIORITY,
    MIN_CHUNK_OVERLAP_CHARS,
    PINNED_VERSIONS,
    detect_engine_versions,
    verify_engine_versions,
)


def test_action_priority_is_a_total_order():
    """max() over this map is what makes the policy ratchet monotonic (G4)."""
    values = list(ACTION_PRIORITY.values())
    assert len(set(values)) == len(values), "priorities must be distinct"


def test_action_priority_ordering_is_correct():
    p = ACTION_PRIORITY
    assert (
        p["BLOCK"]
        > p["REDACT"]
        > p["TOKENIZE"]
        > p["HASH"]
        > p["MASK"]
        > p["REPLACE"]
        > p["ALLOW"]
    )


def test_action_priority_covers_every_action():
    expected = {
        "ALLOW",
        "REPLACE",
        "MASK",
        "HASH",
        "TOKENIZE",
        "REDACT",
        "BLOCK",
    }
    assert set(ACTION_PRIORITY) == expected


def test_hash_ranks_below_tokenize():
    """HASH is pseudonymization; TOKENIZE has no algebraic link to the input."""
    assert ACTION_PRIORITY["HASH"] < ACTION_PRIORITY["TOKENIZE"]


def test_chunk_overlap_floor_exceeds_a_pem_key():
    """COR-02 — a 200-char overlap split PEM keys undetected.

    An RSA-2048 PEM block is ~1700 chars; the floor must comfortably exceed it.
    """
    assert MIN_CHUNK_OVERLAP_CHARS >= 4096


def test_installed_engine_versions_match_pins():
    assert verify_engine_versions() == []


def test_detect_engine_versions_reports_all_pinned_packages():
    detected = detect_engine_versions()
    assert set(detected) == set(PINNED_VERSIONS)
    assert "MISSING" not in detected.values()


@pytest.mark.parametrize("package", sorted(PINNED_VERSIONS))
def test_each_pinned_package_is_installed(package: str):
    assert detect_engine_versions()[package] != "MISSING"
