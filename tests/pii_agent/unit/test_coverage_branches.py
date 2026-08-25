"""Branch coverage for the coverage ledger and allowlist store.

The ledger drives the fail-closed gate (G6), so an untested branch here means a
condition that should block artifact production might not.
"""

from __future__ import annotations

import pytest

from pii_agent.models.coverage import CoverageLedger, DetectorStatus
from pii_agent.session.allowlist import AllowlistStore


# ---------------------------------------------------------------------------
# DetectorStatus
# ---------------------------------------------------------------------------


def test_status_is_unhealthy_until_it_has_executed():
    assert DetectorStatus(name="presidio").healthy is False


def test_status_is_healthy_once_executed_without_failure():
    status = DetectorStatus(name="presidio", executed=True)
    assert status.healthy is True


@pytest.mark.parametrize("field", ["failed", "timed_out"])
def test_status_is_unhealthy_when_failed_or_timed_out(field):
    status = DetectorStatus(name="presidio", executed=True, **{field: True})
    assert status.healthy is False


# ---------------------------------------------------------------------------
# Ledger transitions
# ---------------------------------------------------------------------------


def test_start_detector_is_idempotent():
    led = CoverageLedger()
    first = led.start_detector("presidio")
    second = led.start_detector("presidio")
    assert first is second
    assert len(led.detectors) == 1


def test_failure_after_success_marks_the_detector_unhealthy():
    """A recognizer that raises mid-scan must not stay marked healthy."""
    led = CoverageLedger(bytes_total=10, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    assert led.healthy_detectors == ("presidio",)

    led.record_detector_failure("presidio", "raised RuntimeError")
    assert led.healthy_detectors == ()
    assert led.failed_detectors == ("presidio",)


def test_timeout_records_a_reason():
    led = CoverageLedger()
    led.record_detector_timeout("spacy")
    assert led.detectors["spacy"].failure_reason == "exceeded time budget"


def test_unavailable_detector_is_not_marked_executed():
    """Distinguishes "never ran" from "ran and failed"."""
    led = CoverageLedger()
    led.record_detector_unavailable("spacy", "model not installed")
    status = led.detectors["spacy"]
    assert status.executed is False
    assert status.failed is True


def test_unavailable_after_start_overrides_executed():
    led = CoverageLedger()
    led.start_detector("spacy")
    led.record_detector_unavailable("spacy", "model unloaded")
    assert led.detectors["spacy"].executed is False


# ---------------------------------------------------------------------------
# Coverage fractions
# ---------------------------------------------------------------------------


def test_coverage_fraction_is_zero_when_nothing_measured():
    assert CoverageLedger(bytes_total=0).coverage_fraction == 0.0
    assert CoverageLedger(bytes_total=0).coverage_percent == 0.0


def test_coverage_fraction_is_capped_at_one():
    """Overlap accounting must not report more than 100%."""
    led = CoverageLedger(bytes_total=100)
    led.advance_bytes(150)
    assert led.coverage_fraction == 1.0
    assert led.coverage_percent == 100.0


def test_advance_bytes_increments_the_chunk_counter():
    led = CoverageLedger(bytes_total=300)
    led.advance_bytes(100)
    led.advance_bytes(100)
    assert led.chunks_processed == 2
    assert led.bytes_processed == 200


# ---------------------------------------------------------------------------
# Completion and reportability
# ---------------------------------------------------------------------------


def test_zero_total_is_never_complete():
    """Nothing measured is not the same as everything inspected."""
    led = CoverageLedger(bytes_total=0, required_detectors=frozenset())
    assert led.bytes_complete is False
    assert led.is_complete() is False


def test_scan_is_not_reportable_before_any_chunk():
    assert CoverageLedger(bytes_total=100).scan_is_reportable() is False


def test_scan_is_reportable_after_a_chunk_even_if_incomplete():
    """Partial findings are still worth showing, labelled UNVERIFIED."""
    led = CoverageLedger(bytes_total=1000)
    led.advance_bytes(100)
    assert led.scan_is_reportable() is True
    assert led.is_complete() is False


def test_aborted_scan_is_not_reportable():
    led = CoverageLedger(bytes_total=1000)
    led.advance_bytes(100)
    led.abort("cancelled")
    assert led.scan_is_reportable() is False


def test_truncation_is_not_intentional_when_also_aborted():
    """An abort overrides the approval — something went wrong regardless."""
    led = CoverageLedger(bytes_total=1000, truncation_approved_by_user=True)
    led.advance_bytes(100)
    assert led.truncation_was_intentional is True
    led.abort("worker cancelled")
    assert led.truncation_was_intentional is False


def test_missing_required_reports_only_required_detectors():
    """A failed optional detector must not block the artifact."""
    led = CoverageLedger(
        bytes_total=10, required_detectors=frozenset({"presidio"})
    )
    led.start_detector("presidio")
    led.record_detector_failure("experimental", "boom")
    led.advance_bytes(10)

    assert led.missing_required_detectors == ()
    assert led.is_complete() is True
    assert "experimental" in led.failed_detectors


# ---------------------------------------------------------------------------
# describe()
# ---------------------------------------------------------------------------


def test_describe_on_complete_coverage_lists_the_detectors():
    led = CoverageLedger(
        bytes_total=1000, required_detectors=frozenset({"presidio"})
    )
    led.start_detector("presidio")
    led.advance_bytes(1000)

    detail = led.describe()
    assert "Fully inspected 1,000 bytes" in detail
    assert "presidio" in detail


def test_describe_mentions_an_abort_reason():
    led = CoverageLedger(bytes_total=1000)
    led.start_detector("presidio")
    led.advance_bytes(1000)
    led.abort("time budget exceeded")

    assert "time budget exceeded" in led.describe()


def test_describe_names_a_detector_that_never_ran():
    led = CoverageLedger(
        bytes_total=100, required_detectors=frozenset({"presidio", "spacy"})
    )
    led.start_detector("presidio")
    led.advance_bytes(100)
    # Required but never registered at all.
    assert "did not run" in led.describe()


def test_describe_includes_the_failure_reason_when_known():
    led = CoverageLedger(
        bytes_total=100, required_detectors=frozenset({"presidio", "spacy"})
    )
    led.start_detector("presidio")
    led.record_detector_unavailable("spacy", "model not installed")
    led.advance_bytes(100)

    assert "model not installed" in led.describe()


def test_metadata_shape_is_stable():
    """Consumed by results, audit records, and the UI."""
    led = CoverageLedger(bytes_total=10, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    led.advance_bytes(10)

    metadata = led.to_metadata()
    assert set(metadata) == {
        "bytes_total",
        "bytes_processed",
        "coverage_percent",
        "chunks_total",
        "chunks_processed",
        "complete",
        "detectors_healthy",
        "detectors_failed",
        "missing_required",
        "truncation_approved",
        "aborted",
    }


# ---------------------------------------------------------------------------
# AllowlistStore
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["", "a", "ab", "abc", "abcd"])
def test_short_values_are_fully_masked_in_previews(value):
    """A four-character value has no safe middle to reveal."""
    store = AllowlistStore("s")
    entry = store.add(value, "IP_ADDRESS", "DEFAULT_PII")
    assert entry.label == "*" * len(value)
    assert value not in entry.label or value == ""


def test_longer_values_keep_only_the_outer_characters():
    store = AllowlistStore("s")
    entry = store.add("203.0.113.42", "IP_ADDRESS", "DEFAULT_PII")
    assert entry.label.startswith("20")
    assert entry.label.endswith("42")
    assert "203.0.113.42" != entry.label


def test_entries_for_returns_only_the_matching_profile():
    store = AllowlistStore("s")
    store.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")
    store.add("10.0.0.2", "IP_ADDRESS", "HEALTHCARE")

    assert len(store.entries_for("DEFAULT_PII")) == 1
    assert len(store.entries_for("HEALTHCARE")) == 1
    assert store.entries_for("FINANCIAL") == ()


def test_clear_empties_the_store():
    store = AllowlistStore("s")
    store.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")
    assert len(store) == 1
    store.clear()
    assert len(store) == 0
    assert store.contains("10.0.0.1", "DEFAULT_PII") is False


def test_readding_the_same_value_does_not_duplicate():
    store = AllowlistStore("s")
    store.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")
    store.add("10.0.0.1", "IP_ADDRESS", "DEFAULT_PII")
    assert len(store) == 1


def test_value_is_never_stored_in_cleartext():
    """The allowlist records what the user said was safe, not the value itself."""
    store = AllowlistStore("s")
    entry = store.add("203.0.113.42", "IP_ADDRESS", "DEFAULT_PII")
    assert "203.0.113.42" not in entry.value_hash
    assert "203.0.113.42" not in repr(entry)
