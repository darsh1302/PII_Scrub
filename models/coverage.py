"""Coverage ledger — the evidence behind the fail-closed gate.

Guardrail G6, Property 10. Addresses review findings SEC-05 and COR-01.

The reviewed design said a failed recognizer should "log the failure, inform the
user of partial coverage, and continue" — and then still produced sanitized
output. That hands the user a file labelled clean which was never fully
inspected. A scrubber that silently under-detects is more dangerous than no
scrubber, because it manufactures confidence.

This ledger makes coverage a fact the pipeline must check rather than an
assumption. ``is_complete()`` gates artifact production: detection results may
always be *reported* (labelled UNVERIFIED), but a sanitized artifact requires
provable full coverage.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class DetectorStatus:
    """Outcome for one detector over one scan."""

    name: str
    executed: bool = False
    failed: bool = False
    failure_reason: str = ""
    chunks_processed: int = 0
    timed_out: bool = False

    @property
    def healthy(self) -> bool:
        return self.executed and not self.failed and not self.timed_out


@dataclass
class CoverageLedger:
    """Records what was actually inspected, and by what.

    ``required_detectors`` comes from the active profile. A profile declaring
    spaCy as required is *unavailable* when spaCy is missing, rather than
    silently downgraded to pattern-matching only (Requirement 36.6).
    """

    bytes_total: int = 0
    bytes_processed: int = 0
    chunks_total: int = 0
    chunks_processed: int = 0
    required_detectors: frozenset[str] = frozenset()
    detectors: dict[str, DetectorStatus] = field(default_factory=dict)
    truncation_approved_by_user: bool = False
    truncation_limit_bytes: int | None = None
    aborted: bool = False
    abort_reason: str = ""

    # -- recording ------------------------------------------------------
    def start_detector(self, name: str) -> DetectorStatus:
        status = self.detectors.setdefault(name, DetectorStatus(name=name))
        status.executed = True
        return status

    def record_detector_failure(self, name: str, reason: str) -> None:
        """A recognizer raised. Coverage is now incomplete."""
        status = self.start_detector(name)
        status.failed = True
        status.failure_reason = reason

    def record_detector_timeout(self, name: str) -> None:
        """A detector exceeded its budget. Treated as incomplete coverage."""
        status = self.start_detector(name)
        status.timed_out = True
        status.failure_reason = "exceeded time budget"

    def record_detector_unavailable(self, name: str, reason: str) -> None:
        """A detector could not be loaded at all (e.g. missing spaCy model)."""
        status = self.detectors.setdefault(name, DetectorStatus(name=name))
        status.executed = False
        status.failed = True
        status.failure_reason = reason

    def advance_bytes(self, byte_length: int) -> None:
        self.bytes_processed += byte_length
        self.chunks_processed += 1

    def abort(self, reason: str) -> None:
        self.aborted = True
        self.abort_reason = reason

    # -- queries --------------------------------------------------------
    @property
    def failed_detectors(self) -> tuple[str, ...]:
        return tuple(
            sorted(n for n, s in self.detectors.items() if not s.healthy)
        )

    @property
    def healthy_detectors(self) -> tuple[str, ...]:
        return tuple(sorted(n for n, s in self.detectors.items() if s.healthy))

    @property
    def missing_required_detectors(self) -> tuple[str, ...]:
        """Required detectors that did not complete successfully."""
        healthy = set(self.healthy_detectors)
        return tuple(sorted(self.required_detectors - healthy))

    @property
    def bytes_complete(self) -> bool:
        """True only when every byte was inspected.

        Deliberately not satisfied by approved truncation. Approving truncation
        makes the *scan* intentional, but an artifact built from a partial scan
        cannot be verified clean: the applier would scrub the region that was
        examined and leave live values in the region that was not. Discovered in
        implementation — a 45 KB budget over an 86 KB file left 166 unscrubbed
        SSNs in the tail, which the verification gate caught. Refusing at the
        coverage gate is the correct place; relying on verification to catch a
        coverage error is not a design.
        """
        return self.bytes_total > 0 and self.bytes_processed >= self.bytes_total

    @property
    def truncation_was_intentional(self) -> bool:
        """True when a partial scan was explicitly requested and approved.

        Distinguishes "the user asked for a partial scan" from "coverage
        degraded unexpectedly". Both block artifact production; only the latter
        indicates something went wrong.
        """
        return self.truncation_approved_by_user and not self.aborted

    @property
    def coverage_fraction(self) -> float:
        if self.bytes_total <= 0:
            return 0.0
        return min(1.0, self.bytes_processed / self.bytes_total)

    @property
    def coverage_percent(self) -> float:
        return round(self.coverage_fraction * 100, 1)

    def is_complete(self) -> bool:
        """True only when a sanitized artifact may be produced.

        Requires: not aborted, every byte inspected, and every
        profile-required detector healthy. Approved truncation does not satisfy
        this — see ``bytes_complete``.
        """
        if self.aborted:
            return False
        if not self.bytes_complete:
            return False
        if self.missing_required_detectors:
            return False
        return True

    def scan_is_reportable(self) -> bool:
        """True when findings may be presented, even if no artifact can be.

        A partial or degraded scan still produces useful findings; they are
        simply labelled UNVERIFIED.
        """
        return not self.aborted and self.chunks_processed > 0

    # -- reporting ------------------------------------------------------
    def describe(self) -> str:
        """Plain-language coverage explanation with remediation guidance.

        Surfaced directly to the user on refusal, so it must explain *why* the
        refusal protects them rather than just reporting a failure.
        """
        if self.is_complete():
            return (
                f"Fully inspected {self.bytes_total:,} bytes using "
                f"{', '.join(self.healthy_detectors)}."
            )

        problems: list[str] = []

        if self.aborted:
            problems.append(f"Processing stopped early: {self.abort_reason}.")

        if not self.bytes_complete:
            if self.truncation_was_intentional:
                problems.append(
                    f"You asked me to scan only part of this source, so I "
                    f"inspected {self.bytes_processed:,} of "
                    f"{self.bytes_total:,} bytes ({self.coverage_percent}%)."
                )
            else:
                problems.append(
                    f"Only {self.coverage_percent}% of the source was "
                    f"inspected ({self.bytes_processed:,} of "
                    f"{self.bytes_total:,} bytes)."
                )

        for name in self.missing_required_detectors:
            status = self.detectors.get(name)
            reason = status.failure_reason if status else "did not run"
            problems.append(f"Required detector '{name}' {reason}.")

        if self.truncation_was_intentional and self.bytes_complete is False:
            remedy = (
                " Findings for the part I did inspect are shown and are marked "
                "UNVERIFIED. I cannot produce a cleaned copy from a partial "
                "scan: I would scrub the region I examined and leave live "
                "values in the region I did not, which would look clean "
                "without being clean. Scan the whole source to get a cleaned "
                "copy."
            )
        else:
            remedy = (
                " Detection results are still shown but are marked UNVERIFIED. "
                "A cleaned copy was withheld deliberately: it would look "
                "verified without having been fully checked."
            )
        return " ".join(problems) + remedy

    def to_metadata(self) -> dict[str, object]:
        """Coverage summary for results, audit records, and the UI.

        Contains no content — safe for the reasoning context and audit trail.
        """
        return {
            "bytes_total": self.bytes_total,
            "bytes_processed": self.bytes_processed,
            "coverage_percent": self.coverage_percent,
            "chunks_total": self.chunks_total,
            "chunks_processed": self.chunks_processed,
            "complete": self.is_complete(),
            "detectors_healthy": list(self.healthy_detectors),
            "detectors_failed": list(self.failed_detectors),
            "missing_required": list(self.missing_required_detectors),
            "truncation_approved": self.truncation_approved_by_user,
            "aborted": self.aborted,
        }
