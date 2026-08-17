"""The deterministic scan-and-scrub pipeline.

Requirement 46. Guardrails G6, G7, G19, G20, G21.
Addresses review findings SEC-02, SEC-05, COR-01.

This module is the trusted core. It contains no LLM call and imports nothing that
does — a property asserted by test, not merely intended. The agent added in
Phase 5 chooses *what* to scan and *which profile*; it never carries content,
entity offsets, or intermediate results between stages.

Ten stages, three fail-closed gates:

    source -> chunk -> detect -> globalize -> reconcile -> coverage
    -> [GATE 1: coverage complete?]
    -> policy -> [GATE 2: any BLOCK?]
    -> apply -> verify -> [GATE 3: residual PII?]
    -> audit

Chunk iteration is owned here rather than delegated. The reviewed design let the
agent decide when it had seen enough of a large file, which for a model
optimising for a helpful answer means scanning chunk 1 of 40 and declaring the
file clean (COR-01).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from core.applier import apply_decisions
from core.chunker import chunk_text
from core.detector import detect_chunk
from core.injection_scan import scan_for_injection
from core.policy import DestinationRequired, PolicyContext, get_policy_engine
from core.profile_resolver import EffectiveProfile, resolve_profile
from core.reconciler import drop_allowlisted, filter_by_profile, reconcile
from core.verifier import verify_sanitized
from models.coverage import CoverageLedger
from models.decision import DecisionSet
from models.entities import Entity
from models.enums import Destination, RefusalReason, ScrubAction, SourceType
from models.results import EngineVersions, ProcessingResult
from session.context import SessionContext
from utils.config import DEFAULT_CONFIDENCE_THRESHOLD


@dataclass
class ScanOptions:
    """Tunables for one pipeline run."""

    profile_names: tuple[str, ...] = ("DEFAULT_PII",)
    destination: Destination | None = None
    requested_action: ScrubAction | None = None
    confidence_threshold: float | None = None
    use_spacy: bool = True
    chunk_size: int | None = None
    max_bytes: int | None = None  # explicit truncation, requires approval
    truncation_approved: bool = False
    dry_run: bool = False


def scan(
    handle: str,
    session: SessionContext,
    options: ScanOptions | None = None,
) -> ProcessingResult:
    """Detect entities in stored content. Does not modify anything.

    Owns chunk iteration so coverage is a fact rather than an assumption.
    """
    options = options or ScanOptions()
    started = time.perf_counter()

    record = session.content_store.get(handle)
    profile = resolve_profile(*options.profile_names)
    content = record.content

    versions = EngineVersions.detect(profile.name, profile.version)

    ledger = CoverageLedger(
        bytes_total=len(content.encode("utf-8")),
        required_detectors=profile.required_detectors,
        truncation_approved_by_user=options.truncation_approved,
        truncation_limit_bytes=options.max_bytes,
    )

    result = ProcessingResult(
        source_type=SourceType(record.source_type),
        source_identifier_hash=record.source_identifier_hash(),
        content_handle=handle,
        coverage=ledger,
        engine_versions=versions,
        destination=options.destination,
    )

    # --- Injection and evasion reporting (G3) ------------------------------
    findings = scan_for_injection(content)
    if findings:
        result.security_findings = [
            f"{f.description} (x{f.occurrences})" for f in findings.findings
        ]

    if not content.strip():
        ledger.bytes_total = 0
        result.processing_time_ms = (time.perf_counter() - started) * 1000
        return result

    # --- Chunk and detect --------------------------------------------------
    threshold = (
        options.confidence_threshold
        if options.confidence_threshold is not None
        else DEFAULT_CONFIDENCE_THRESHOLD
    )
    # Presidio filters at its own threshold; profile thresholds are applied
    # per-entity afterwards, so detect permissively and filter precisely.
    detect_threshold = min(threshold, 0.3)

    chunks = chunk_text(
        content,
        max_pattern_span=profile.max_pattern_span,
        chunk_size=options.chunk_size,
    )
    ledger.chunks_total = len(chunks)

    collected: list[Entity] = []
    evasion_signals: set[str] = set()
    budget_exhausted = False

    for chunk in chunks:
        if options.max_bytes is not None and ledger.bytes_processed >= options.max_bytes:
            budget_exhausted = True
            break

        outcome = detect_chunk(
            chunk.text,
            threshold=detect_threshold,
            use_spacy=options.use_spacy,
            ledger=ledger,
        )
        evasion_signals.update(outcome.evasion_signals)

        # Chunk-local offsets become document coordinates here. Omitting this is
        # the bug Property 12 exists to catch.
        for entity in outcome.entities:
            collected.append(entity.shifted(chunk.global_offset_base))

        ledger.advance_bytes(len(chunk.text[chunk.overlap_prefix_chars :].encode()))

    if budget_exhausted and not options.truncation_approved:
        ledger.abort(
            f"stopped at {ledger.bytes_processed:,} bytes "
            f"(limit {options.max_bytes:,})"
        )

    result.warnings.extend(sorted(evasion_signals))

    # --- Filter, then reconcile -------------------------------------------
    # Profile filtering runs FIRST so a type the profile ignores can never
    # displace one it cares about. Reconciling first allowed a spaCy
    # ORGANIZATION guess to win an overlap against a checksum-validated IBAN and
    # then be dropped by the filter, leaving the IBAN unscrubbed — a silent loss
    # with no trace in the output.
    relevant, _ = filter_by_profile(collected, profile)
    reconciled, _ = reconcile(relevant)
    kept, suppressed = drop_allowlisted(reconciled, session.allowlist, profile.name)

    result.entities = kept
    result.allowlist_suppressed = suppressed
    result.unverified = not ledger.is_complete()

    # --- Resolve policy (reporting only; no artifact produced here) --------
    engine = get_policy_engine()
    try:
        result.decisions = engine.resolve(
            kept,
            PolicyContext(
                profile=profile,
                destination=options.destination,
                document=content,
                requested_action=options.requested_action,
            ),
            strict_destination=not options.dry_run,
        )
    except DestinationRequired as exc:
        result.refusal = RefusalReason.NEEDS_DESTINATION
        result.refusal_detail = (
            "Some detected types are handled differently depending on where the "
            f"cleaned data is going: {', '.join(exc.entity_types)}. "
            "Tell me the destination and I'll apply the right policy."
        )

    result.processing_time_ms = (time.perf_counter() - started) * 1000
    return result


def scrub(
    handle: str,
    session: SessionContext,
    options: ScanOptions | None = None,
    *,
    scan_result: ProcessingResult | None = None,
) -> ProcessingResult:
    """Scan (unless a result is supplied) then produce a sanitized artifact.

    Fails closed at three gates. Detection results remain reportable in every
    refusal case; only the artifact is withheld.
    """
    options = options or ScanOptions()
    started = time.perf_counter()

    result = scan_result or scan(handle, session, options)
    if result.is_refusal:
        return result

    record = session.content_store.get(handle)
    profile = resolve_profile(*options.profile_names)

    # --- GATE 1: coverage completeness (G6, SEC-05, COR-01) ---------------
    if not result.coverage.is_complete():
        result.refusal = RefusalReason.DEGRADED_COVERAGE
        result.refusal_detail = result.coverage.describe()
        result.unverified = True
        _write_audit(result, session)
        return result

    if options.dry_run:
        # Full detection and policy resolution, no modification (R68).
        result.processing_time_ms += (time.perf_counter() - started) * 1000
        return result

    # Capture the verification scope from the decisions as resolved, before any
    # application. Reading it afterwards would describe what the applier
    # actually did rather than what policy required — so an applier that dropped
    # a decision would also narrow the check that exists to catch it.
    permitted: dict[str, int] = {}
    actioned: set[str] = set()
    for decision in result.decisions:
        if decision.applied_action is ScrubAction.ALLOW:
            key = decision.entity.type
            permitted[key] = permitted.get(key, 0) + 1
        else:
            actioned.add(decision.entity.type)

    # --- GATE 2: BLOCK suppresses the artifact (G19, COR-05) --------------
    applied = apply_decisions(record.content, result.decisions, session.token_vault)
    if applied.is_refusal:
        result.refusal = applied.refusal
        result.refusal_detail = applied.refusal_detail
        _write_audit(result, session)
        return result

    result.warnings.extend(applied.warnings)

    # --- GATE 3: verification re-scan (G7, SEC-02) ------------------------
    # ``permitted`` covers entities policy resolved to ALLOW, which legitimately
    # remain — an exempt log timestamp, or an IP kept for SIEM correlation.
    # ``actioned`` restricts the check to types we chose to remove, so new
    # detections in the modified text are not mistaken for survivors.
    verification = verify_sanitized(
        applied.text,
        profile,
        use_spacy=options.use_spacy,
        permitted_counts=permitted,
        actioned_types=actioned,
    )
    if not verification.clean:
        result.refusal = RefusalReason.RESIDUAL_PII_DETECTED
        result.refusal_detail = verification.detail
        result.verified_clean = False
        _write_audit(result, session)
        return result

    result.sanitized_handle = session.content_store.put_sanitized(
        applied.text, record
    )
    result.verified_clean = True
    result.processing_time_ms += (time.perf_counter() - started) * 1000

    _write_audit(result, session)
    return result


def scan_and_scrub(
    handle: str,
    session: SessionContext,
    options: ScanOptions | None = None,
) -> ProcessingResult:
    """Convenience entry point: the whole pipeline in one call.

    This is what the agent's single coarse tool invokes. One call, so the
    pipeline cannot be partially executed.
    """
    return scrub(handle, session, options)


def _write_audit(result: ProcessingResult, session: SessionContext) -> None:
    """Persist exactly one audit record before returning (G20, R41.3)."""
    try:
        session.audit_sink.append(result.to_audit_record())
    except Exception as exc:  # pragma: no cover - sink failure
        result.warnings.append(
            f"audit record could not be written ({exc.__class__.__name__})"
        )
