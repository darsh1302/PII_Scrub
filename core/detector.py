"""Detection over a chunk, with coverage recording and time budgets.

Guardrails G6, G13. Requirements 7, 8, 36.

Three responsibilities, deliberately together because they must not drift apart:

* Run the detectors and translate their output into ``Entity`` objects.
* Record what actually ran in the ``CoverageLedger`` — a detector that raised or
  timed out makes coverage incomplete, which later blocks artifact production.
* Map offsets from normalized back to original coordinates, so every reported
  span refers to text the applier will actually see.

A failing detector never silently degrades detection. It is recorded, and the
fail-closed gate in Phase 4 refuses to produce a sanitized artifact from a scan
whose required detectors did not all succeed.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from models.coverage import CoverageLedger
from models.entities import Entity, severity_for
from models.enums import ConfidenceSource, DetectorName
from session.context import get_shared_engine
from utils.config import SPACY_MODEL_NAME, chunk_timeout_for
from utils.normalization import NormalizationResult, normalize

# Presidio entity names mapped to ours where they differ.
_PRESIDIO_ALIASES = {
    "NRP": "NRP",
    "URL": "URL",
    "DATE_TIME": "DATE_TIME",
    "US_ITIN": "US_ITIN",
    "UK_NHS": "UK_NHS",
    "ORGANIZATION": "ORGANIZATION",
}

# spaCy label -> our entity type. Labels with no PII meaning are dropped.
_SPACY_LABELS = {
    "PERSON": "PERSON",
    "ORG": "ORGANIZATION",
    "GPE": "LOCATION",
    "LOC": "LOCATION",
    "FAC": "LOCATION",
    "DATE": "DATE_TIME",
    "TIME": "DATE_TIME",
    "NORP": "NRP",
}

# spaCy emits no calibrated probability. This constant is a heuristic and is
# tagged as such so reconciliation never weighs it against a Presidio score
# (COR-03).
SPACY_HEURISTIC_CONFIDENCE = 0.6


class DetectorUnavailable(RuntimeError):
    """A detector could not be loaded at all."""


@dataclass
class DetectionOutcome:
    """Entities from one chunk, plus signals worth surfacing."""

    entities: list[Entity] = field(default_factory=list)
    evasion_signals: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0


# --------------------------------------------------------------------------
# Engine construction (shared, read-only)
# --------------------------------------------------------------------------
def _build_analyzer():
    """Presidio analyzer with our custom security recognizers registered."""
    from presidio_analyzer import AnalyzerEngine

    from core.ai_recognizers import build_ai_recognizers
    from core.financial_recognizers import build_financial_recognizers
    from core.recognizers import build_security_recognizers

    engine = AnalyzerEngine()
    for recognizer in build_security_recognizers():
        engine.registry.add_recognizer(recognizer)

    # Registered unconditionally. Detection is cheap and the active profile
    # decides what is reported, so a DEFAULT_PII scan is unchanged by their
    # presence — and a PAYMENT_PCI scan does not need a different engine.
    for recognizer in build_financial_recognizers():
        engine.registry.add_recognizer(recognizer)

    for recognizer in build_ai_recognizers():
        engine.registry.add_recognizer(recognizer)
    return engine


def get_analyzer():
    return get_shared_engine("presidio_analyzer", _build_analyzer)


def _build_spacy():
    import spacy

    return spacy.load(SPACY_MODEL_NAME)


def get_spacy():
    """Load the spaCy model, raising DetectorUnavailable if absent.

    Not cached on failure: a later call after the model is installed should
    succeed without a restart.
    """
    try:
        return get_shared_engine("spacy_model", _build_spacy)
    except OSError as exc:
        raise DetectorUnavailable(
            f"spaCy model '{SPACY_MODEL_NAME}' is not installed. "
            f"Install with: python -m spacy download {SPACY_MODEL_NAME}"
        ) from exc


def spacy_available() -> bool:
    try:
        get_spacy()
        return True
    except DetectorUnavailable:
        return False


# --------------------------------------------------------------------------
# Presidio
# --------------------------------------------------------------------------
def detect_presidio(
    text: str,
    *,
    entity_types: list[str] | None = None,
    threshold: float = 0.0,
    language: str = "en",
    ledger: CoverageLedger | None = None,
    nlp_artifacts=None,
    normalized: NormalizationResult | None = None,
) -> DetectionOutcome:
    """Run Presidio over ``text``, returning entities in original coordinates.

    ``nlp_artifacts`` lets the caller supply a pre-computed NLP pass so Presidio
    does not repeat work this module already did. Optional: when omitted Presidio
    runs its own pass, which is slower and identical.

    ``normalized`` lets the caller supply an existing normalization of the same
    text, so the index map is built once per chunk instead of once per detector.
    """
    normalized = normalized if normalized is not None else normalize(text)

    if not normalized.text.strip():
        return DetectionOutcome(elapsed_ms=0.0)

    # Engine acquisition happens before the timer starts. Building the
    # AnalyzerEngine loads an NLP pipeline and registers ~40 recognizers, which
    # takes seconds on first use. Timing that would make the budget fire on a
    # 40-character input and falsely mark detectors failed — which blocks
    # artifact production. The budget exists to catch pathological *detection*
    # (catastrophic backtracking), not one-time initialisation.
    try:
        analyzer = get_analyzer()
    except Exception as exc:  # pragma: no cover - import/registry failure
        if ledger is not None:
            ledger.record_detector_unavailable(
                DetectorName.PRESIDIO.value, f"{exc.__class__.__name__}"
            )
        raise DetectorUnavailable("Presidio analyzer failed to initialise") from exc

    started = time.perf_counter()

    if ledger is not None:
        # The custom security recognizers are registered into this same engine
        # and run in this same analyze() call, so their health is identical to
        # Presidio's. Recording only "presidio" would leave a profile that
        # requires "custom_security" permanently short of complete coverage,
        # and the fail-closed gate would refuse every scan.
        ledger.start_detector(DetectorName.PRESIDIO.value)
        ledger.start_detector(DetectorName.CUSTOM_SECURITY.value)

    try:
        results = analyzer.analyze(
            text=normalized.text,
            entities=entity_types or None,
            language=language,
            score_threshold=threshold,
            # When supplied, Presidio skips its own spaCy pass. Verified to
            # produce byte-identical results to letting it run its own.
            nlp_artifacts=nlp_artifacts,
        )
    except Exception as exc:
        if ledger is not None:
            for detector in (
                DetectorName.PRESIDIO.value,
                DetectorName.CUSTOM_SECURITY.value,
            ):
                ledger.record_detector_failure(
                    detector, f"raised {exc.__class__.__name__} during analysis"
                )
        return DetectionOutcome(
            evasion_signals=normalized.evasion_signals,
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )

    elapsed = (time.perf_counter() - started) * 1000

    # A chunk that blows the budget makes coverage incomplete. Recording it
    # rather than raising keeps partial results reportable.
    if ledger is not None and elapsed > chunk_timeout_for(len(text)) * 1000:
        ledger.record_detector_timeout(DetectorName.PRESIDIO.value)
        ledger.record_detector_timeout(DetectorName.CUSTOM_SECURITY.value)

    from core.ai_recognizers import ai_entity_types
    from core.financial_recognizers import financial_entity_types
    from core.recognizers import security_entity_types

    # All three sets are purpose-built recognizers rather than generic Presidio
    # ones, so all are attributed to CUSTOM_SECURITY. That attribution drives
    # reconciliation precedence — a targeted pattern should beat a generic guess.
    security_types = (
        set(security_entity_types())
        | set(financial_entity_types())
        | set(ai_entity_types())
    )
    entities: list[Entity] = []

    for result in results:
        start, end = normalized.index_map.to_original(result.start, result.end)
        if end <= start:
            continue

        entity_type = _PRESIDIO_ALIASES.get(result.entity_type, result.entity_type)
        is_security = entity_type in security_types
        detector = (
            DetectorName.CUSTOM_SECURITY.value
            if is_security
            else DetectorName.PRESIDIO.value
        )

        entities.append(
            Entity(
                type=entity_type,
                start=start,
                end=end,
                confidence=float(result.score),
                text=text[start:end],
                confidence_source=ConfidenceSource.CALIBRATED,
                severity=severity_for(entity_type),
                detected_by=[detector],
                is_base_security=is_security,
            )
        )

    return DetectionOutcome(
        entities=entities,
        evasion_signals=normalized.evasion_signals,
        elapsed_ms=elapsed,
    )


# --------------------------------------------------------------------------
# Shared NLP pass
# --------------------------------------------------------------------------
# Only the parser is skipped. The lemmatizer and its prerequisites are required:
# Presidio's context enhancer reads ``NlpArtifacts.lemmas`` to raise scores when
# a context word sits near a match, and DEFAULT_PII depends on that — US_SSN has
# a 0.4 threshold with ``context`` among its detection methods. Trimming lemmas
# would be a silent recall change dressed up as an optimisation.
_SPACY_UNUSED_COMPONENTS = ("parser",)

# Set once if the shared-NLP optimisation stops working. Module-level rather than
# per-session because it is a property of the installed Presidio, not of a user.
_shared_nlp_failure: str | None = None


def build_shared_nlp(text: str, language: str = "en"):
    """Run spaCy once and return ``(doc, nlp_artifacts)`` for both detectors.

    Presidio loads its own spaCy model and runs its own pass, on top of the pass
    this module already runs — the NLP work happened twice on identical text for
    identical output. ``AnalyzerEngine.analyze`` accepts pre-computed artifacts,
    so one pass can serve both.

    The artifacts are produced by Presidio's own converter rather than assembled
    here. Its NER configuration relabels and filters spans on the way through
    (``GPE`` becomes ``LOCATION``, for instance), and reimplementing that mapping
    would be a second source of truth that drifts.

    Note the returned ``doc.ents`` carry *raw* spaCy labels while
    ``artifacts.entities`` carry Presidio's relabelled ones. Our spaCy detector
    maps raw labels, so it must read ``doc.ents``.
    """
    global _shared_nlp_failure

    nlp = get_spacy()
    doc = nlp(text, disable=_SPACY_UNUSED_COMPONENTS)

    artifacts = None
    try:
        artifacts = get_analyzer().nlp_engine._doc_to_nlp_artifact(doc, language)
    except Exception as exc:  # pragma: no cover - Presidio internals changed
        # Falling back is correct — Presidio does its own pass, slower and
        # identical — but it must not be silent. This depends on a private
        # Presidio method, so a version bump can break it, and the only symptom
        # would be everything quietly getting 21% slower forever. Recorded once
        # and surfaced in the health panel.
        artifacts = None
        if _shared_nlp_failure is None:
            _shared_nlp_failure = (
                f"{exc.__class__.__name__} from Presidio's "
                f"_doc_to_nlp_artifact — the shared NLP pass is disabled and "
                f"detection is running the NLP work twice. Correct, ~20% slower."
            )

    return doc, artifacts


def shared_nlp_failure() -> str | None:
    """Why the shared NLP pass is unavailable, or None if it is working."""
    return _shared_nlp_failure


def reset_shared_nlp_failure() -> None:
    """Test support: clear the recorded failure."""
    global _shared_nlp_failure
    _shared_nlp_failure = None


# --------------------------------------------------------------------------
# spaCy
# --------------------------------------------------------------------------


def detect_spacy(
    text: str,
    *,
    ledger: CoverageLedger | None = None,
    doc=None,
    normalized: NormalizationResult | None = None,
) -> DetectionOutcome:
    """Run spaCy NER, returning entities in original coordinates.

    ``doc`` lets the caller supply a Doc already produced for this same
    normalized text, so the model runs once per chunk rather than twice. It must
    be a Doc over ``normalize(text).text``, not over the raw text — the offsets
    are mapped back through the normalization index map.

    ``normalized`` lets the caller supply an existing normalization, avoiding a
    second index-map build for the same chunk.
    """
    normalized = normalized if normalized is not None else normalize(text)

    if not normalized.text.strip():
        return DetectionOutcome()

    # Model load is untimed for the same reason as Presidio above: loading
    # en_core_web_lg takes seconds and is not detection work.
    try:
        nlp = get_spacy()
    except DetectorUnavailable as exc:
        if ledger is not None:
            ledger.record_detector_unavailable(DetectorName.SPACY.value, str(exc))
        raise

    started = time.perf_counter()

    if ledger is not None:
        ledger.start_detector(DetectorName.SPACY.value)

    try:
        if doc is None:
            doc = nlp(normalized.text, disable=_SPACY_UNUSED_COMPONENTS)
    except Exception as exc:
        if ledger is not None:
            ledger.record_detector_failure(
                DetectorName.SPACY.value,
                f"raised {exc.__class__.__name__} during analysis",
            )
        return DetectionOutcome(
            elapsed_ms=(time.perf_counter() - started) * 1000
        )

    elapsed = (time.perf_counter() - started) * 1000
    if ledger is not None and elapsed > chunk_timeout_for(len(text)) * 1000:
        ledger.record_detector_timeout(DetectorName.SPACY.value)

    entities: list[Entity] = []
    for span in doc.ents:
        entity_type = _SPACY_LABELS.get(span.label_)
        if entity_type is None:
            continue

        start, end = normalized.index_map.to_original(
            span.start_char, span.end_char
        )
        if end <= start:
            continue

        entities.append(
            Entity(
                type=entity_type,
                start=start,
                end=end,
                confidence=SPACY_HEURISTIC_CONFIDENCE,
                text=text[start:end],
                # Tagged HEURISTIC so reconciliation does not treat this
                # constant as a real probability.
                confidence_source=ConfidenceSource.HEURISTIC,
                severity=severity_for(entity_type),
                detected_by=[DetectorName.SPACY.value],
            )
        )

    return DetectionOutcome(entities=entities, elapsed_ms=elapsed)


# --------------------------------------------------------------------------
# Combined
# --------------------------------------------------------------------------
def detect_chunk(
    text: str,
    *,
    entity_types: list[str] | None = None,
    threshold: float = 0.0,
    language: str = "en",
    use_spacy: bool = True,
    ledger: CoverageLedger | None = None,
) -> DetectionOutcome:
    """Run all configured detectors over one chunk.

    spaCy unavailability is recorded rather than raised: the caller may still
    want Presidio results for reporting. Whether that is sufficient is decided
    by the coverage gate, not here.
    """
    # One spaCy pass feeds both detectors. Presidio would otherwise run its own
    # over identical text for identical output — the single largest piece of
    # duplicated work in the pipeline.
    #
    # Failure here is not fatal: build_shared_nlp returning nothing means each
    # detector falls back to doing its own pass, which is slower and correct.
    # Normalized once here and threaded through both detectors. Each used to
    # normalize independently, so a chunk was normalized three times over — once
    # for the shared NLP pass and once inside each detector — building the same
    # index map each time.
    normalized = normalize(text)

    doc = None
    artifacts = None
    if use_spacy:
        try:
            doc, artifacts = build_shared_nlp(normalized.text, language)
        except DetectorUnavailable:
            if ledger is not None:
                ledger.record_detector_unavailable(
                    DetectorName.SPACY.value, "spaCy model unavailable"
                )
            doc = None
            artifacts = None

    outcome = detect_presidio(
        text,
        entity_types=entity_types,
        threshold=threshold,
        language=language,
        ledger=ledger,
        nlp_artifacts=artifacts,
        normalized=normalized,
    )

    if not use_spacy:
        return outcome

    try:
        spacy_outcome = detect_spacy(
            text, ledger=ledger, doc=doc, normalized=normalized
        )
    except DetectorUnavailable:
        # Already recorded in the ledger; coverage will reflect it.
        return outcome

    return DetectionOutcome(
        entities=[*outcome.entities, *spacy_outcome.entities],
        evasion_signals=outcome.evasion_signals,
        elapsed_ms=outcome.elapsed_ms + spacy_outcome.elapsed_ms,
    )
