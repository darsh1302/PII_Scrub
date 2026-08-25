"""Detection over a chunk — accuracy, coverage recording, offset mapping.

The coverage-recording tests matter most: a detector that fails must make the
ledger incomplete, because that is what blocks artifact production in Phase 4.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from pii_agent.core.detector import (
    SPACY_HEURISTIC_CONFIDENCE,
    DetectorUnavailable,
    detect_chunk,
    detect_presidio,
    detect_spacy,
    spacy_available,
)
from pii_agent.core.profile_resolver import resolve_profile
from pii_agent.models.coverage import CoverageLedger
from pii_agent.models.enums import ConfidenceSource, DetectorName, EntitySeverity

FIXTURES = Path(__file__).parent.parent / "fixtures"


def _types(outcome) -> set[str]:
    return {e.type for e in outcome.entities}


# ---------------------------------------------------------------------------
# Presidio accuracy
# ---------------------------------------------------------------------------


def test_detects_email_address():
    assert "EMAIL_ADDRESS" in _types(
        detect_presidio("contact alice.morgan@example.com today")
    )


def test_detects_luhn_valid_credit_card():
    assert "CREDIT_CARD" in _types(detect_presidio("card 4532015112830366"))


def test_detects_ssn_with_context():
    assert "US_SSN" in _types(detect_presidio("patient ssn=482-71-9053"))


def test_detects_ip_address():
    assert "IP_ADDRESS" in _types(detect_presidio("request from 203.0.113.42"))


def test_clean_text_yields_no_detections():
    """False positives on operational log lines make the tool unusable."""
    outcome = detect_presidio(
        "cache warm complete entries=48210 heap=512MB workers=8", threshold=0.5
    )
    assert outcome.entities == []


# ---------------------------------------------------------------------------
# Custom security recognizers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload,expected",
    [
        ("api_key=sk-live-9fK2mQ7xR4tZ8vB1nH6jL0pW", "API_KEY"),
        ("AKIAIOSFODNN7EXAMPLE", "AWS_ACCESS_KEY"),
        ("password=hunter2secret", "PASSWORD"),
        ("client_secret=abc123def456ghi", "CLIENT_SECRET"),
        ("refresh_token=rt_abc123def456", "REFRESH_TOKEN"),
        (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0"
            "NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            "AUTHORIZATION_HEADER",
        ),
        (
            "postgresql://svc_user:hunter2@db.internal:5432/records",
            "CONNECTION_STRING",
        ),
        ("ghp_" + "a" * 36, "API_KEY"),
        ("sk_live_" + "b" * 24, "API_KEY"),
    ],
)
def test_credential_types_are_detected(payload: str, expected: str):
    assert expected in _types(detect_presidio(payload, threshold=0.3))


def test_jwt_is_detected():
    jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
        ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    assert "JWT" in _types(detect_presidio(f"token {jwt}", threshold=0.3))


def test_pem_private_key_is_detected():
    from tests.pii_agent.fixtures.make_fixtures import PEM_KEY

    assert "PRIVATE_KEY" in _types(detect_presidio(PEM_KEY, threshold=0.3))


def test_credential_entities_are_flagged_base_security():
    """Drives the policy ratchet's unconditional branch."""
    outcome = detect_presidio("api_key=sk-live-abc123def456ghi", threshold=0.3)
    api_keys = [e for e in outcome.entities if e.type == "API_KEY"]
    assert api_keys
    assert all(e.is_base_security for e in api_keys)


def test_credential_entities_are_high_severity():
    """HIGH severity is what keeps their text out of the reasoning context."""
    outcome = detect_presidio("api_key=sk-live-abc123def456ghi", threshold=0.3)
    api_keys = [e for e in outcome.entities if e.type == "API_KEY"]
    assert all(e.severity is EntitySeverity.HIGH for e in api_keys)


def test_credential_detections_are_attributed_to_custom_security():
    outcome = detect_presidio("password=hunter2secret", threshold=0.3)
    passwords = [e for e in outcome.entities if e.type == "PASSWORD"]
    assert all(
        DetectorName.CUSTOM_SECURITY.value in e.detected_by for e in passwords
    )


# ---------------------------------------------------------------------------
# Offset correctness
# ---------------------------------------------------------------------------


def test_reported_spans_match_the_original_text():
    text = "user alice.morgan@example.com logged in from 203.0.113.42"
    for entity in detect_presidio(text, threshold=0.3).entities:
        assert text[entity.start : entity.end] == entity.text


def test_offsets_survive_zero_width_evasion():
    """Normalization must not shift reported offsets.

    A zero-width space inside an SSN defeats the pattern unless normalized, but
    if the offset map is wrong the scrub lands on the wrong characters.
    """
    text = "ssn 482-\u200b71-\u200b9053 end"
    outcome = detect_presidio(text, threshold=0.3)
    for entity in outcome.entities:
        assert text[entity.start : entity.end] == entity.text


def test_zero_width_characters_are_reported_as_evasion_signals():
    text = "ssn 482-\u200b71-\u200b9053"
    outcome = detect_presidio(text, threshold=0.3)
    assert outcome.evasion_signals
    assert "zero-width" in outcome.evasion_signals[0]


def test_homoglyph_folding_is_reported():
    text = "\u0430pi_key=sk-live-abc123def456"  # Cyrillic 'а'
    outcome = detect_presidio(text, threshold=0.3)
    assert any("homoglyph" in s for s in outcome.evasion_signals)


# ---------------------------------------------------------------------------
# Coverage recording — the fail-closed inputs
# ---------------------------------------------------------------------------


def test_successful_detection_marks_presidio_and_custom_security_healthy():
    """Both run in one analyze() call, so both must be recorded.

    Recording only 'presidio' would leave any profile requiring
    'custom_security' permanently short of complete coverage, and the
    fail-closed gate would refuse every scan.
    """
    ledger = CoverageLedger(
        bytes_total=10, required_detectors=frozenset({"presidio", "custom_security"})
    )
    detect_presidio("hello world", ledger=ledger)
    ledger.advance_bytes(10)

    assert "presidio" in ledger.healthy_detectors
    assert "custom_security" in ledger.healthy_detectors
    assert ledger.is_complete() is True


def test_detector_failure_is_recorded_and_blocks_completion(monkeypatch):
    ledger = CoverageLedger(
        bytes_total=10, required_detectors=frozenset({"presidio"})
    )

    class Exploding:
        def analyze(self, **_kwargs):
            raise RuntimeError("recognizer exploded")

    monkeypatch.setattr("pii_agent.core.detector.get_analyzer", lambda: Exploding())

    outcome = detect_presidio("some text", ledger=ledger)
    ledger.advance_bytes(10)

    assert outcome.entities == []
    assert "presidio" in ledger.failed_detectors
    assert ledger.is_complete() is False
    assert "presidio" in ledger.describe()


def test_missing_spacy_model_is_recorded_not_silently_ignored(monkeypatch):
    """SEC-05: the case the original design let through."""
    ledger = CoverageLedger(
        bytes_total=10, required_detectors=frozenset({"presidio", "spacy"})
    )

    def boom():
        raise DetectorUnavailable("model not installed")

    monkeypatch.setattr("pii_agent.core.detector.get_spacy", boom)

    detect_chunk("Jane Fairweather called", ledger=ledger, use_spacy=True)
    ledger.advance_bytes(10)

    assert "spacy" in ledger.failed_detectors
    assert ledger.is_complete() is False


def test_detect_chunk_still_returns_presidio_results_when_spacy_missing(monkeypatch):
    """Results remain reportable; only sanitization is blocked."""
    def boom():
        raise DetectorUnavailable("model not installed")

    monkeypatch.setattr("pii_agent.core.detector.get_spacy", boom)

    outcome = detect_chunk("email alice@example.com", threshold=0.3)
    assert "EMAIL_ADDRESS" in _types(outcome)


# ---------------------------------------------------------------------------
# spaCy
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not spacy_available(), reason="spaCy model not installed")
def test_spacy_detects_person_in_context():
    """Contextual names are what regex cannot reach."""
    outcome = detect_spacy("Jane Fairweather approved the transfer yesterday")
    assert "PERSON" in _types(outcome)


@pytest.mark.skipif(not spacy_available(), reason="spaCy model not installed")
def test_spacy_confidence_is_tagged_heuristic():
    """It emits no calibrated probability; the constant must be labelled."""
    outcome = detect_spacy("Jane Fairweather approved the transfer")
    assert outcome.entities
    for entity in outcome.entities:
        assert entity.confidence_source is ConfidenceSource.HEURISTIC
        assert entity.confidence == SPACY_HEURISTIC_CONFIDENCE


@pytest.mark.skipif(not spacy_available(), reason="spaCy model not installed")
def test_spacy_offsets_match_original_text():
    text = "Jane Fairweather visited London on 16 August 2026"
    for entity in detect_spacy(text).entities:
        assert text[entity.start : entity.end] == entity.text


@pytest.mark.skipif(not spacy_available(), reason="spaCy model not installed")
def test_combined_detection_includes_both_engines():
    text = "Jane Fairweather email alice@example.com api_key=sk-live-abc123def"
    outcome = detect_chunk(text, threshold=0.3)
    detectors = {d for e in outcome.entities for d in e.detected_by}
    assert "spacy" in detectors
    assert {"presidio", "custom_security"} & detectors


# ---------------------------------------------------------------------------
# Realistic end-to-end over a fixture
# ---------------------------------------------------------------------------


def test_sample_log_yields_expected_entity_families():
    from pii_agent.core.reconciler import filter_by_profile, reconcile

    text = (FIXTURES / "sample_log.txt").read_text(encoding="utf-8")
    profile = resolve_profile("DEFAULT_PII")
    ledger = CoverageLedger(
        bytes_total=len(text.encode()),
        required_detectors=profile.required_detectors,
    )

    outcome = detect_chunk(text, threshold=0.3, ledger=ledger)
    ledger.advance_bytes(len(text.encode()))
    reconciled, _ = reconcile(outcome.entities)
    filtered, _ = filter_by_profile(reconciled, profile)

    found = {e.type for e in filtered}
    assert {"US_SSN", "CREDIT_CARD", "EMAIL_ADDRESS"} <= found
    # At least one credential family must be caught.
    assert found & {
        "API_KEY",
        "AWS_ACCESS_KEY",
        "PASSWORD",
        "CONNECTION_STRING",
        "AUTHORIZATION_HEADER",
        "ACCESS_TOKEN",
    }
    assert ledger.is_complete() is True


def test_clean_fixture_yields_no_high_confidence_pii():
    from pii_agent.core.reconciler import filter_by_profile, reconcile

    text = (FIXTURES / "sample_clean.txt").read_text(encoding="utf-8")
    profile = resolve_profile("DEFAULT_PII")

    outcome = detect_chunk(text, threshold=0.3)
    reconciled, _ = reconcile(outcome.entities)
    filtered, _ = filter_by_profile(reconciled, profile)

    # DATE_TIME on log timestamps is expected here; nothing else should appear.
    unexpected = {e.type for e in filtered} - {"DATE_TIME"}
    assert not unexpected, f"false positives on clean content: {unexpected}"



# ---------------------------------------------------------------------------
# Shared NLP pass
# ---------------------------------------------------------------------------
# Presidio loaded its own spaCy model and ran its own pass on top of ours, so the
# NLP work happened twice on identical text for identical output. One pass now
# feeds both. The invariant is that sharing changes nothing about what is found —
# it is purely a saving, and the moment it stops being purely a saving it is a
# silent detection regression.
def test_shared_nlp_returns_a_doc_and_artifacts():
    from pii_agent.core.detector import build_shared_nlp

    doc, artifacts = build_shared_nlp(
        "Contact Priya Raghunathan at priya@example.com in London"
    )
    assert doc is not None
    assert artifacts is not None
    # Raw spaCy labels on the doc, Presidio's relabelled ones on the artifacts.
    assert any(ent.label_ == "PERSON" for ent in doc.ents)
    assert artifacts.lemmas, "lemmas are required by Presidio's context enhancer"


def test_supplying_artifacts_does_not_change_presidio_output():
    """The whole optimisation rests on this."""
    from pii_agent.core.detector import build_shared_nlp, detect_presidio, normalize

    text = (
        "user=Dana Reyes email=dana.reyes@example.com ssn=482-71-9053 "
        "card=4532015112830366 host=London office ip=10.20.4.11"
    )

    _, artifacts = build_shared_nlp(normalize(text).text)

    without = detect_presidio(text, threshold=0.0)
    with_shared = detect_presidio(text, threshold=0.0, nlp_artifacts=artifacts)

    def signature(outcome):
        return sorted(
            (e.type, e.start, e.end, round(float(e.confidence), 6))
            for e in outcome.entities
        )

    assert signature(with_shared) == signature(without)


def test_supplying_a_doc_does_not_change_spacy_output():
    from pii_agent.core.detector import build_shared_nlp, detect_spacy, normalize

    text = "Priya Raghunathan met Dana Reyes in London and Berlin last week."
    doc, _ = build_shared_nlp(normalize(text).text)

    without = detect_spacy(text)
    with_shared = detect_spacy(text, doc=doc)

    def signature(outcome):
        return sorted((e.type, e.start, e.end) for e in outcome.entities)

    assert signature(with_shared) == signature(without)


def test_lemmatizer_stays_enabled():
    """Presidio's context enhancer reads lemmas to boost context-adjacent scores.

    DEFAULT_PII gives US_SSN a 0.4 threshold with ``context`` among its detection
    methods, so dropping lemmas would lower recall while looking like a speedup.
    """
    from pii_agent.core.detector import _SPACY_UNUSED_COMPONENTS

    assert "lemmatizer" not in _SPACY_UNUSED_COMPONENTS
    assert "tagger" not in _SPACY_UNUSED_COMPONENTS
    assert "attribute_ruler" not in _SPACY_UNUSED_COMPONENTS
