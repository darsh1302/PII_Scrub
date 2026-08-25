"""Data model invariants.

The important ones: the action lattice that makes the policy ratchet monotonic,
the coverage gate that fails closed, and the LLM-exposure projections that keep
content out of the reasoning context.
"""

from __future__ import annotations

import pytest

from pii_agent.models.coverage import CoverageLedger
from pii_agent.models.decision import Decision, DecisionSet, PolicyViolation
from pii_agent.models.entities import Entity, NormalizedEvent, severity_for
from pii_agent.models.enums import (
    ConfidenceSource,
    Destination,
    EntitySeverity,
    RefusalReason,
    ScrubAction,
    SourceType,
)
from pii_agent.models.results import EngineVersions, ProcessingResult


# ---------------------------------------------------------------------------
# ScrubAction lattice
# ---------------------------------------------------------------------------


def test_most_restrictive_picks_the_stricter_action():
    assert (
        ScrubAction.most_restrictive(ScrubAction.ALLOW, ScrubAction.REDACT)
        is ScrubAction.REDACT
    )
    assert (
        ScrubAction.most_restrictive(ScrubAction.MASK, ScrubAction.REPLACE)
        is ScrubAction.MASK
    )


def test_most_restrictive_ignores_none():
    """Callers pass an absent request without branching."""
    assert (
        ScrubAction.most_restrictive(ScrubAction.MASK, None) is ScrubAction.MASK
    )


def test_most_restrictive_requires_at_least_one_action():
    with pytest.raises(ValueError):
        ScrubAction.most_restrictive(None, None)


def test_block_is_distinct_from_redact():
    """COR-05 — BLOCK suppresses the artifact; REDACT still yields output."""
    assert ScrubAction.BLOCK.suppresses_artifact is True
    assert ScrubAction.REDACT.suppresses_artifact is False


def test_hash_ranks_below_tokenize():
    assert ScrubAction.HASH.priority < ScrubAction.TOKENIZE.priority


# ---------------------------------------------------------------------------
# Severity and LLM exposure
# ---------------------------------------------------------------------------


def test_high_severity_text_may_not_reach_llm():
    """Requirement 31.2 — sending a secret to ask if it is a secret is absurd."""
    assert EntitySeverity.HIGH.text_may_reach_llm is False
    assert EntitySeverity.MEDIUM.text_may_reach_llm is True


def test_credentials_default_to_high_severity():
    for t in ("API_KEY", "PRIVATE_KEY", "JWT", "PASSWORD", "AWS_ACCESS_KEY"):
        assert severity_for(t) is EntitySeverity.HIGH


def test_unknown_type_defaults_to_medium_not_low():
    """Bias toward protection for anything unrecognised."""
    assert severity_for("SOME_NEW_TYPE") is EntitySeverity.MEDIUM


def test_destination_external_classification():
    assert Destination.EXTERNAL_LLM.is_external is True
    assert Destination.INTERNAL_SIEM.is_external is False


# ---------------------------------------------------------------------------
# Entity
# ---------------------------------------------------------------------------


def test_entity_repr_never_contains_text():
    e = Entity(type="US_SSN", start=0, end=11, confidence=0.9, text="123-45-6789")
    assert "123-45-6789" not in repr(e)


def test_high_severity_preview_is_a_type_label_only():
    e = Entity(type="API_KEY", start=0, end=20, confidence=0.9, text="sk-live-abc123xyz")
    assert e.to_llm_metadata()["preview"] == "[API_KEY]"


def test_medium_severity_preview_is_masked_not_plain():
    e = Entity(type="EMAIL_ADDRESS", start=0, end=17, confidence=0.9, text="alice@example.com")
    preview = e.to_llm_metadata()["preview"]
    assert preview == "al*************om"
    assert "alice@example.com" != preview


def test_llm_metadata_omits_offsets_entirely():
    """SEC-02 — the model has no legitimate use for offsets."""
    e = Entity(type="PERSON", start=42, end=52, confidence=0.8, text="Jane Smith")
    metadata = e.to_llm_metadata()
    assert "start" not in metadata
    assert "end" not in metadata
    assert 42 not in metadata.values()


@pytest.mark.parametrize(
    "start,end", [(-1, 5), (5, 5), (10, 3), (0, 0)]
)
def test_invalid_spans_are_rejected(start, end):
    with pytest.raises(ValueError):
        Entity(type="PERSON", start=start, end=end, confidence=0.5)


@pytest.mark.parametrize("confidence", [-0.1, 1.1, 2.0])
def test_out_of_range_confidence_is_rejected(confidence):
    with pytest.raises(ValueError):
        Entity(type="PERSON", start=0, end=5, confidence=confidence)


def test_shifted_translates_offsets_and_preserves_everything_else():
    e = Entity(
        type="PERSON",
        start=10,
        end=20,
        confidence=0.8,
        text="Jane Smith",
        detected_by=["spacy"],
    )
    moved = e.shifted(8000)
    assert moved.span == (8010, 8020)
    assert moved.text == e.text
    assert moved.detected_by == ["spacy"]


def test_overlap_and_containment():
    a = Entity(type="LOCATION", start=0, end=20, confidence=0.7)
    b = Entity(type="PERSON", start=5, end=10, confidence=0.8)
    c = Entity(type="PERSON", start=30, end=40, confidence=0.8)
    assert a.overlaps(b) and b.overlaps(a)
    assert a.contains(b) and not b.contains(a)
    assert not a.overlaps(c)


def test_validator_backed_types_flagged():
    """Reconciliation rule 3 prefers checksum-validated detections."""
    assert Entity(type="CREDIT_CARD", start=0, end=16, confidence=0.9).is_validator_backed
    assert not Entity(type="PERSON", start=0, end=5, confidence=0.9).is_validator_backed


# ---------------------------------------------------------------------------
# NormalizedEvent
# ---------------------------------------------------------------------------


def test_event_repr_omits_content():
    ev = NormalizedEvent(source_type=SourceType.FILE, content="SSN 123-45-6789")
    assert "123-45-6789" not in repr(ev)


def test_to_document_offsets_applies_chunk_base():
    """Property 12 — chunk-local offsets must become document coordinates."""
    ev = NormalizedEvent(
        source_type=SourceType.FILE, content="x", global_offset_base=8000
    )
    local = [Entity(type="PERSON", start=12, end=22, confidence=0.8)]
    globalised = ev.to_document_offsets(local)
    assert globalised[0].span == (8012, 8022)


def test_to_document_offsets_is_a_noop_for_first_chunk():
    ev = NormalizedEvent(source_type=SourceType.FILE, global_offset_base=0)
    local = [Entity(type="PERSON", start=12, end=22, confidence=0.8)]
    assert ev.to_document_offsets(local)[0].span == (12, 22)


# ---------------------------------------------------------------------------
# CoverageLedger — the fail-closed gate
# ---------------------------------------------------------------------------


def test_complete_coverage_when_all_bytes_and_detectors_healthy():
    led = CoverageLedger(bytes_total=1000, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    led.advance_bytes(1000)
    assert led.is_complete() is True


def test_partial_bytes_is_incomplete():
    """COR-01 — a partial scan must never yield a 'clean' artifact."""
    led = CoverageLedger(bytes_total=1000, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    led.advance_bytes(400)
    assert led.is_complete() is False
    assert "40.0%" in led.describe()


def test_failed_required_detector_is_incomplete():
    """SEC-05 — the case the original design let through."""
    led = CoverageLedger(
        bytes_total=100, required_detectors=frozenset({"presidio", "spacy"})
    )
    led.start_detector("presidio")
    led.advance_bytes(100)
    led.record_detector_unavailable("spacy", "model not installed")
    assert led.is_complete() is False
    assert "spacy" in led.describe()


def test_failed_optional_detector_does_not_block():
    """Only profile-required detectors gate the artifact."""
    led = CoverageLedger(bytes_total=100, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    led.advance_bytes(100)
    led.record_detector_failure("experimental", "boom")
    assert led.is_complete() is True


def test_detector_timeout_counts_as_failure():
    led = CoverageLedger(bytes_total=100, required_detectors=frozenset({"presidio"}))
    led.record_detector_timeout("presidio")
    led.advance_bytes(100)
    assert led.is_complete() is False


def test_abort_makes_coverage_incomplete():
    led = CoverageLedger(bytes_total=100, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    led.advance_bytes(100)
    led.abort("cancelled by user")
    assert led.is_complete() is False
    assert "cancelled by user" in led.describe()


def test_approved_truncation_does_not_permit_an_artifact():
    """A partial scan can never be complete, however intentional.

    Approving truncation makes the scan deliberate, but the applier would scrub
    the inspected region and leave live values in the uninspected one — output
    that looks clean without being clean.
    """
    led = CoverageLedger(
        bytes_total=10_000,
        required_detectors=frozenset({"presidio"}),
        truncation_approved_by_user=True,
    )
    led.start_detector("presidio")
    led.advance_bytes(1000)

    assert led.is_complete() is False
    assert led.truncation_was_intentional is True
    assert led.scan_is_reportable() is True


def test_approved_truncation_is_described_as_intent_not_failure():
    led = CoverageLedger(
        bytes_total=10_000,
        required_detectors=frozenset({"presidio"}),
        truncation_approved_by_user=True,
    )
    led.start_detector("presidio")
    led.advance_bytes(1000)

    detail = led.describe()
    assert "You asked me to scan only part" in detail
    assert "leave live values" in detail


def test_unintentional_partial_scan_is_described_as_a_problem():
    """The wording must distinguish a deliberate partial scan from a failure."""
    led = CoverageLedger(
        bytes_total=10_000, required_detectors=frozenset({"presidio"})
    )
    led.start_detector("presidio")
    led.advance_bytes(1000)

    detail = led.describe()
    assert "Only 10.0% of the source was inspected" in detail
    assert "withheld deliberately" in detail


def test_describe_explains_why_the_refusal_protects_the_user():
    led = CoverageLedger(bytes_total=1000, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    led.advance_bytes(500)
    text = led.describe()
    assert "UNVERIFIED" in text
    assert "withheld" in text


def test_zero_byte_source_is_not_silently_complete():
    """bytes_total == 0 means nothing was measured, not 'all done'."""
    led = CoverageLedger(bytes_total=0, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    assert led.is_complete() is False


def test_coverage_metadata_contains_no_content():
    led = CoverageLedger(bytes_total=100, required_detectors=frozenset({"presidio"}))
    led.start_detector("presidio")
    led.advance_bytes(100)
    meta = led.to_metadata()
    assert set(meta) >= {"bytes_total", "coverage_percent", "complete"}


# ---------------------------------------------------------------------------
# Decision — Property 8
# ---------------------------------------------------------------------------


def _entity(entity_type: str = "US_SSN") -> Entity:
    return Entity(type=entity_type, start=0, end=11, confidence=0.9, text="x" * 11)


def test_decision_rejects_a_weakened_action():
    """SEC-04 — this is the bypass the reviewed design permitted."""
    with pytest.raises(PolicyViolation) as exc:
        Decision(
            entity=_entity(),
            profile_mandated_action=ScrubAction.REDACT,
            applied_action=ScrubAction.ALLOW,
        )
    assert "policy weakened" in str(exc.value)


def test_decision_accepts_an_equal_action():
    d = Decision(
        entity=_entity(),
        profile_mandated_action=ScrubAction.REDACT,
        applied_action=ScrubAction.REDACT,
    )
    assert d.was_escalated is False


def test_decision_accepts_an_escalated_action():
    d = Decision(
        entity=_entity(),
        profile_mandated_action=ScrubAction.MASK,
        applied_action=ScrubAction.REDACT,
        requested_action=ScrubAction.REDACT,
    )
    assert d.was_escalated is True


def test_decision_metadata_has_no_entity_text():
    d = Decision(
        entity=_entity(),
        profile_mandated_action=ScrubAction.REDACT,
        applied_action=ScrubAction.REDACT,
    )
    assert "text" not in d.to_metadata()


# ---------------------------------------------------------------------------
# DecisionSet
# ---------------------------------------------------------------------------


def test_decision_set_detects_artifact_suppression():
    ds = DecisionSet(
        decisions=[
            Decision(
                entity=_entity("PERSON"),
                profile_mandated_action=ScrubAction.REPLACE,
                applied_action=ScrubAction.REPLACE,
            ),
            Decision(
                entity=_entity("CVV"),
                profile_mandated_action=ScrubAction.BLOCK,
                applied_action=ScrubAction.BLOCK,
            ),
        ]
    )
    assert ds.blocks_artifact is True
    assert ds.blocking_types == ("CVV",)


def test_actionable_orders_descending_by_offset():
    """Requirement 12.8 — apply right-to-left so offsets stay valid."""
    a = Entity(type="PERSON", start=0, end=5, confidence=0.9, text="Alice")
    b = Entity(type="PERSON", start=100, end=105, confidence=0.9, text="Bobby")
    c = Entity(type="PERSON", start=50, end=55, confidence=0.9, text="Carol")
    ds = DecisionSet(
        decisions=[
            Decision(
                entity=e,
                profile_mandated_action=ScrubAction.REPLACE,
                applied_action=ScrubAction.REPLACE,
            )
            for e in (a, b, c)
        ]
    )
    starts = [d.entity.start for d in ds.actionable()]
    assert starts == [100, 50, 0]


def test_actionable_excludes_allow_decisions():
    ds = DecisionSet(
        decisions=[
            Decision(
                entity=_entity("IP_ADDRESS"),
                profile_mandated_action=ScrubAction.ALLOW,
                applied_action=ScrubAction.ALLOW,
            )
        ]
    )
    assert ds.actionable() == []


def test_discarded_requests_are_surfaced():
    """A denied request must be explained, not silently dropped."""
    ds = DecisionSet(
        decisions=[
            Decision(
                entity=_entity("US_SSN"),
                profile_mandated_action=ScrubAction.REDACT,
                applied_action=ScrubAction.REDACT,
                requested_action=ScrubAction.ALLOW,
                request_was_discarded=True,
            )
        ]
    )
    assert len(ds.discarded_requests) == 1


# ---------------------------------------------------------------------------
# ProcessingResult
# ---------------------------------------------------------------------------


def test_artifact_requires_both_handle_and_verification():
    """Property 11 — a handle alone would let unverified output escape."""
    r = ProcessingResult(sanitized_handle="h2", verified_clean=False)
    assert r.artifact_available is False

    r.verified_clean = True
    assert r.artifact_available is True

    r.sanitized_handle = None
    assert r.artifact_available is False


def test_status_reflects_refusal():
    r = ProcessingResult()
    assert r.status == "OK"
    r.refusal = RefusalReason.DEGRADED_COVERAGE
    assert r.status == "DEGRADED_COVERAGE"
    assert r.is_refusal is True


def test_llm_metadata_contains_no_content_or_offsets():
    """Property 9 — the model never receives content or entity offsets.

    The offset assertion is structural rather than a substring search, and that
    matters. The original version asserted ``"42" not in str(meta)`` for an entity at
    offset 42, and it failed once when ``request_id`` was generated as ``426a7e60`` —
    a coincidental match, not a leak.

    Distinctive offsets would have hidden the flake rather than fixed it. A short
    number legitimately appears in a hex id, a token count or a percentage, so
    searching rendered text for it asserts something the projection was never meant
    to guarantee. What Property 9 actually requires is that no *offset field* is
    present, which is what is checked here.

    Same lesson as the Hypothesis property corrected during the restructure: "this
    value appears nowhere in the output" is almost always the wrong shape for an
    assertion about a value that is also an ordinary number.
    """
    r = ProcessingResult(
        entities=[
            Entity(type="US_SSN", start=42, end=53, confidence=0.9, text="123-45-6789")
        ]
    )
    meta = r.to_llm_metadata()

    # Content must not appear at all. A credit-card-shaped string has no innocent
    # reason to be in a metadata projection, so a substring search is valid here.
    assert "123-45-6789" not in str(meta)

    forbidden_keys = {"start", "end", "offset", "offsets", "start_offset",
                      "end_offset", "text", "value", "content", "entities"}

    def walk(node, path="meta"):
        if isinstance(node, dict):
            for key, value in node.items():
                assert key not in forbidden_keys, (
                    f"{path}.{key} exposes an offset or a value to the model"
                )
                walk(value, f"{path}.{key}")
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(meta)

    # And the offsets are genuinely absent as values, checked against the fields that
    # could plausibly carry a number rather than against the whole rendering.
    numeric_values = _numeric_leaves(meta)
    assert 42 not in numeric_values
    assert 53 not in numeric_values


def test_the_llm_metadata_checker_would_catch_a_leak():
    """The guard on the guard above.

    A structural check that walks a nested dict is easy to write in a way that only
    inspects the top level, and it would then pass for a projection that nested an
    offset one layer down. This drives the same walk over a fabricated projection that
    does leak, and asserts it is caught.
    """
    leaky = {
        "request_id": "abc123",
        "entity_breakdown": {"US_SSN": 1},
        "spans": [{"start": 42, "end": 53}],
    }

    forbidden_keys = {"start", "end", "offset", "text", "value", "content"}
    found: list[str] = []

    def walk(node, path="meta"):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in forbidden_keys:
                    found.append(f"{path}.{key}")
                walk(value, f"{path}.{key}")
        elif isinstance(node, (list, tuple)):
            for index, value in enumerate(node):
                walk(value, f"{path}[{index}]")

    walk(leaky)
    assert found == ["meta.spans[0].start", "meta.spans[0].end"]
    assert 42 in _numeric_leaves(leaky)


def _numeric_leaves(node) -> set[int]:
    """Every integer appearing anywhere in a nested structure.

    Used to assert offsets are absent as values without tripping over a hex id that
    happens to contain the same digits as a string.
    """
    found: set[int] = set()
    if isinstance(node, bool):
        return found
    if isinstance(node, int):
        found.add(node)
    elif isinstance(node, dict):
        for value in node.values():
            found |= _numeric_leaves(value)
    elif isinstance(node, (list, tuple)):
        for value in node:
            found |= _numeric_leaves(value)
    return found


def test_audit_record_avoids_forbidden_field_names():
    """Must pass AuditSink validation (Property 5)."""
    from pii_agent.session.audit_sink import AuditSink

    r = ProcessingResult(
        entities=[
            Entity(type="US_SSN", start=0, end=11, confidence=0.9, text="123-45-6789")
        ],
        source_identifier_hash="abc123",
    )
    record = r.to_audit_record()
    AuditSink._path_for  # sanity: symbol exists
    from pii_agent.session.audit_sink import _assert_pii_free

    _assert_pii_free(record)  # raises if a forbidden field is present


def test_refusal_reasons_have_plain_language_messages():
    """No stack traces or internal codes reach the user."""
    for reason in RefusalReason:
        message = reason.user_message
        assert len(message) > 20
        assert "Exception" not in message
        assert "Traceback" not in message


def test_engine_versions_fingerprint_is_stable():
    a = EngineVersions.detect("DEFAULT_PII", "1.0.0")
    b = EngineVersions.detect("DEFAULT_PII", "1.0.0")
    assert a.fingerprint() == b.fingerprint()


def test_engine_versions_fingerprint_changes_with_profile_version():
    a = EngineVersions.detect("DEFAULT_PII", "1.0.0")
    b = EngineVersions.detect("DEFAULT_PII", "1.1.0")
    assert a.fingerprint() != b.fingerprint()
