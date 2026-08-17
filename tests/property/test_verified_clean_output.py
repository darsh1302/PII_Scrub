"""Property 11 — verified-clean output. Guardrail G7.

The claim: **whenever the pipeline returns status OK, the sanitized output
contains nothing that policy required to be removed.**

This is the property that makes the tool trustworthy rather than merely helpful.
A scrubber that occasionally leaves PII in output it labelled clean is worse than
no scrubber, because it manufactures confidence. Generative testing matters here
because the failure mode is positional and content-dependent — adjacent entities,
overlapping spans, replacement lengths shifting offsets. Hand-picked cases miss
exactly those.
"""

from __future__ import annotations

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from core.file_source import load_text
from core.pipeline import ScanOptions, scan_and_scrub
from core.profile_resolver import resolve_profile
from core.verifier import verify_sanitized
from models.enums import Destination, ScrubAction
from session.context import get_session_context
from utils.config import Settings

SETTINGS = settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[
        HealthCheck.too_slow,
        HealthCheck.function_scoped_fixture,
        HealthCheck.filter_too_much,
    ],
)

# Fragments that reliably produce detections, so the property is exercised
# against real entities rather than random noise.
PII_FRAGMENTS = [
    "ssn=482-71-9053",
    "ssn 482-71-9053",
    "alice.morgan@example.com",
    "card 4532015112830366",
    "+1 (415) 555-0142",
    "api_key=sk-live-9fK2mQ7xR4tZ8vB1nH6jL0pW",
    "AKIAIOSFODNN7EXAMPLE",
    "password=hunter2secret",
    "203.0.113.42",
    "Jane Fairweather",
    "postgresql://svc:pw@db.internal:5432/records",
    "2026-08-16T09:15:44Z INFO ok",
    "IBAN GB82WEST12345698765432",
]

FILLER = [
    "",
    "INFO request handled",
    "DEBUG cache hit",
    "WARN retry scheduled",
    "processing batch",
    "---",
]


@st.composite
def pii_document(draw, min_lines: int = 1, max_lines: int = 25):
    """A document mixing detectable entities with benign filler."""
    lines = draw(
        st.lists(
            st.sampled_from(PII_FRAGMENTS) | st.sampled_from(FILLER),
            min_size=min_lines,
            max_size=max_lines,
        )
    )
    return "\n".join(lines)


def _session(tmp_path):
    settings_obj = Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"property-salt",
        scan_roots=(),
        audit_dir=tmp_path / "audit",
    )
    return get_session_context("property-test", settings_obj)


# ---------------------------------------------------------------------------
# The central property
# ---------------------------------------------------------------------------


@given(text=pii_document())
@SETTINGS
def test_ok_status_implies_no_residual_that_policy_required_removing(
    tmp_path_factory, text
):
    """Property 11, stated directly."""
    assume(text.strip())
    session = _session(tmp_path_factory.mktemp("prop"))

    loaded = load_text(text, session)
    result = scan_and_scrub(
        loaded.handle, session, ScanOptions(destination=Destination.FILE)
    )

    if result.status != "OK":
        return  # refusals are permitted; they are the safe outcome

    assert result.verified_clean is True
    assert result.sanitized_handle is not None

    sanitized = session.content_store.get(result.sanitized_handle).content
    profile = resolve_profile("DEFAULT_PII")

    permitted: dict[str, int] = {}
    for decision in result.decisions:
        if decision.applied_action is ScrubAction.ALLOW:
            key = decision.entity.type
            permitted[key] = permitted.get(key, 0) + 1

    recheck = verify_sanitized(sanitized, profile, permitted_counts=permitted)
    assert recheck.clean is True, (
        f"independent re-verification found {recheck.residual_count} residual: "
        f"{recheck.residual_breakdown()}"
    )


@given(text=pii_document())
@SETTINGS
def test_ok_status_implies_scrubbed_values_are_literally_absent(
    tmp_path_factory, text
):
    """Direct string check, independent of the detectors.

    Verification uses the same engines as detection, so a shared blind spot
    would pass unnoticed. Asserting the literal text is gone catches that.
    """
    assume(text.strip())
    session = _session(tmp_path_factory.mktemp("prop"))

    loaded = load_text(text, session)
    result = scan_and_scrub(
        loaded.handle, session, ScanOptions(destination=Destination.FILE)
    )

    if result.status != "OK":
        return

    sanitized = session.content_store.get(result.sanitized_handle).content

    for decision in result.decisions:
        if decision.applied_action is ScrubAction.ALLOW:
            continue
        value = decision.entity.text
        # Short values may legitimately reappear as substrings of markers or
        # unrelated text; only assert on values long enough to be distinctive.
        if len(value) < 8:
            continue
        assert value not in sanitized, (
            f"{decision.entity.type} value survived a "
            f"{decision.applied_action.value} action"
        )


# ---------------------------------------------------------------------------
# Artifact gating
# ---------------------------------------------------------------------------


@given(text=pii_document())
@SETTINGS
def test_artifact_is_offered_only_when_verified(tmp_path_factory, text):
    """A handle alone must never be enough to export."""
    assume(text.strip())
    session = _session(tmp_path_factory.mktemp("prop"))

    loaded = load_text(text, session)
    result = scan_and_scrub(
        loaded.handle, session, ScanOptions(destination=Destination.FILE)
    )

    if result.artifact_available:
        assert result.verified_clean is True
        assert result.sanitized_handle is not None
        assert result.refusal is None
    else:
        assert not (result.verified_clean and result.sanitized_handle)


@given(text=pii_document())
@SETTINGS
def test_refusals_never_produce_a_sanitized_handle(tmp_path_factory, text):
    assume(text.strip())
    session = _session(tmp_path_factory.mktemp("prop"))

    loaded = load_text(text, session)
    result = scan_and_scrub(
        loaded.handle, session, ScanOptions(destination=Destination.FILE)
    )

    if result.is_refusal:
        assert result.sanitized_handle is None
        assert result.artifact_available is False


# ---------------------------------------------------------------------------
# Applier correctness
# ---------------------------------------------------------------------------


@given(text=pii_document(min_lines=2, max_lines=20))
@SETTINGS
def test_output_length_changes_do_not_corrupt_unrelated_content(
    tmp_path_factory, text
):
    """Right-to-left application must leave benign lines untouched.

    Applying left-to-right would invalidate later offsets and corrupt text that
    contained no PII at all.
    """
    assume(text.strip())
    session = _session(tmp_path_factory.mktemp("prop"))

    loaded = load_text(text, session)
    result = scan_and_scrub(
        loaded.handle, session, ScanOptions(destination=Destination.FILE)
    )

    if result.status != "OK":
        return

    sanitized = session.content_store.get(result.sanitized_handle).content

    # Lines that contained no detected entity must survive verbatim.
    original_lines = text.split("\n")
    entity_lines: set[int] = set()
    cursor = 0
    for index, line in enumerate(original_lines):
        line_end = cursor + len(line)
        for entity in result.entities:
            if entity.start < line_end and cursor < entity.end:
                entity_lines.add(index)
        cursor = line_end + 1

    for index, line in enumerate(original_lines):
        if index in entity_lines or not line.strip():
            continue
        assert line in sanitized, f"benign line {index} was altered: {line!r}"


@given(text=pii_document())
@SETTINGS
def test_every_decision_is_accounted_for_in_the_action_counts(
    tmp_path_factory, text
):
    """Property 3 — anonymisation completeness."""
    assume(text.strip())
    session = _session(tmp_path_factory.mktemp("prop"))

    loaded = load_text(text, session)
    result = scan_and_scrub(
        loaded.handle, session, ScanOptions(destination=Destination.FILE)
    )

    counts = result.decisions.action_counts()
    assert sum(counts.values()) == len(result.decisions)
