"""Streamlit rendering of a ProcessingResult.

Split from ``ui.presenters`` so the presentation *logic* stays testable without
importing Streamlit. This module is the thin drawing layer.

Requirements 29, 36.5. The export button is gated on ``artifact_available``,
which requires both a sanitized handle and a passed verification — a handle alone
would let unverified output escape (Property 11).
"""

from __future__ import annotations

import json
from pathlib import Path

import streamlit as st

from pii_agent.models.results import ProcessingResult
from pii_agent.session.context import SessionContext
from pii_agent.ui.presenters import (
    build_entity_rows,
    build_summary,
    describe_denied_requests,
    describe_refusal,
    describe_security_findings,
)


def render_result(result: ProcessingResult, session: SessionContext) -> None:
    """Draw findings, refusals, and export controls for one result."""
    summary = build_summary(result)

    _render_headline(result, summary)
    _render_security_findings(result)
    _render_refusal(result)
    _render_denied_requests(result)
    _render_metrics(summary)
    _render_findings_table(result)
    _render_export(result, session)
    _render_provenance(result, summary)


# ---------------------------------------------------------------------------
def _render_headline(result: ProcessingResult, summary: dict) -> None:
    if result.artifact_available:
        st.success(
            f"Cleaned copy ready and verified — {summary['entities']} item(s) "
            f"handled across {summary['types']} type(s)."
        )
    elif result.is_refusal:
        pass  # the refusal block below carries the headline
    elif summary["entities"]:
        st.info(
            f"Found {summary['entities']} item(s) across {summary['types']} "
            f"type(s). Nothing has been changed yet."
        )
    else:
        st.success("No sensitive data found.")

    if summary["unverified"]:
        st.warning(
            "These findings are **unverified** — coverage was incomplete, so "
            "treat them as a floor rather than a complete picture."
        )


def _render_security_findings(result: ProcessingResult) -> None:
    message = describe_security_findings(result)
    if message:
        st.error(message, icon="🚨")


def _render_refusal(result: ProcessingResult) -> None:
    notice = describe_refusal(result)
    if notice is None:
        return

    container = st.error if notice.is_defect else st.warning
    container(f"**{notice.headline}**\n\n{notice.explanation}")

    if notice.next_steps:
        with st.container():
            st.markdown("**What to do next**")
            for step in notice.next_steps:
                st.markdown(f"- {step}")


def _render_denied_requests(result: ProcessingResult) -> None:
    message = describe_denied_requests(result)
    if message:
        st.info(message, icon="⚖️")


def _render_metrics(summary: dict) -> None:
    columns = st.columns(4)
    columns[0].metric("Items found", summary["entities"])
    columns[1].metric("Coverage", f"{summary['coverage_percent']}%")
    columns[2].metric("Profile", summary["profile"] or "—")
    columns[3].metric(
        "Verified", "Yes" if summary["verified_clean"] else "No"
    )

    if summary["actions"]:
        st.caption(
            "Actions applied: "
            + ", ".join(f"{k} ×{v}" for k, v in sorted(summary["actions"].items()))
        )

    if summary["suppressed_by_allowlist"]:
        st.caption(
            f"{summary['suppressed_by_allowlist']} detection(s) suppressed by "
            f"your session allowlist."
        )


def _render_findings_table(result: ProcessingResult) -> None:
    rows = build_entity_rows(result)
    if not rows:
        return

    with st.expander(f"Findings ({len(rows)})", expanded=len(rows) <= 25):
        st.caption(
            "Previews are masked. Credentials show a type label only — the "
            "value is never rendered."
        )
        st.dataframe(
            [
                {
                    "": row.severity_icon,
                    "Severity": row.severity_label,
                    "Type": row.entity_type,
                    "Preview": row.preview,
                    "Confidence": row.confidence,
                    "Detected by": row.detected_by,
                    "Action": row.action,
                }
                for row in rows
            ],
            use_container_width=True,
            hide_index=True,
        )


def _render_export(result: ProcessingResult, session: SessionContext) -> None:
    if not result.artifact_available or result.sanitized_handle is None:
        return

    try:
        record = session.content_store.get(result.sanitized_handle)
    except KeyError:
        st.caption("The cleaned copy is no longer available in this session.")
        return

    source_name = str(
        session.content_store.get(result.content_handle).metadata.get(
            "display_name", "content"
        )
    ) if session.content_store.exists(result.content_handle) else "content"
    stem = Path(source_name).stem or "content"
    suffix = Path(source_name).suffix or ".txt"

    # Keys are explicit and request-scoped. Several results can be on screen at
    # once in one session, and unkeyed buttons with identical labels collide on
    # Streamlit's generated widget id.
    columns = st.columns(2)
    columns[0].download_button(
        "⬇️ Cleaned copy",
        data=record.content,
        file_name=f"{stem}-cleaned{suffix}",
        mime="text/plain",
        use_container_width=True,
        key=f"dl-clean-{result.request_id}",
    )
    columns[1].download_button(
        "⬇️ Findings report (JSON)",
        data=json.dumps(result.to_audit_record(), indent=2, default=str),
        file_name=f"{stem}-findings.json",
        mime="application/json",
        use_container_width=True,
        key=f"dl-findings-{result.request_id}",
    )
    st.caption(
        "Nothing is written to disk — the cleaned copy is held in this session "
        "only, and downloading is the way out. It goes to your browser's "
        "download folder."
    )

    # Shown at the download rather than buried in docs: this is the moment
    # someone decides whether they can join this artifact against another one.
    if result.decisions.action_counts().get("TOKENIZE"):
        st.caption(
            "⚠️ This artifact contains tokenized values. The token-to-value "
            "mapping lives in this session only and is discarded when the session "
            "ends — tokens are consistent within this artifact, but the same input "
            "scrubbed later gets different tokens, and the original values cannot "
            "be recovered afterwards."
        )


def _render_provenance(result: ProcessingResult, summary: dict) -> None:
    with st.expander("Provenance"):
        versions = result.engine_versions
        st.caption(
            "Recorded so this result can be reproduced later — detection output "
            "depends on these versions."
        )
        st.code(
            "\n".join(
                [
                    f"request id     {summary['request_id']}",
                    f"profile        {versions.profile_name} "
                    f"v{versions.profile_version}",
                    f"presidio       {versions.presidio_analyzer}",
                    f"spacy          {versions.spacy} "
                    f"(model {versions.spacy_model})",
                    f"coverage       {result.coverage.bytes_processed:,} of "
                    f"{result.coverage.bytes_total:,} bytes",
                    f"detectors      "
                    f"{', '.join(result.coverage.healthy_detectors) or 'none'}",
                    f"processing     {result.processing_time_ms:.0f} ms",
                ]
            ),
            language="text",
        )
