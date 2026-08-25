"""PII Scrubbing Agent — Streamlit chat interface.

Requirements 3, 4, 29, 36, 39, 44.

Deployment note (guardrail G10): this app reads the local filesystem and cloud
logs using the host's credentials and has no authentication of its own. Startup
refuses a non-loopback bind unless PII_AGENT_ALLOW_REMOTE is explicitly set, and
that should only be done behind an authenticating reverse proxy.

Run with:
    streamlit run apps/pii_agent_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Streamlit puts the script's own directory on sys.path, not the working
# directory, so `apps/` would be importable and the repo root would not. Adding
# the root here keeps the entry point runnable from a clone with no editable
# install — pytest gets the same via `pythonpath` in pyproject.toml.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st  # noqa: E402
from langchain_core.messages import (  # noqa: E402
    AIMessage,
    HumanMessage,
    ToolMessage,
)

from pii_agent.agent.graph import AgentRuntime
from pii_agent.agent.memory import SessionMemory, prepare_for_model
from pii_agent.agent.state import initial_state
from pii_agent.core.file_source import load_upload
from pii_agent.models.enums import AgentStateEnum
from pii_agent.session.context import get_session_context, sweep_idle_sessions
from pii_agent.ui.health import collect_health, overall_status, scrubbing_blockers
from pii_agent.ui.presenters import (
    DESTINATION_NOTES,
    PROMPT_EXAMPLES,
    available_profile_names,
    build_profile_catalog,
    format_state,
)
from pii_agent.utils.config import DEMO_MAX_UPLOAD_BYTES, DEMO_MODE, load_settings
from pii_agent.utils.content_gate import sanitize_error
from pii_agent.utils.paths import PathRefused
from pii_agent.utils.startup import validate_startup

st.set_page_config(
    page_title="PII Scrubbing Agent",
    page_icon="🛡️",
    layout="wide",
)


# ---------------------------------------------------------------------------
# Startup gate
# ---------------------------------------------------------------------------
@st.cache_resource
def _startup():
    """Validate once per process. Cached because it sweeps temp dirs."""
    settings = load_settings()
    return settings, validate_startup(settings)


settings, report = _startup()

if not report.ok:
    st.title("🛡️ PII Scrubbing Agent")
    st.error("This app will not start with the current configuration.")
    st.code(report.summary(), language="text")
    st.caption(
        "These checks exist because the app reads local files and cloud logs "
        "with the host's credentials. Fix the items above and reload."
    )
    st.stop()


# ---------------------------------------------------------------------------
# Session wiring
# ---------------------------------------------------------------------------
def _session_id() -> str:
    """Stable per-browser-session id.

    Streamlit reruns the script on every interaction, so this must come from
    session_state rather than being regenerated.
    """
    if "session_id" not in st.session_state:
        import uuid

        st.session_state.session_id = f"ui-{uuid.uuid4().hex[:12]}"
    return st.session_state.session_id


session = get_session_context(_session_id(), settings)

# Swept on every rerun rather than once at startup. Streamlit never tells us a
# browser closed, so an abandoned session would otherwise hold its scanned
# content — the actual sensitive data — for the life of the process. The sweep is
# a dict scan over active sessions, so running it per interaction is free.
_swept = sweep_idle_sessions()

if "memory" not in st.session_state:
    st.session_state.memory = SessionMemory()
if "messages" not in st.session_state:
    st.session_state.messages = []
if "agent_state" not in st.session_state:
    st.session_state.agent_state = AgentStateEnum.IDLE.value
# Results are held on the SessionContext, not in session_state — the artifact
# must not pass through the model, and the tool that produces it has the session.
if "uploaded_names" not in st.session_state:
    st.session_state.uploaded_names = set()


@st.cache_resource
def _runtime_for(session_id: str) -> AgentRuntime:
    """One runtime per session. Cached on the id, not shared globally."""
    return AgentRuntime(get_session_context(session_id, load_settings()))


runtime = _runtime_for(_session_id())


# ---------------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------------
with st.sidebar:
    st.markdown("### 🛡️ PII Scrubbing Agent")
    st.caption(format_state(st.session_state.agent_state))

    st.divider()
    st.markdown("**Session preferences**")

    prefs = session.preferences
    st.text(f"Profile:     {prefs.get('profile', 'DEFAULT_PII')}")
    st.text(f"Destination: {prefs.get('destination') or 'not set'}")
    st.text(f"Threshold:   {prefs.get('confidence_threshold')}")
    st.caption("Ask in chat to change any of these.")

    st.divider()
    st.markdown("**Scanned this session**")
    memory: SessionMemory = st.session_state.memory
    if memory.scanned:
        for source in memory.scanned[-8:]:
            mark = "✅" if source.sanitized_handle else "•"
            st.text(f"{mark} {source.label} ({source.entity_count})")
    else:
        st.caption("Nothing yet.")

    st.divider()
    with st.expander("Component health"):
        probe = st.checkbox(
            "Include a live LLM check",
            value=False,
            help=(
                "Costs one token. Without it we can only confirm a key is "
                "present, not that the account can serve requests."
            ),
        )
        components = collect_health(settings, probe_llm=probe)
        st.markdown(f"**Overall:** {overall_status(components).icon}")
        for component in components:
            st.markdown(f"{component.status.icon} **{component.name}**")
            if component.detail:
                st.caption(component.detail)

        blockers = scrubbing_blockers(components)
        if blockers:
            st.warning(
                "Cleaned copies cannot be produced while these are unavailable: "
                + ", ".join(b.name for b in blockers)
            )

    st.divider()
    with st.expander("Audit trail"):
        st.caption(f"{session.audit_sink.count()} record(s) on disk")
        ok, bad = session.audit_sink.verify_chain()
        if ok:
            st.success("Hash chain intact")
        else:
            st.error(f"Chain broken at request {bad}")
        st.download_button(
            "Export audit trail",
            data=session.audit_sink.export() or "(empty)",
            file_name="audit-trail.jsonl",
            mime="application/x-ndjson",
            use_container_width=True,
        )

    st.divider()
    if st.button("Reset session", use_container_width=True):
        from pii_agent.session.context import drop_session_context

        drop_session_context(_session_id())
        # Session results are dropped by drop_session_context -> teardown().
        for key in (
            "messages",
            "memory",
            "session_id",
            "uploaded_names",
        ):
            st.session_state.pop(key, None)
        st.cache_resource.clear()
        st.rerun()


# ---------------------------------------------------------------------------
# Header
# ---------------------------------------------------------------------------
st.title("🛡️ PII Scrubbing Agent")
st.caption(
    "Ask me to scan a file or some text for sensitive data. I will tell you what "
    "is there before changing anything."
)

if DEMO_MODE:
    # Stated plainly and above the uploader, because the failure mode is a
    # visitor pasting a real production log into a public demo.
    st.warning(
        "**Public demo — do not upload real data.** This instance has no "
        "sign-in, so anything you submit is processed on a shared host by an "
        "app anyone can reach. Uploads are capped at "
        f"{DEMO_MAX_UPLOAD_BYTES // 1024} KB, filesystem scanning is disabled, "
        "and the NER model is the smaller one, so fewer names are detected than "
        "in a local install. Use the sample file from the repository.",
        icon="⚠️",
    )

if report.warnings:
    with st.expander(f"⚠️ {len(report.warnings)} startup warning(s)"):
        for warning in report.warnings:
            st.caption(warning)


# ---------------------------------------------------------------------------
# Capability and prompt help
# ---------------------------------------------------------------------------
# Users cannot ask for what they cannot see. Both panels read from the resolved
# profiles rather than a written-out list, so they cannot drift from behaviour.
_help_left, _help_right = st.columns(2)

with _help_left.expander("💬 How to ask"):
    st.caption(
        "Plain language works. Name a **destination** — a couple of types are "
        "handled differently depending on where the data goes, and I ask rather "
        "than guess."
    )
    for label, example in PROMPT_EXAMPLES:
        st.markdown(f"**{label}**")
        st.code(example, language=None)

    st.markdown("**Destinations**")
    for name, note in DESTINATION_NOTES:
        st.caption(f"`{name}` — {note}")

with _help_right.expander("🔍 What I can detect"):
    _profiles = available_profile_names()
    _selected = st.selectbox(
        "Profile",
        _profiles,
        index=_profiles.index("DEFAULT_PII") if "DEFAULT_PII" in _profiles else 0,
        help="Effective rules, including everything inherited from parents.",
    )
    _catalog = build_profile_catalog(_selected)
    st.caption(
        f"{len(_catalog)} entity types under **{_selected}**, including inherited "
        f"rules. The action shown is what policy resolves to — you can request "
        f"stricter, never weaker."
    )
    st.dataframe(
        [
            {
                "": row.severity_icon,
                "Type": row.entity_type,
                "Action": row.action,
                "What it is": row.description,
            }
            for row in _catalog
        ],
        use_container_width=True,
        hide_index=True,
    )
    st.caption(
        "Detection is a floor, not a guarantee — name recall in terse log syntax "
        "is imperfect."
    )


# ---------------------------------------------------------------------------
# Upload
# ---------------------------------------------------------------------------
upload = st.file_uploader(
    "Upload a file to scan",
    type=["txt", "log", "json", "jsonl", "csv", "xml"],
    help=(
        "Held in memory, not written to disk. Uploads bypass the scan-root "
        "allowlist because you supplied the bytes directly."
    ),
)

if upload is not None and upload.name not in st.session_state.uploaded_names:
    try:
        loaded = load_upload(upload.getvalue(), upload.name, session)
    except PathRefused as exc:
        st.error(sanitize_error(exc))
    else:
        st.session_state.uploaded_names.add(upload.name)
        st.session_state.memory.remember_source(
            loaded.handle, loaded.display_name, loaded.source_type.value
        )
        st.success(
            f"Loaded **{loaded.display_name}** "
            f"({loaded.bytes_total:,} bytes, {loaded.line_count:,} lines). "
            f"Ask me to scan it."
        )
        for warning in loaded.warnings:
            st.caption(f"⚠️ {warning}")


# ---------------------------------------------------------------------------
# Transcript
# ---------------------------------------------------------------------------
for message in st.session_state.messages:
    if isinstance(message, ToolMessage):
        continue  # tool traffic belongs in the details expander, not the chat
    role = "user" if isinstance(message, HumanMessage) else "assistant"
    with st.chat_message(role):
        st.markdown(message.content)


# ---------------------------------------------------------------------------
# Chat turn
# ---------------------------------------------------------------------------
def _render_results() -> None:
    """Render every result produced this session.

    Read from the SessionContext rather than st.session_state: the result is
    produced inside a tool, and the artifact must not travel through the model.
    Rendered on every rerun, because Streamlit discards widgets from previous
    runs — a download button drawn only on the turn that produced it would
    disappear the moment the user clicked anything else.
    """
    from pii_agent.ui.streamlit_render import render_result

    for result in session.results():
        render_result(result, session)


_render_results()


prompt = st.chat_input("e.g. scan sample_log.txt and give me a clean copy")

if prompt:
    st.session_state.messages.append(HumanMessage(content=prompt))
    with st.chat_message("user"):
        st.markdown(prompt)

    with st.chat_message("assistant"):
        status = st.empty()
        body = st.empty()

        state = initial_state(_session_id())
        state["messages"] = prepare_for_model(st.session_state.messages)
        state["session_preferences"] = dict(session.preferences)

        final_text = ""
        try:
            for update in runtime.stream(state):
                for node_output in update.values():
                    if not isinstance(node_output, dict):
                        continue

                    if node_output.get("agent_state"):
                        st.session_state.agent_state = node_output["agent_state"]
                        status.caption(format_state(node_output["agent_state"]))

                    for message in node_output.get("messages", []) or []:
                        if isinstance(message, AIMessage) and message.content:
                            final_text = str(message.content)
                            body.markdown(final_text)
        except Exception as exc:
            final_text = (
                "Something went wrong handling that request: "
                f"{sanitize_error(exc)}"
            )
            body.markdown(final_text)

        status.empty()
        st.session_state.agent_state = AgentStateEnum.IDLE.value

        if final_text:
            st.session_state.messages.append(AIMessage(content=final_text))

    st.rerun()
