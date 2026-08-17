"""AI_SAAS profile — LLM application telemetry.

Task 9.2. Requirement 24. Guardrail G13.

The properties that matter:

* Payload fields like ``prompt=`` and ``arguments=`` appear in ordinary
  application logs, so enabling them under DEFAULT_PII would flag everything.
  They must be reported only when AI_SAAS is active.
* Embeddings must be detected. A logged vector is recoverable to a substantial
  degree by inversion, so treating it as opaque would be wrong.
* The profile must not claim to find proprietary source code, because it cannot.
"""

from __future__ import annotations

import pytest

from core.file_source import load_upload
from core.pipeline import ScanOptions, scan, scrub
from core.profile_resolver import get_resolver
from models.enums import Destination, ScrubAction
from session.context import get_session_context
from utils.config import Settings


@pytest.fixture
def session(tmp_path):
    settings = Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"salt-for-ai-tests",
        scan_roots=(),
        audit_dir=tmp_path / "audit",
    )
    return get_session_context(f"ai-{tmp_path.name}", settings)


def _scan(session, content: bytes, profile: str = "AI_SAAS", name: str = "t.log"):
    loaded = load_upload(content, name, session)
    return scan(
        loaded.handle,
        session,
        ScanOptions(profile_names=(profile,), destination=Destination.INTERNAL_SIEM),
    )


def _types(result) -> set[str]:
    return {e.type for e in result.entities}


def _action_for(result, entity_type: str) -> ScrubAction | None:
    for decision in result.decisions:
        if decision.entity.type == entity_type:
            return decision.applied_action
    return None


# ---------------------------------------------------------------------------
# Availability
# ---------------------------------------------------------------------------
def test_profile_is_available():
    assert "AI_SAAS" in get_resolver().available_profiles()


def test_profile_inherits_base_security():
    """Requirement 24.2: BASE_SECURITY applies regardless of configuration."""
    resolved = get_resolver().resolve("AI_SAAS")
    entities = resolved.entities
    items = entities.values() if isinstance(entities, dict) else entities
    rules = {r.type: r.action for r in items if r.enabled}

    assert rules["API_KEY"].priority >= ScrubAction.REDACT.priority
    assert rules["CONNECTION_STRING"].priority >= ScrubAction.REDACT.priority


# ---------------------------------------------------------------------------
# Provider credentials
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "line",
    [
        b"token=hf_QxWzRtYuIoPaSdFgHjKlZxCvBnMqWe\n",
        b"replicate=r8_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8\n",
        b"groq=gsk_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2\n",
    ],
)
def test_provider_tokens_are_detected(session, line):
    result = _scan(session, line)
    assert "MODEL_PROVIDER_TOKEN" in _types(result)
    assert _action_for(result, "MODEL_PROVIDER_TOKEN") is ScrubAction.REDACT


def test_anthropic_key_is_protected_even_though_base_security_claims_it(session):
    """An ``sk-ant-`` key overlaps BASE_SECURITY's ``sk-`` pattern.

    Both recognizers fire, reconciliation resolves the overlap deterministically,
    and API_KEY wins the final name tie-break. That is a labelling difference, not
    a protection gap — both are HIGH severity and both resolve to REDACT — so the
    property asserted here is that the value cannot survive, whichever type wins.
    """
    line = b"anthropic_key=sk-ant-api03-Kx8mQ2vR7tZ4nB1jH6pL0wY9fA3sD5gE8cV2bN4m\n"
    result = scrub(
        load_upload(line, "k.log", session).handle,
        session,
        ScanOptions(
            profile_names=("AI_SAAS",), destination=Destination.INTERNAL_SIEM
        ),
    )

    found = _types(result)
    assert found & {"MODEL_PROVIDER_TOKEN", "API_KEY"}

    cleaned = session.content_store.get(result.sanitized_handle).content
    assert "sk-ant-api03-Kx8mQ2vR7tZ4nB1jH6pL0wY9fA3sD5gE8cV2bN4m" not in cleaned


# ---------------------------------------------------------------------------
# Conversation payloads
# ---------------------------------------------------------------------------
def test_user_prompt_field_is_detected_and_redacted(session):
    content = b'prompt="my ssn is 482-71-9053 please look up my account"\n'
    result = _scan(session, content)
    assert "USER_PROMPT" in _types(result)
    assert _action_for(result, "USER_PROMPT") is ScrubAction.REDACT


def test_chat_transcript_user_turn_is_detected(session):
    content = (
        b'{"role": "user", "content": "here is my card 4532015112830366 ok"}\n'
    )
    result = _scan(session, content)
    assert "USER_PROMPT" in _types(result)


def test_system_prompt_is_replaced_not_redacted(session):
    """Not every system prompt is a secret, so the default is milder."""
    content = b'system_prompt="You are a helpful billing assistant for Acme"\n'
    result = _scan(session, content)
    assert "SYSTEM_PROMPT" in _types(result)
    assert _action_for(result, "SYSTEM_PROMPT") is ScrubAction.REPLACE


def test_agent_memory_is_detected(session):
    content = b'conversation_history="user asked about invoice 88213 for Dana"\n'
    result = _scan(session, content)
    assert "AGENT_MEMORY" in _types(result)


# ---------------------------------------------------------------------------
# Tool traffic
# ---------------------------------------------------------------------------
def test_tool_arguments_are_detected(session):
    content = b'tool_args={"account_id": "AC-99213", "email": "d@example.com"}\n'
    result = _scan(session, content)
    assert "TOOL_ARGUMENTS" in _types(result)


def test_tool_response_is_detected(session):
    content = b'tool_result="account AC-99213 balance 4210.55 holder Dana Reyes"\n'
    result = _scan(session, content)
    assert "TOOL_RESPONSE" in _types(result)


# ---------------------------------------------------------------------------
# Retrieval
# ---------------------------------------------------------------------------
def test_retrieved_document_is_detected(session):
    content = b'retrieved_chunk="Policy 4471 covers claimant Ravi Menon in full"\n'
    result = _scan(session, content)
    assert "RETRIEVED_DOCUMENT" in _types(result)


def test_embedding_vector_is_detected(session):
    """A vector is not opaque — inversion recovers much of the source text."""
    vector = ", ".join(f"{i / 1000:.6f}" for i in range(1, 25))
    content = f"embedding=[{vector}]\n".encode()
    result = _scan(session, content)
    assert "VECTOR_EMBEDDING" in _types(result)
    assert _action_for(result, "VECTOR_EMBEDDING") is ScrubAction.REDACT


def test_a_short_number_list_is_not_an_embedding(session):
    """Three coordinates are not an embedding."""
    content = b"vector=[1.0, 2.0, 3.0]\n"
    result = _scan(session, content)
    assert "VECTOR_EMBEDDING" not in _types(result)


# ---------------------------------------------------------------------------
# Isolation from DEFAULT_PII — the false-positive guard
# ---------------------------------------------------------------------------
def test_payload_fields_are_not_reported_under_default_pii(session):
    """``prompt=`` and ``arguments=`` occur in ordinary logs constantly."""
    content = (
        b'prompt="hello" tool_args="{}" retrieved_chunk="x" '
        b'completion="hi" ssn=482-71-9053\n'
    )
    result = _scan(session, content, profile="DEFAULT_PII")

    found = _types(result)
    assert "US_SSN" in found
    for ai_only in (
        "USER_PROMPT",
        "TOOL_ARGUMENTS",
        "RETRIEVED_DOCUMENT",
        "MODEL_COMPLETION",
    ):
        assert ai_only not in found


# ---------------------------------------------------------------------------
# End to end
# ---------------------------------------------------------------------------
def test_agent_trace_scrubs_to_a_verified_artifact(session):
    trace = (
        b'2026-08-16T10:00:00Z INFO request_id=r-8821 '
        b'prompt="look up account for dana.reyes@example.com ssn 482-71-9053"\n'
        b'2026-08-16T10:00:01Z INFO tool_args={"email": "dana.reyes@example.com"}\n'
        b'2026-08-16T10:00:02Z INFO tool_result="balance 4210.55 card 4532015112830366"\n'
        b'2026-08-16T10:00:03Z INFO anthropic_key=sk-ant-api03-Kx8mQ2vR7tZ4nB1jH6pL0wY9fA3sD5gE8cV2\n'
    )
    result = scrub(
        load_upload(trace, "trace.log", session).handle,
        session,
        ScanOptions(
            profile_names=("AI_SAAS",), destination=Destination.INTERNAL_SIEM
        ),
    )

    assert result.artifact_available is True
    assert result.verified_clean is True

    cleaned = session.content_store.get(result.sanitized_handle).content
    for secret in (
        "482-71-9053",
        "dana.reyes@example.com",
        "4532015112830366",
        "sk-ant-api03-Kx8mQ2vR7tZ4nB1jH6pL0wY9fA3sD5gE8cV2",
    ):
        assert secret not in cleaned

    # Timestamps survive: a trace you cannot order is not a trace.
    assert "2026-08-16T10:00:00Z" in cleaned
