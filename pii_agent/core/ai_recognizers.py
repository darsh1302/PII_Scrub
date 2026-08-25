"""Recognizers for the AI_SAAS profile — LLM application telemetry.

Task 9.2. Requirement 24. Guardrail G13.

The problem this addresses: an LLM application logs its own traffic. Prompts,
tool arguments, retrieved chunks and model responses end up in application logs
and traces, and that content is whatever the user typed — frequently their name,
their customer's account number, a pasted support email. The prompt log becomes
one of the most PII-dense artifacts the company holds, and nobody planned it.

What is detectable here, and what is not:

**Detectable.** Provider credentials have distinctive prefixes. Payload fields in
agent telemetry are label-anchored: ``prompt=``, ``"role": "user"``,
``"arguments":``, ``tool_result=``. Embedding vectors have an unmistakable shape.

**Not detectable, and not claimed.** Proprietary source code and free-form
confidential customer content have no format. Requirement 24.1 lists both. A
recognizer that pretended to find them would report coverage the profile cannot
deliver, and coverage is what the fail-closed gates trust — so they are
deliberately absent rather than approximated. The profile documents this.

Why embeddings are included: a vector is not opaque. Embedding-inversion
research recovers substantial portions of the source text from the vector alone,
so a logged embedding is closer to logging the input than to logging a hash.

Patterns are linear-time: bounded repetition, no nested unbounded quantifiers.
Value bounds are generous because prompts are long, but they are bounds.
"""

from __future__ import annotations

from presidio_analyzer import Pattern, PatternRecognizer

# Prompt and completion payloads are long. Bounded, but generously.
_PAYLOAD = r"[^\"'\n]{16,2000}"


def _field(keys: str, value: str = _PAYLOAD) -> str:
    """Label-anchored field match. Newlines excluded so a match cannot run on."""
    return (
        rf"(?i:\b(?:{keys})\b)"
        rf"[ \t]{{0,4}}[:=][ \t]{{0,4}}"
        rf'["\']?({value})["\']?'
    )


def _json_field(keys: str) -> str:
    """Label-anchored field whose value is a JSON object or array.

    Needed separately because ``_PAYLOAD`` excludes quotes to stop a match
    running past its own delimiter, and a JSON value is full of them. Agent
    telemetry logs tool arguments and results as JSON far more often than as bare
    strings, so without this the most PII-dense fields were never matched.

    Not balanced-brace matching — a regex cannot do that safely. Bounded to a
    single line, which is how these are logged.
    """
    return (
        rf"(?i:\b(?:{keys})\b)"
        rf"[ \t]{{0,4}}[:=][ \t]{{0,4}}"
        rf"((?:\{{|\[)[^\n]{{8,2000}}(?:\}}|\]))"
    )


def _json_role(role: str) -> str:
    """Chat-message content for a given role in a JSON transcript.

    Matches ``{"role": "user", "content": "..."}`` with either key order-tolerant
    spacing. Bounded throughout.
    """
    return (
        rf'"role"[ \t]{{0,4}}:[ \t]{{0,4}}"{role}"[ \t]{{0,4}},[ \t]{{0,4}}'
        rf'"content"[ \t]{{0,4}}:[ \t]{{0,4}}"({_PAYLOAD})"'
    )


# --------------------------------------------------------------------------
# Model provider credentials
# --------------------------------------------------------------------------
# OpenAI (sk-), Google (AIza) and generic api_key assignments are already covered
# by BASE_SECURITY. These are the providers it does not name.
MODEL_PROVIDER_TOKEN_PATTERNS = [
    Pattern(
        name="anthropic_key",
        regex=r"\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_\-]{20,200}\b",
        score=0.9,
    ),
    Pattern(
        name="huggingface_token",
        regex=r"\bhf_[A-Za-z0-9]{30,40}\b",
        score=0.9,
    ),
    Pattern(
        name="replicate_token",
        regex=r"\br8_[A-Za-z0-9]{32,45}\b",
        score=0.9,
    ),
    Pattern(
        name="groq_key",
        regex=r"\bgsk_[A-Za-z0-9]{40,60}\b",
        score=0.9,
    ),
    Pattern(
        name="provider_key_assignment",
        regex=_field(
            r"anthropic[_\-]?api[_\-]?key|openai[_\-]?api[_\-]?key|"
            r"cohere[_\-]?api[_\-]?key|mistral[_\-]?api[_\-]?key|"
            r"together[_\-]?api[_\-]?key|azure[_\-]?openai[_\-]?key|"
            r"hf[_\-]?token|huggingface[_\-]?token|"
            r"model[_\-]?api[_\-]?key|llm[_\-]?api[_\-]?key",
            r"[A-Za-z0-9_\-\.]{16,200}",
        ),
        score=0.85,
    ),
]

# --------------------------------------------------------------------------
# Conversation payloads
# --------------------------------------------------------------------------
USER_PROMPT_PATTERNS = [
    Pattern(
        name="prompt_field",
        regex=_field(
            r"prompt|user[_\-]?prompt|user[_\-]?input|user[_\-]?message|"
            r"user[_\-]?query|input[_\-]?text|question"
        ),
        score=0.6,
    ),
    Pattern(name="chat_user_turn", regex=_json_role("user"), score=0.7),
]

SYSTEM_PROMPT_PATTERNS = [
    Pattern(
        name="system_prompt_field",
        regex=_field(
            r"system[_\-]?prompt|system[_\-]?message|system[_\-]?instruction|"
            r"instructions"
        ),
        score=0.6,
    ),
    Pattern(name="chat_system_turn", regex=_json_role("system"), score=0.65),
]

MODEL_COMPLETION_PATTERNS = [
    Pattern(
        name="completion_field",
        regex=_field(
            r"completion|model[_\-]?output|model[_\-]?response|"
            r"assistant[_\-]?message|generated[_\-]?text"
        ),
        score=0.55,
    ),
    Pattern(name="chat_assistant_turn", regex=_json_role("assistant"), score=0.6),
]

_MEMORY_KEYS = (
    r"agent[_\-]?memory|conversation[_\-]?history|chat[_\-]?history|"
    r"message[_\-]?history|scratchpad|agent[_\-]?scratchpad|"
    r"working[_\-]?memory"
)

AGENT_MEMORY_PATTERNS = [
    Pattern(name="agent_memory_field", regex=_field(_MEMORY_KEYS), score=0.6),
    # History is usually a JSON array of message objects.
    Pattern(name="agent_memory_json", regex=_json_field(_MEMORY_KEYS), score=0.65),
]

# --------------------------------------------------------------------------
# Tool traffic
# --------------------------------------------------------------------------
_TOOL_ARG_KEYS = (
    r"tool[_\-]?args|tool[_\-]?arguments|function[_\-]?args|"
    r"function[_\-]?arguments|arguments|tool[_\-]?input"
)

TOOL_ARGUMENTS_PATTERNS = [
    Pattern(name="tool_arguments_field", regex=_field(_TOOL_ARG_KEYS), score=0.6),
    Pattern(
        name="tool_arguments_json",
        regex=_json_field(_TOOL_ARG_KEYS),
        score=0.65,
    ),
]

_TOOL_RESULT_KEYS = (
    r"tool[_\-]?result|tool[_\-]?response|tool[_\-]?output|"
    r"function[_\-]?result|observation"
)

TOOL_RESPONSE_PATTERNS = [
    Pattern(
        name="tool_response_field", regex=_field(_TOOL_RESULT_KEYS), score=0.6
    ),
    Pattern(
        name="tool_response_json",
        regex=_json_field(_TOOL_RESULT_KEYS),
        score=0.65,
    ),
    Pattern(name="chat_tool_turn", regex=_json_role("tool"), score=0.65),
]

# --------------------------------------------------------------------------
# Retrieval payloads
# --------------------------------------------------------------------------
_RETRIEVAL_KEYS = (
    r"retrieved[_\-]?(?:context|document|chunk|text)|rag[_\-]?context|"
    r"context[_\-]?chunk|document[_\-]?text|page[_\-]?content|"
    r"source[_\-]?document"
)

RETRIEVED_DOCUMENT_PATTERNS = [
    Pattern(
        name="retrieved_context_field", regex=_field(_RETRIEVAL_KEYS), score=0.6
    ),
    Pattern(
        name="retrieved_context_json",
        regex=_json_field(_RETRIEVAL_KEYS),
        score=0.65,
    ),
]

# A logged vector is much closer to logging the input than to logging a hash:
# embedding-inversion attacks recover substantial portions of the source text.
# Shape is unmistakable — a labelled array of at least eight signed decimals.
VECTOR_EMBEDDING_PATTERNS = [
    Pattern(
        name="embedding_array",
        regex=(
            r"(?i:\b(?:embedding|embeddings|vector|dense[_\-]?vector)\b)"
            r"[ \t]{0,4}[:=][ \t]{0,4}\[[ \t]{0,4}"
            r"(-?\d\.\d{3,20}(?:[eE][+\-]?\d{1,3})?"
            r"(?:[ \t]{0,2},[ \t]{0,2}-?\d\.\d{3,20}(?:[eE][+\-]?\d{1,3})?){7,4095})"
        ),
        score=0.85,
    ),
]


_DEFINITIONS: list[tuple[str, list[Pattern], list[str]]] = [
    (
        "MODEL_PROVIDER_TOKEN",
        MODEL_PROVIDER_TOKEN_PATTERNS,
        ["api", "key", "token", "anthropic", "openai", "model", "llm"],
    ),
    (
        "USER_PROMPT",
        USER_PROMPT_PATTERNS,
        ["prompt", "user", "input", "message", "chat"],
    ),
    (
        "SYSTEM_PROMPT",
        SYSTEM_PROMPT_PATTERNS,
        ["system", "prompt", "instruction"],
    ),
    (
        "MODEL_COMPLETION",
        MODEL_COMPLETION_PATTERNS,
        ["completion", "response", "output", "assistant", "generated"],
    ),
    (
        "AGENT_MEMORY",
        AGENT_MEMORY_PATTERNS,
        ["memory", "history", "conversation", "scratchpad"],
    ),
    (
        "TOOL_ARGUMENTS",
        TOOL_ARGUMENTS_PATTERNS,
        ["tool", "function", "arguments", "args"],
    ),
    (
        "TOOL_RESPONSE",
        TOOL_RESPONSE_PATTERNS,
        ["tool", "result", "response", "observation"],
    ),
    (
        "RETRIEVED_DOCUMENT",
        RETRIEVED_DOCUMENT_PATTERNS,
        ["retrieved", "context", "document", "chunk", "rag"],
    ),
    (
        "VECTOR_EMBEDDING",
        VECTOR_EMBEDDING_PATTERNS,
        ["embedding", "vector", "index"],
    ),
]


def build_ai_recognizers() -> list[PatternRecognizer]:
    """Construct the AI_SAAS recognizers.

    Registered unconditionally with the analyzer. Only the AI_SAAS profile enables
    these types, so a DEFAULT_PII scan is unaffected — which matters, because
    ``prompt=`` and ``arguments=`` appear in ordinary application logs and would
    otherwise be flagged everywhere.
    """
    return [
        PatternRecognizer(
            supported_entity=entity,
            name=f"{entity}_recognizer",
            patterns=patterns,
            context=context,
        )
        for entity, patterns, context in _DEFINITIONS
    ]


def ai_entity_types() -> tuple[str, ...]:
    return tuple(entity for entity, _, _ in _DEFINITIONS)
