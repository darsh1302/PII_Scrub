"""Session memory: transcript hygiene and reference resolution.

Guardrail G23. Requirements 5, 30. Addresses review finding OPS-04.

The reviewed design let ``messages`` grow without bound and resent it in full on
every turn. Two consequences: anything the user pasted — including raw PII — was
re-transmitted to OpenAI on every subsequent request, and token cost grew
quadratically over a session.

Redaction happens *after* the turn that produced it. The user needs to see what
they pasted in that turn; they do not need it resent on the next fifteen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from langchain_core.messages import (
    AIMessage,
    BaseMessage,
    HumanMessage,
    SystemMessage,
    ToolMessage,
)

from pii_agent.utils.content_gate import redact_secret_shapes
from pii_agent.utils.normalization import normalize

# Directly-identifiable shapes redacted from stored history. Deliberately narrow:
# this is transcript hygiene, not detection. Real detection runs in the core over
# content the model never sees.
_TRANSCRIPT_SHAPES = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[US_SSN]"),
    (re.compile(r"\b(?:\d[ -]?){13,19}\b"), "[CARD_NUMBER]"),
    (
        re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "[EMAIL_ADDRESS]",
    ),
    (re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "[IP_ADDRESS]"),
]

DEFAULT_WINDOW_TURNS = 12


@dataclass
class ScannedSource:
    """A source seen this session, for resolving "that file" style references."""

    handle: str
    label: str
    source_type: str
    entity_count: int = 0
    sanitized_handle: str | None = None


@dataclass
class SessionMemory:
    """Conversation history plus the context needed to resolve references."""

    scanned: list[ScannedSource] = field(default_factory=list)
    window_turns: int = DEFAULT_WINDOW_TURNS

    # -- source tracking ------------------------------------------------
    def remember_source(
        self,
        handle: str,
        label: str,
        source_type: str,
        entity_count: int = 0,
    ) -> ScannedSource:
        for existing in self.scanned:
            if existing.handle == handle:
                existing.entity_count = entity_count
                return existing
        source = ScannedSource(
            handle=handle,
            label=label,
            source_type=source_type,
            entity_count=entity_count,
        )
        self.scanned.append(source)
        return source

    def remember_sanitized(self, handle: str, sanitized_handle: str) -> None:
        for source in self.scanned:
            if source.handle == handle:
                source.sanitized_handle = sanitized_handle
                return

    def resolve_reference(self, phrase: str) -> ScannedSource | None:
        """Resolve "that file", "the log", "it" to a source seen this session.

        Most recent match wins: in conversation, an unqualified reference almost
        always means the thing just discussed.
        """
        if not self.scanned:
            return None

        lowered = phrase.lower()

        # Explicit name match first.
        for source in reversed(self.scanned):
            if source.label.lower() in lowered:
                return source

        type_hints = {
            "cloudwatch": "AWS_CLOUDWATCH",
            "cloud": "AWS_CLOUDWATCH",
            "event log": "WINDOWS_EVENT_LOG",
            "windows": "WINDOWS_EVENT_LOG",
            "file": "FILE",
            "log": "FILE",
            "text": "TEXT",
            "paste": "TEXT",
        }
        for hint, source_type in type_hints.items():
            if hint in lowered:
                for source in reversed(self.scanned):
                    if source.source_type == source_type:
                        return source

        return self.scanned[-1]

    @property
    def last_source(self) -> ScannedSource | None:
        return self.scanned[-1] if self.scanned else None

    def summary(self) -> dict[str, Any]:
        return {
            "sources_scanned": len(self.scanned),
            "sources": [
                {
                    "label": s.label,
                    "type": s.source_type,
                    "entities": s.entity_count,
                    "cleaned": s.sanitized_handle is not None,
                }
                for s in self.scanned[-10:]
            ],
        }


# ----------------------------------------------------------------------
# Transcript hygiene
# ----------------------------------------------------------------------
def redact_for_storage(text: str) -> tuple[str, int]:
    """Redact identifiable shapes from text bound for stored history.

    Normalised first so a zero-width space inside an SSN does not defeat the
    pattern — the same evasion the detection pipeline handles.
    """
    normalised = normalize(text).text
    out = redact_secret_shapes(normalised)

    count = 0
    for pattern, replacement in _TRANSCRIPT_SHAPES:
        out, replaced = pattern.subn(replacement, out)
        count += replaced

    if "[REDACTED_SECRET]" in out:
        count += out.count("[REDACTED_SECRET]")

    return out, count


def redact_message(message: BaseMessage) -> BaseMessage:
    """Return a redacted copy of a message for storage.

    System messages are left alone — they are ours, contain no user data, and
    rewriting them would corrupt the envelope delimiter the prompt relies on.
    """
    if isinstance(message, SystemMessage):
        return message

    content = getattr(message, "content", "")
    if not isinstance(content, str) or not content:
        return message

    redacted, count = redact_for_storage(content)
    if count == 0:
        return message

    if isinstance(message, HumanMessage):
        return HumanMessage(content=redacted)
    if isinstance(message, AIMessage):
        # Preserve tool_calls: dropping them would break the loop's routing.
        return AIMessage(
            content=redacted,
            tool_calls=list(getattr(message, "tool_calls", []) or []),
        )
    if isinstance(message, ToolMessage):
        return ToolMessage(
            content=redacted,
            tool_call_id=getattr(message, "tool_call_id", ""),
        )
    return message


def redact_history(messages: list[BaseMessage]) -> list[BaseMessage]:
    """Redact all but the most recent turn.

    The current turn stays intact so the user sees what they typed; earlier turns
    are redacted so they are not resent indefinitely.
    """
    if len(messages) <= 1:
        return list(messages)

    boundary = _last_human_index(messages)
    if boundary is None:
        return [redact_message(m) for m in messages]

    return [
        *(redact_message(m) for m in messages[:boundary]),
        *messages[boundary:],
    ]


def _last_human_index(messages: list[BaseMessage]) -> int | None:
    for index in range(len(messages) - 1, -1, -1):
        if isinstance(messages[index], HumanMessage):
            return index
    return None


def apply_window(
    messages: list[BaseMessage], window_turns: int = DEFAULT_WINDOW_TURNS
) -> list[BaseMessage]:
    """Trim history to the last ``window_turns`` user turns.

    Keeps the system message, and never splits a tool call from its result — an
    orphaned tool_call in the history makes the next model call fail.
    """
    system = [m for m in messages[:1] if isinstance(m, SystemMessage)]
    body = messages[len(system) :]

    human_indices = [
        i for i, m in enumerate(body) if isinstance(m, HumanMessage)
    ]
    if len(human_indices) <= window_turns:
        return list(messages)

    start = human_indices[-window_turns]
    return [*system, *body[start:]]


def prepare_for_model(
    messages: list[BaseMessage], window_turns: int = DEFAULT_WINDOW_TURNS
) -> list[BaseMessage]:
    """Full outbound preparation: redact history, then window it."""
    return apply_window(redact_history(list(messages)), window_turns)
