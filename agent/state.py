"""LangGraph state definition.

Requirement 18.4. Correctness Property 7.

Two things the reviewed design got wrong and are corrected here:

* **Nodes must not mutate state in place.** LangGraph applies returned dicts
  through channel reducers; in-place mutation bypasses them and produces
  non-deterministic state under concurrency. The convention is enforced by test.
* **Iteration budget is per turn, not per session.** The original counted every
  AIMessage with tool_calls across the whole history, so after ten tool calls in
  a long conversation the agent would refuse to use tools at all.
"""

from __future__ import annotations

from typing import Annotated, Any, Sequence, TypedDict

from langchain_core.messages import BaseMessage
from langgraph.graph.message import add_messages

from models.enums import AgentStateEnum
from utils.config import (
    DEFAULT_CONFIDENCE_THRESHOLD,
    MAX_REASONING_ITERATIONS,
)


class AgentState(TypedDict):
    """State flowing through the StateGraph."""

    # Accumulates via the add_messages reducer.
    messages: Annotated[Sequence[BaseMessage], add_messages]

    # Which session's stores and tools this turn is bound to.
    session_id: str

    # Surfaced live in the UI.
    agent_state: str

    # Scratch-pad for the current turn and cross-turn references.
    working_memory: dict[str, Any]

    # Preferences accumulated from conversation.
    session_preferences: dict[str, Any]


def initial_working_memory() -> dict[str, Any]:
    return {
        "turn_iterations": 0,
        "turn_started_at": 0.0,
        "current_plan": None,
        "scanned_sources": [],
        "last_scan_handle": None,
        "last_sanitized_handle": None,
        "pending_confirmation": None,
        "tokens_used": 0,
    }


def initial_preferences() -> dict[str, Any]:
    return {
        "profile": "DEFAULT_PII",
        "confidence_threshold": DEFAULT_CONFIDENCE_THRESHOLD,
        "requested_action": None,
        "destination": None,
        "locale": "en",
        "max_iterations": MAX_REASONING_ITERATIONS,
    }


def initial_state(session_id: str) -> AgentState:
    return {
        "messages": [],
        "session_id": session_id,
        "agent_state": AgentStateEnum.IDLE.value,
        "working_memory": initial_working_memory(),
        "session_preferences": initial_preferences(),
    }


def begin_turn(working_memory: dict[str, Any]) -> dict[str, Any]:
    """Reset per-turn counters. Returns a new dict, never mutates.

    Called at the start of each user turn so the iteration and time budgets
    apply per request rather than accumulating across a session.
    """
    import time

    fresh = dict(working_memory)
    fresh["turn_iterations"] = 0
    fresh["turn_started_at"] = time.monotonic()
    return fresh
