"""Per-session tool registry.

Guardrails G11, G15. Requirement 6.

Two structural properties:

* **Per session, never a module singleton.** The reviewed design used
  module-level ``tool_registry`` and ``tool_map``, with the token vault held as
  instance state on a shared tool. Streamlit runs one process for every browser
  session, so tokens and handles would leak across users (SEC-06).
* **No detokenization capability.** Because the agent ingests attacker-writable
  content, an exposed reverse-lookup turns prompt injection into an exfiltration
  primitive (SEC-09). Reversal lives in ``scripts/detokenize.py``, reachable only
  out of band. ``build_registry`` asserts the absence rather than relying on
  nobody adding it.
"""

from __future__ import annotations

from langchain_core.tools import BaseTool

from session.context import SessionContext
from tools.agent_tools import (
    ExplainProfileTool,
    ExportTool,
    ListSourcesTool,
    ScanTool,
    ScrubTool,
    SetPreferenceTool,
)
from utils.budgets import TurnBudget

# Names that must never appear in the registry.
_FORBIDDEN_TOOL_TOKENS = (
    "detokenize",
    "detoken",
    "reverse",
    "resolve_token",
    "unmask",
    "reveal",
    "decrypt",
)


class ForbiddenCapability(RuntimeError):
    """Raised when the registry would expose a capability the agent must not have."""


def build_registry(
    session: SessionContext, budget: TurnBudget | None = None
) -> list[BaseTool]:
    """Construct the agent-visible tools for one session.

    The seven fine-grained components of the design still exist and are unit
    tested; they are simply no longer individually addressable by the model.
    Each additional tool hop is a chance for the model to drop a parameter, and
    collapsing the pipeline into one deterministic call removes those failure
    modes as well as the security ones.
    """
    tools: list[BaseTool] = [
        ListSourcesTool(session=session, budget=budget),
        ScanTool(session=session, budget=budget),
        ScrubTool(session=session, budget=budget),
        ExplainProfileTool(session=session, budget=budget),
        ExportTool(session=session, budget=budget),
        SetPreferenceTool(session=session, budget=budget),
    ]

    for tool in tools:
        lowered = tool.name.lower()
        for token in _FORBIDDEN_TOOL_TOKENS:
            if token in lowered:
                raise ForbiddenCapability(
                    f"tool '{tool.name}' exposes a capability the agent must "
                    f"not have. Detokenization is an out-of-band operator "
                    f"action; exposing it here would make prompt injection an "
                    f"exfiltration primitive."
                )

    return tools


def build_tool_map(tools: list[BaseTool]) -> dict[str, BaseTool]:
    return {tool.name: tool for tool in tools}


def get_tool_registry(
    session: SessionContext, budget: TurnBudget | None = None
) -> tuple[list[BaseTool], dict[str, BaseTool]]:
    tools = build_registry(session, budget)
    return tools, build_tool_map(tools)


__all__ = [
    "ForbiddenCapability",
    "build_registry",
    "build_tool_map",
    "get_tool_registry",
]
