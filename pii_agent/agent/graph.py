"""LangGraph agent construction.

Requirements 1, 4, 18. Guardrails G1, G22, G23.

The ReAct loop, with the corrections from the review applied:

* Nodes return state updates and never mutate in place (Requirement 18.4).
* The iteration budget is scoped to the turn, not the session — the reviewed
  design counted tool calls across the whole message history, so after ten calls
  in a long conversation the agent would stop using tools entirely.
* Every tool result passes the content gate before entering the context (G1).
* Budgets are checked at real points in the loop, not merely documented (G22).
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import AIMessage, BaseMessage, ToolMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph

from pii_agent.agent.prompts import build_system_prompt
from pii_agent.agent.state import AgentState, begin_turn
from pii_agent.models.enums import AgentStateEnum
from pii_agent.session.context import SessionContext
from pii_agent.tools import get_tool_registry
from pii_agent.utils.budgets import BudgetExceeded, Cancelled, TurnBudget, estimate_tokens
from pii_agent.utils.config import (
    LLM_MAX_TOKENS,
    LLM_MODEL,
    LLM_TEMPERATURE,
    MAX_REASONING_ITERATIONS,
)
from pii_agent.utils.content_gate import gate_tool_output, sanitize_error
from pii_agent.utils.prompt_safety import PromptSafety


def build_llm(model: str = LLM_MODEL) -> ChatOpenAI:
    return ChatOpenAI(
        model=model,
        temperature=LLM_TEMPERATURE,
        max_tokens=LLM_MAX_TOKENS,
        streaming=True,
    )


class AgentRuntime:
    """A compiled agent bound to one session.

    Built per session rather than shared, so the tool registry, prompt-safety
    delimiter, and budgets all belong to that session (G15).
    """

    def __init__(
        self,
        session: SessionContext,
        *,
        llm: Any | None = None,
        max_iterations: int = MAX_REASONING_ITERATIONS,
    ) -> None:
        self.session = session
        self.safety = PromptSafety(session.session_id)
        self.budget = TurnBudget(max_iterations=max_iterations)

        self.tools, self.tool_map = get_tool_registry(session, self.budget)
        self._llm = llm if llm is not None else build_llm()
        self._bound = self._llm.bind_tools(self.tools)
        self.system_prompt = build_system_prompt(
            self.safety.system_prompt_clause()
        )
        self.graph = self._build_graph()

    # ------------------------------------------------------------------
    # Nodes
    # ------------------------------------------------------------------
    def _reasoning_node(self, state: AgentState) -> dict[str, Any]:
        """Invoke the model. Returns updates; never mutates ``state``."""
        from langchain_core.messages import SystemMessage

        messages = list(state["messages"])
        if not messages or not isinstance(messages[0], SystemMessage):
            messages = [SystemMessage(content=self.system_prompt), *messages]

        # Pre-flight token check so the budget can refuse rather than report an
        # overspend after the fact (Requirement 34.4).
        estimated = estimate_tokens(
            "".join(str(getattr(m, "content", "")) for m in messages)
        )
        try:
            self.budget.check_tokens(estimated)
            self.budget.check()
        except (BudgetExceeded, Cancelled) as exc:
            return {
                "messages": [AIMessage(content=str(exc))],
                "agent_state": AgentStateEnum.REPORTING.value,
            }

        try:
            response = self._bound.invoke(messages)
        except Exception as exc:
            return {
                "messages": [
                    AIMessage(
                        content=(
                            "I could not complete that request: "
                            f"{sanitize_error(exc)}"
                        )
                    )
                ],
                "agent_state": AgentStateEnum.REPORTING.value,
            }

        usage = getattr(response, "usage_metadata", None) or {}
        if usage.get("total_tokens"):
            self.budget.record_tokens(int(usage["total_tokens"]))

        has_calls = bool(getattr(response, "tool_calls", None))
        next_state = (
            AgentStateEnum.PLANNING.value
            if has_calls and self.budget.iterations == 0
            else AgentStateEnum.THINKING.value
        )

        return {"messages": [response], "agent_state": next_state}

    def _tool_node(self, state: AgentState) -> dict[str, Any]:
        """Execute the requested tools and gate their results."""
        last = state["messages"][-1]
        calls = list(getattr(last, "tool_calls", []) or [])

        outputs: list[BaseMessage] = []
        for call in calls:
            self.budget.record_iteration()
            name = call.get("name", "")
            tool = self.tool_map.get(name)

            if tool is None:
                outputs.append(
                    ToolMessage(
                        content=gate_tool_output(
                            {
                                "status": "ERROR",
                                "detail": (
                                    f"'{name}' is not an available tool. "
                                    f"Available: "
                                    f"{', '.join(sorted(self.tool_map))}"
                                ),
                            }
                        ),
                        tool_call_id=call.get("id", ""),
                    )
                )
                continue

            try:
                result = tool.invoke(call.get("args", {}) or {})
            except Exception as exc:
                # Tool results already pass the gate internally; this covers
                # schema-validation and unexpected failures.
                result = gate_tool_output(
                    {"status": "ERROR", "detail": sanitize_error(exc)}
                )

            outputs.append(
                ToolMessage(content=str(result), tool_call_id=call.get("id", ""))
            )

        working = dict(state["working_memory"])
        working["turn_iterations"] = self.budget.iterations

        return {
            "messages": outputs,
            "agent_state": AgentStateEnum.ANALYZING.value,
            "working_memory": working,
        }

    @staticmethod
    def _response_node(state: AgentState) -> dict[str, Any]:
        return {"agent_state": AgentStateEnum.IDLE.value}

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------
    def _should_continue(self, state: AgentState) -> str:
        last = state["messages"][-1]

        if self.budget.cancelled:
            return "respond"

        # Per-turn budget. Counting across the full history — as the reviewed
        # design did — would exhaust the allowance mid-conversation.
        if self.budget.iterations >= self.budget.max_iterations:
            return "respond"

        if self.budget.elapsed > self.budget.max_seconds:
            return "respond"

        if getattr(last, "tool_calls", None):
            return "tools"

        return "respond"

    def _build_graph(self):
        graph = StateGraph(AgentState)
        graph.add_node("reasoning", self._reasoning_node)
        graph.add_node("tools", self._tool_node)
        graph.add_node("respond", self._response_node)

        graph.set_entry_point("reasoning")
        graph.add_conditional_edges(
            "reasoning",
            self._should_continue,
            {"tools": "tools", "respond": "respond"},
        )
        graph.add_edge("tools", "reasoning")
        graph.add_edge("respond", END)

        return graph.compile()

    # ------------------------------------------------------------------
    # Invocation
    # ------------------------------------------------------------------
    def start_turn(self, state: AgentState) -> AgentState:
        """Reset per-turn budgets. Returns a new state dict."""
        self.budget = TurnBudget(
            max_iterations=self.budget.max_iterations,
            session_tokens_used=self.budget.session_tokens_used,
        )
        # Rebuild tools so they hold the current turn's budget.
        self.tools, self.tool_map = get_tool_registry(self.session, self.budget)
        self._bound = self._llm.bind_tools(self.tools)

        fresh = dict(state)
        fresh["working_memory"] = begin_turn(state["working_memory"])
        fresh["agent_state"] = AgentStateEnum.THINKING.value
        return fresh  # type: ignore[return-value]

    def invoke(self, state: AgentState) -> AgentState:
        return self.graph.invoke(self.start_turn(state))

    def stream(self, state: AgentState):
        yield from self.graph.stream(self.start_turn(state), stream_mode="updates")

    def cancel(self) -> None:
        self.budget.cancel()
