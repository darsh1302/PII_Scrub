"""Wall-clock and cost budgets.

Guardrail G22. Requirements 34.3-34.5. Addresses review finding OPS-03.

The reviewed design had no per-tool timeout. A stalled CloudWatch pagination, a
pathological regex, or spaCy over a large file would block the Streamlit worker
indefinitely with no cancel path — the UI simply appears hung.

Cancellation is cooperative rather than pre-emptive. Killing a thread mid-scrub
could leave a partially-written artifact or a half-updated ledger, so the flag is
checked between chunks where the state is consistent.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from utils.config import (
    MAX_LLM_TOKENS_PER_SESSION,
    PER_TOOL_TIMEOUT_SECONDS,
    PER_TURN_TIMEOUT_SECONDS,
)


class BudgetExceeded(RuntimeError):
    """Raised when a budget is exhausted. Message is user-facing."""


class Cancelled(RuntimeError):
    """Raised when the user cancelled the operation."""


@dataclass
class TurnBudget:
    """Budgets for one user turn."""

    started_at: float = field(default_factory=time.monotonic)
    max_seconds: float = PER_TURN_TIMEOUT_SECONDS
    max_iterations: int = 10
    iterations: int = 0
    cancelled: bool = False

    # Session-level, carried across turns.
    session_tokens_used: int = 0
    max_session_tokens: int = MAX_LLM_TOKENS_PER_SESSION

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def seconds_remaining(self) -> float:
        return max(0.0, self.max_seconds - self.elapsed)

    def cancel(self) -> None:
        self.cancelled = True

    def check(self) -> None:
        """Raise if any budget is exhausted. Called between steps."""
        if self.cancelled:
            raise Cancelled("the operation was cancelled")

        if self.elapsed > self.max_seconds:
            raise BudgetExceeded(
                f"this request has been running for "
                f"{int(self.elapsed)} seconds, over the "
                f"{int(self.max_seconds)}-second limit. Try a narrower scope — "
                f"a single file, or a shorter time range."
            )

        if self.iterations >= self.max_iterations:
            raise BudgetExceeded(
                f"I have taken {self.iterations} steps on this request, which "
                f"is the limit. I will summarise what I found so far rather "
                f"than continuing."
            )

    def check_tokens(self, estimated: int) -> None:
        """Pre-flight token check (Requirement 34.4).

        Estimated before the call rather than counted after, so the budget can
        refuse rather than merely report an overspend.
        """
        if self.session_tokens_used + estimated > self.max_session_tokens:
            raise BudgetExceeded(
                f"this session has used {self.session_tokens_used:,} of its "
                f"{self.max_session_tokens:,} token allowance. Start a new "
                f"session to continue."
            )

    def record_tokens(self, used: int) -> None:
        self.session_tokens_used += used

    def record_iteration(self) -> None:
        self.iterations += 1

    def to_metadata(self) -> dict[str, object]:
        return {
            "elapsed_seconds": round(self.elapsed, 1),
            "seconds_remaining": round(self.seconds_remaining, 1),
            "iterations": self.iterations,
            "max_iterations": self.max_iterations,
            "session_tokens_used": self.session_tokens_used,
            "cancelled": self.cancelled,
        }


@dataclass
class ToolBudget:
    """Budget for a single tool invocation."""

    started_at: float = field(default_factory=time.monotonic)
    max_seconds: float = PER_TOOL_TIMEOUT_SECONDS
    turn: TurnBudget | None = None

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    @property
    def exhausted(self) -> bool:
        if self.turn is not None and self.turn.cancelled:
            return True
        return self.elapsed > self.max_seconds

    def check(self) -> None:
        """Raise if this tool has run too long, or the turn was cancelled."""
        if self.turn is not None and self.turn.cancelled:
            raise Cancelled("the operation was cancelled")
        if self.elapsed > self.max_seconds:
            raise BudgetExceeded(
                f"this step exceeded its {int(self.max_seconds)}-second budget "
                f"and was stopped. Coverage is incomplete, so no cleaned copy "
                f"will be produced."
            )

    def should_continue(self) -> bool:
        """Non-raising variant for chunk loops.

        Lets the caller stop cleanly and record incomplete coverage rather than
        unwinding mid-scan.
        """
        return not self.exhausted


def estimate_tokens(text: str) -> int:
    """Rough token estimate for pre-flight checks.

    Deliberately approximate — roughly four characters per token for English.
    Exactness is unnecessary: the budget is a guard rail, and using tiktoken
    here would add a dependency to a hot path for no practical gain.
    """
    return max(1, len(text) // 4)
