"""The content gate — what may cross from the trusted core into the LLM.

Guardrail G1. Correctness Property 9. Addresses SEC-01, SEC-02, SEC-03.

Every value returned by a tool passes through here before it can reach the
reasoning context. The gate exists because the reviewed design let three things
through that must never cross:

* **Raw content** — the agent ingests attacker-writable logs by design, so
  content in the prompt is an injection vector (SEC-01), and it is also a
  disclosure to a third-party processor (SEC-03).
* **Entity offsets** — an LLM asked to transcribe integers gets them wrong
  occasionally, and a wrong offset scrubs the wrong span while leaving the PII
  in place (SEC-02). The model has no legitimate use for them.
* **HIGH-severity entity text** — sending a detected secret to a model to ask
  whether it is a secret defeats the point.

``sanitize_error`` is here for the same reason: parser and OS error messages
routinely quote the input that caused them.
"""

from __future__ import annotations

import json
import re
from typing import Any

from models.results import ProcessingResult
from utils.config import MAX_CONTENT_TO_LLM_CHARS

# Keys that must never appear in anything handed to the model.
_FORBIDDEN_KEYS = frozenset(
    {
        "content",
        "raw_content",
        "text",
        "sanitized",
        "sanitized_text",
        "value",
        "matched_text",
        "entity_text",
        "start",
        "end",
        "span",
        "offset",
        "offsets",
        "positions",
        "original",
        "document",
    }
)

# Credential shapes scrubbed from any string crossing the gate, as a backstop
# for a value that reached here by an unexpected path.
_SECRET_SHAPES = [
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{16,}"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{5,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)://[^:/\s]{1,64}:([^@/\s]{3,128})@"),
]

# Filesystem paths reduced to a filename: a full path discloses directory
# layout, and the model only needs to name the file.
#
# The separator is ``\\{1,2}`` rather than a single backslash because OSError
# renders its filename through repr(), so ``str(exc)`` contains doubled
# backslashes. Matching only single ones let real paths through unshortened.
_PATH_SHAPES = [
    re.compile(r"[A-Za-z]:\\{1,2}(?:[^\\\s\"']+\\{1,2})*([^\\\s\"']+)"),
    re.compile(r"(?:/[^/\s\"']+){2,}/([^/\s\"']+)"),
]


class GateViolation(RuntimeError):
    """Raised when a payload bound for the LLM contains forbidden material.

    A bug rather than a user error: it means a code path bypassed the gate's
    intended construction.
    """


def redact_secret_shapes(text: str) -> str:
    """Replace credential-shaped substrings with a type marker."""
    out = text
    for pattern in _SECRET_SHAPES:
        out = pattern.sub("[REDACTED_SECRET]", out)
    return out


def shorten_paths(text: str) -> str:
    """Reduce absolute paths to their filename."""
    out = text
    for pattern in _PATH_SHAPES:
        out = pattern.sub(lambda m: m.group(1), out)
    return out


def assert_gate_safe(payload: Any, path: str = "") -> None:
    """Raise if ``payload`` contains a forbidden key.

    Checked structurally rather than trusted to construction, because the
    failure is silent: a leaked offset or content field looks like ordinary
    metadata.
    """
    if isinstance(payload, dict):
        for key, value in payload.items():
            here = f"{path}.{key}" if path else str(key)
            if str(key).lower() in _FORBIDDEN_KEYS:
                raise GateViolation(
                    f"field '{here}' may not cross the content gate — the "
                    f"reasoning context receives no content, offsets, or "
                    f"secret values"
                )
            assert_gate_safe(value, here)
    elif isinstance(payload, (list, tuple)):
        for index, item in enumerate(payload):
            assert_gate_safe(item, f"{path}[{index}]")


def sanitize_text_for_llm(text: str, *, max_chars: int | None = None) -> str:
    """Make an arbitrary string safe to include in a prompt."""
    limit = max_chars or MAX_CONTENT_TO_LLM_CHARS
    out = shorten_paths(redact_secret_shapes(text))
    if len(out) > limit:
        out = out[:limit] + f"\n[... truncated at {limit:,} characters]"
    return out


def gate_result(result: ProcessingResult) -> dict[str, Any]:
    """Project a ProcessingResult into its LLM-safe form.

    The single sanctioned path from the trusted core to the reasoning context.
    """
    payload = result.to_llm_metadata()
    assert_gate_safe(payload)
    return payload


def gate_tool_output(payload: Any) -> str:
    """Serialise a tool result for the reasoning context.

    Returns JSON so the model receives structure rather than prose it might
    reinterpret. Verified against the forbidden-key set before serialisation.
    """
    assert_gate_safe(payload)
    rendered = json.dumps(payload, default=str, sort_keys=True)
    rendered = redact_secret_shapes(rendered)
    if len(rendered) > MAX_CONTENT_TO_LLM_CHARS:
        # Truncating JSON produces invalid JSON, so replace it with a structured
        # notice rather than a broken fragment.
        return json.dumps(
            {
                "status": "RESULT_TOO_LARGE",
                "detail": (
                    f"the result was {len(rendered):,} characters, over the "
                    f"{MAX_CONTENT_TO_LLM_CHARS:,} limit for a single step. "
                    f"Ask for a narrower summary."
                ),
            }
        )
    return rendered


def sanitize_error(exc: BaseException) -> str:
    """Turn an exception into a message safe to show a user or the model.

    Strips stack traces, internal codes, absolute paths, and credential shapes.
    Requirement 16.4: the user gets an explanation, never a traceback.
    """
    message = str(exc).strip() or exc.__class__.__name__

    # Only the first line — later lines are usually traceback context.
    message = message.split("\n")[0]
    message = shorten_paths(redact_secret_shapes(message))

    # Strip errno-style prefixes such as "[Errno 13]".
    message = re.sub(r"^\[Errno \d+\]\s*", "", message)

    if len(message) > 400:
        message = message[:400] + "..."
    return message
