"""Detection of prompt-injection and encoded-secret evasion in scanned content.

Guardrail G3. Requirements 33.3, 33.4, 43.5.

This is a *reporting* control, not the primary defence. The structural defence is
that scanned content never enters the reasoning context at all (G1) and that
policy is decided in code (G4). Even a fully manipulated reasoning step cannot
weaken a scrub action.

What this adds is visibility. If a log file contains text engineered to
manipulate an AI agent, the operator should know — someone wrote it deliberately,
and that is worth investigating regardless of whether it worked here.

Detected content is reported by *type and count*. The injected text itself is
never reproduced in the audit record (Requirement 43.7): doing so would place
attacker-authored instructions into the compliance trail, where a later reader or
tool might act on them.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

# Instruction-shaped markers. Case-insensitive, bounded.
_INJECTION_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    (
        "role_marker",
        re.compile(
            r"(?i)^[ \t]{0,8}(?:system|assistant|user|human|ai)[ \t]{0,4}:",
            re.MULTILINE,
        ),
        "text formatted as a chat role marker",
    ),
    (
        "chat_template_token",
        re.compile(r"<\|(?:im_start|im_end|endoftext|system|assistant|user)\|>"),
        "chat template control tokens",
    ),
    (
        "bracketed_directive",
        re.compile(r"\[\[[ \t]{0,4}(?i:system|instruction|note|important)\b"),
        "bracketed directive block",
    ),
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(?:ignore|disregard|forget|override)\b[ \t]{1,4}"
            r"(?:\w+[ \t]{1,4}){0,3}"
            r"\b(?:previous|prior|earlier|above|all)\b[ \t]{1,4}"
            r"\b(?:instruction|instructions|prompt|prompts|rule|rules|context)\b"
        ),
        "instruction-override phrasing",
    ),
    (
        "false_completion_claim",
        re.compile(
            r"(?i)\b(?:scan|analysis|review)\b[ \t]{1,4}"
            r"\b(?:complete|completed|finished|done)\b"
            r"[^\n]{0,60}?\b(?:0|no|zero|none)\b[^\n]{0,20}?"
            r"\b(?:pii|findings?|issues?|sensitive)\b"
        ),
        "a false claim that scanning found nothing",
    ),
    (
        "action_directive",
        re.compile(
            r"(?i)\b(?:set|use|apply)\b[ \t]{0,4}"
            r"(?:requested_action|action|scrub_action)[ \t]{0,4}"
            r"[=:][ \t]{0,4}(?:allow|none|skip)"
        ),
        "an attempt to set a scrub action directly",
    ),
    (
        "skip_directive",
        re.compile(
            r"(?i)\b(?:skip|bypass|disable|suppress)\b[ \t]{1,4}"
            r"(?:\w+[ \t]{1,4}){0,2}"
            r"\b(?:redaction|scrubbing|detection|sanitization|sanitisation)\b"
        ),
        "an attempt to skip redaction",
    ),
    (
        "report_clean_directive",
        re.compile(
            r"(?i)\breport\b[ \t]{1,4}(?:\w+[ \t]{1,4}){0,3}\bas\b[ \t]{1,4}"
            r"\b(?:clean|safe|verified)\b"
        ),
        "an instruction to report content as clean",
    ),
]

# Base64 that decodes to something credential-shaped.
_BASE64_CANDIDATE = re.compile(r"\b[A-Za-z0-9+/]{20,512}={0,2}\b")
_HEX_CANDIDATE = re.compile(r"\b(?:[0-9a-fA-F]{2}){10,256}\b")

# Applied to decoded output to decide whether it was worth encoding.
_SECRET_SHAPED = re.compile(
    r"(?i)(?:sk-[A-Za-z0-9_\-]{16,}|AKIA[A-Z0-9]{16}|"
    r"gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-|"
    r"-----BEGIN|"
    r"\b(?:password|passwd|api[_\-]?key|secret|token|bearer)\b[ \t]{0,4}[:=])"
)

# Values split across adjacent fields, e.g. first=482 second=71 third=9053
#
# Written as "two-or-more separated pairs, then a final unseparated pair" rather
# than "three-or-more separated pairs": the last field on a line has no trailing
# separator, so requiring one would miss every value that ends a line — which is
# most of them.
_FIELD_PAIR = r"\b\w{1,20}[ \t]{0,4}[=:][ \t]{0,4}\d{2,4}\b"
_SPLIT_FIELD = re.compile(rf"(?:{_FIELD_PAIR}[ \t,;]{{1,4}}){{2,}}{_FIELD_PAIR}")


@dataclass
class SecurityFinding:
    """A non-PII observation about the content itself."""

    kind: str
    description: str
    occurrences: int = 1
    # Offsets so the UI can highlight, never the matched text.
    spans: list[tuple[int, int]] = field(default_factory=list)

    def to_metadata(self) -> dict[str, object]:
        """Audit-safe: kind and count only, never the injected text."""
        return {
            "kind": self.kind,
            "description": self.description,
            "occurrences": self.occurrences,
        }


@dataclass
class ScanFindings:
    findings: list[SecurityFinding] = field(default_factory=list)

    def __bool__(self) -> bool:
        return bool(self.findings)

    def __len__(self) -> int:
        return len(self.findings)

    @property
    def has_injection(self) -> bool:
        return any(f.kind.startswith("injection:") for f in self.findings)

    @property
    def has_encoded_secret(self) -> bool:
        return any(f.kind.startswith("encoded:") for f in self.findings)

    def user_summary(self) -> str:
        """Plain-language summary for the chat response."""
        if not self.findings:
            return ""
        lines: list[str] = []
        if self.has_injection:
            lines.append(
                "This content contains text that appears designed to "
                "manipulate an AI agent. It had no effect — scrub actions are "
                "decided in code, not by the model — but someone wrote it "
                "deliberately, so it is worth investigating how it got there."
            )
        if self.has_encoded_secret:
            lines.append(
                "This content contains encoded values that decode to "
                "credential-shaped data. Encoding is often used to slip secrets "
                "past pattern matching."
            )
        for finding in self.findings:
            lines.append(f"  - {finding.description} ({finding.occurrences}x)")
        return "\n".join(lines)

    def to_metadata(self) -> list[dict[str, object]]:
        return [f.to_metadata() for f in self.findings]


def _decodes_to_secret(candidate: str) -> bool:
    try:
        padded = candidate + "=" * (-len(candidate) % 4)
        decoded = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return False
    try:
        text = decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return bool(_SECRET_SHAPED.search(text))


def _hex_decodes_to_secret(candidate: str) -> bool:
    try:
        decoded = bytes.fromhex(candidate)
    except ValueError:
        return False
    try:
        text = decoded.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return bool(_SECRET_SHAPED.search(text))


def scan_for_injection(text: str) -> ScanFindings:
    """Report injection-shaped and encoded-secret content."""
    findings: list[SecurityFinding] = []

    for kind, pattern, description in _INJECTION_PATTERNS:
        spans = [(m.start(), m.end()) for m in pattern.finditer(text)]
        if spans:
            findings.append(
                SecurityFinding(
                    kind=f"injection:{kind}",
                    description=description,
                    occurrences=len(spans),
                    spans=spans[:20],
                )
            )

    b64_spans = [
        (m.start(), m.end())
        for m in _BASE64_CANDIDATE.finditer(text)
        if _decodes_to_secret(m.group(0))
    ]
    if b64_spans:
        findings.append(
            SecurityFinding(
                kind="encoded:base64",
                description="base64 value decoding to credential-shaped data",
                occurrences=len(b64_spans),
                spans=b64_spans[:20],
            )
        )

    hex_spans = [
        (m.start(), m.end())
        for m in _HEX_CANDIDATE.finditer(text)
        if _hex_decodes_to_secret(m.group(0))
    ]
    if hex_spans:
        findings.append(
            SecurityFinding(
                kind="encoded:hex",
                description="hex value decoding to credential-shaped data",
                occurrences=len(hex_spans),
                spans=hex_spans[:20],
            )
        )

    split_spans = [(m.start(), m.end()) for m in _SPLIT_FIELD.finditer(text)]
    if split_spans:
        findings.append(
            SecurityFinding(
                kind="evasion:split_fields",
                description=(
                    "numeric value apparently split across adjacent fields"
                ),
                occurrences=len(split_spans),
                spans=split_spans[:20],
            )
        )

    return ScanFindings(findings=findings)
