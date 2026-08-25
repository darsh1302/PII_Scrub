"""Guardrail G13 — regex patterns must be linear-time.

Addresses review finding SEC-11. Every custom recognizer runs over
attacker-controlled log content. A pattern with nested unbounded quantifiers
backtracks catastrophically on crafted input and hangs the worker — a
denial-of-service reachable by anyone who can write a log line.

The structural audit catches obvious shapes during review; these tests provide
the behavioural guarantee.
"""

from __future__ import annotations

import re
import time

import pytest

from pii_agent.core.recognizers import (
    audit_pattern_linearity,
    build_security_recognizers,
    security_entity_types,
)

# Generous: a linear pattern finishes in microseconds. Catastrophic
# backtracking takes seconds to minutes, so the gap is enormous and the
# threshold is not sensitive to machine speed.
BUDGET_SECONDS = 2.0


def _all_patterns() -> list[tuple[str, str, str]]:
    out: list[tuple[str, str, str]] = []
    for recognizer in build_security_recognizers():
        for pattern in recognizer.patterns:
            out.append(
                (recognizer.supported_entities[0], pattern.name, pattern.regex)
            )
    return out


def test_structural_audit_finds_no_suspicious_patterns():
    """No nested quantifiers or unbounded dot-star in any pattern."""
    assert audit_pattern_linearity() == []


ADVERSARIAL_INPUTS = [
    # Classic backtracking triggers against key/value shapes.
    "password" + "=" * 200,
    "password=" + "a" * 5000,
    "api_key" + " " * 2000 + "=" + "x" * 2000,
    "authorization:" + "bearer " * 800,
    # Near-miss PEM: opening header with no terminator forces the engine to
    # scan to the bound before failing.
    "-----BEGIN RSA PRIVATE KEY-----" + "A" * 20000,
    "-----BEGIN " + "RSA " * 3000 + "PRIVATE KEY-----",
    # Near-miss JWT: two segments only, so the third alternative never matches.
    "eyJ" + "A" * 4000 + "." + "B" * 4000,
    "eyJ" + ("A" * 100 + ".") * 200,
    # Connection-string shapes without the closing @host.
    "postgresql://" + "u" * 2000 + ":" + "p" * 2000,
    "Server=" + "s" * 3000 + ";Password=",
    # Repeated separators and quotes.
    '"' * 5000,
    "=" * 5000,
    ":" * 5000,
    "a:" * 3000,
    # Base64-ish runs.
    "A" * 10000,
    ("AKIA" + "A" * 16) * 300,
    # Mixed whitespace padding.
    ("password" + "\t" * 4 + "=" + " " * 4) * 500,
]


@pytest.mark.parametrize("entity,name,regex", _all_patterns())
def test_each_pattern_is_time_bounded(entity: str, name: str, regex: str):
    """Every pattern completes within budget on every adversarial input."""
    compiled = re.compile(regex)
    for payload in ADVERSARIAL_INPUTS:
        started = time.perf_counter()
        compiled.search(payload)
        elapsed = time.perf_counter() - started
        assert elapsed < BUDGET_SECONDS, (
            f"{entity}.{name} took {elapsed:.2f}s on a "
            f"{len(payload)}-char input — likely catastrophic backtracking"
        )


@pytest.mark.parametrize("length", [1_000, 10_000, 50_000])
def test_full_recognizer_set_scales_linearly(length: int):
    """Combined pattern set must stay tractable as input grows.

    Superlinear growth here would mean a large log file becomes a DoS even
    without a crafted payload.
    """
    payload = ("password=hunter2 api_key=sk-abc token=xyz " * (length // 40))[
        :length
    ]
    compiled = [re.compile(regex) for _, _, regex in _all_patterns()]

    started = time.perf_counter()
    for pattern in compiled:
        pattern.findall(payload)
    elapsed = time.perf_counter() - started

    assert elapsed < BUDGET_SECONDS * 3, (
        f"full pattern set took {elapsed:.2f}s on {length} chars"
    )


def test_all_security_entity_types_have_at_least_one_pattern():
    covered = {entity for entity, _, _ in _all_patterns()}
    assert covered == set(security_entity_types())


def test_patterns_do_not_span_newlines_except_pem_and_odbc():
    """A credential match running across log lines produces nonsense spans.

    PEM blocks and ODBC strings are the deliberate exceptions — both are
    genuinely multi-line, and both are explicitly bounded.
    """
    multiline_allowed = {
        "pem_private_key",
        "openssh_private_key",
        "ssh_private_key_body",
        "pem_private_key_header",
        "odbc_connection_string",
        "role_marker",
    }
    for entity, name, regex in _all_patterns():
        if name in multiline_allowed:
            continue
        compiled = re.compile(regex)
        payload = "password=first\npassword=second\n"
        for match in compiled.finditer(payload):
            assert "\n" not in match.group(0), (
                f"{entity}.{name} matched across a newline"
            )
