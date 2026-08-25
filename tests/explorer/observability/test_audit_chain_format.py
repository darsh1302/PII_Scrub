"""The audit chain, and its contract with the PII agent's sink.

``explorer.observability.audit_chain`` duplicates the hash-chaining in
``pii_agent.session.audit_sink``. That duplication is the price of dependency rules D1
and D2 — a deletion audit is not a PII operation, so it cannot go through the
``pii_service`` seam, and the design rejected a ``shared/`` package on the grounds that
it becomes the place coupling hides.

The risk in paying that price is drift. Two hash chains that were once identical, and
then were not, mean a trail exported from one product will not verify with the other's
verifier — discovered at the worst possible moment, which is when someone is trying to
verify an old trail.

So the formats are pinned to each other by test rather than by shared code. This file
imports both, which is legitimate: the architecture test walks ``pii_agent/`` and
``explorer/``, not ``tests/``, and a test asserting a contract between two products is
exactly where that contract should live.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from explorer.observability import audit_chain as explorer_audit
from pii_agent.session import audit_sink as agent_audit


# ---------------------------------------------------------------------------
# the contract with the PII agent's sink
# ---------------------------------------------------------------------------
def test_both_implementations_agree_on_canonical_form():
    """Byte-identical serialization, or the hashes cannot match.

    Sorted keys and no insignificant whitespace. A difference as small as a space after
    a comma changes every hash in the chain.
    """
    record = {
        "event": "deletion",
        "zebra": 1,
        "alpha": {"nested": True, "count": 3},
        "list": [1, 2, {"inner": "x"}],
    }

    assert explorer_audit.canonical(record) == agent_audit._canonical(record)


def test_both_implementations_produce_the_same_record_hash():
    record = {"event": "deletion", "subject": "document", "rows_deleted": 5}

    assert explorer_audit.compute_record_hash(record) == (
        agent_audit.compute_record_hash(record)
    )


def test_the_hash_excludes_the_record_hash_field_in_both():
    """Otherwise a record's hash would depend on itself.

    Both must exclude it, and both must exclude only it — including ``prev_hash`` in the
    payload is what makes the chain a chain.
    """
    base = {"event": "deletion", "prev_hash": "a" * 64}
    with_hash = {**base, "record_hash": "irrelevant"}

    assert explorer_audit.compute_record_hash(base) == (
        explorer_audit.compute_record_hash(with_hash)
    )
    assert agent_audit.compute_record_hash(base) == (
        agent_audit.compute_record_hash(with_hash)
    )


def test_the_genesis_hash_matches():
    assert explorer_audit.GENESIS_HASH == agent_audit.GENESIS_HASH


def test_the_explorer_forbids_at_least_everything_the_agent_forbids():
    """The platform's set may be wider, never narrower.

    Narrower would mean a field the security product refuses to log is acceptable in a
    platform audit record, which is the wrong direction for a rule about content.
    """
    agent_forbidden = agent_audit._FORBIDDEN_FIELDS
    explorer_forbidden = explorer_audit._FORBIDDEN_FIELDS

    missing = agent_forbidden - explorer_forbidden
    assert missing == set(), (
        f"the platform audit chain permits fields the PII agent refuses: {missing}"
    )


def test_a_trail_written_by_the_explorer_verifies_with_the_agents_verifier(tmp_path):
    """The practical form of the contract.

    Not just equal hash functions — an actual file written by one and verified by the
    other. This is what would break if the two drifted, and it is the failure that
    would otherwise surface only when verifying an old trail.
    """
    chain = explorer_audit.AuditChain(tmp_path, prefix="audit")
    for index in range(3):
        chain.append({"event": "deletion", "sequence": index})

    # The agent's sink reads `audit-*.jsonl` from a directory, which is why the prefix
    # above is set to match.
    sink = agent_audit.AuditSink(tmp_path)
    ok, bad = sink.verify_chain()

    assert ok is True, f"the agent's verifier rejected the platform's chain at {bad}"
    assert sink.count() == 3


# ---------------------------------------------------------------------------
# the chain itself
# ---------------------------------------------------------------------------
def test_records_chain_to_their_predecessors(tmp_path):
    chain = explorer_audit.AuditChain(tmp_path)
    first = chain.append({"event": "deletion", "n": 1})
    second = chain.append({"event": "deletion", "n": 2})

    records = list(chain.read_all())
    assert records[0]["prev_hash"] == explorer_audit.GENESIS_HASH
    assert records[0]["record_hash"] == first
    assert records[1]["prev_hash"] == first
    assert records[1]["record_hash"] == second


def test_an_empty_chain_verifies(tmp_path):
    ok, bad = explorer_audit.AuditChain(tmp_path).verify_chain()
    assert ok is True and bad is None


def test_removing_a_record_breaks_the_chain(tmp_path):
    """Reordering and removal, not just editing.

    An edited record fails its own hash. A removed one leaves the next record's
    ``prev_hash`` pointing at something that is no longer there, which is why both
    checks are needed.
    """
    chain = explorer_audit.AuditChain(tmp_path)
    for index in range(3):
        chain.append({"event": "deletion", "n": index})

    path = sorted(tmp_path.glob("explorer-audit-*.jsonl"))[0]
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")

    ok, _ = chain.verify_chain()
    assert ok is False


@pytest.mark.parametrize(
    "field",
    ["text", "content", "value", "payload", "prompt", "vector", "token", "verifier"],
)
def test_forbidden_fields_are_rejected_at_write_time(tmp_path, field):
    """Enforced at the write, not trusted to review.

    The failure is silent and permanent: content in the one file designed to outlive
    every retention policy.
    """
    chain = explorer_audit.AuditChain(tmp_path)
    with pytest.raises(explorer_audit.AuditIntegrityError, match=field):
        chain.append({"event": "deletion", field: "something sensitive"})


def test_forbidden_fields_are_rejected_when_nested(tmp_path):
    """A top-level-only check would pass a payload one dictionary deep.

    Which is exactly how content ends up in a log — nobody writes ``{"content": ...}``
    at the top level, they write ``{"detail": {"content": ...}}``.
    """
    chain = explorer_audit.AuditChain(tmp_path)
    with pytest.raises(explorer_audit.AuditIntegrityError, match="detail.content"):
        chain.append({"event": "deletion", "detail": {"content": "leaked"}})


def test_forbidden_fields_are_rejected_inside_a_list(tmp_path):
    chain = explorer_audit.AuditChain(tmp_path)
    with pytest.raises(explorer_audit.AuditIntegrityError):
        chain.append({"event": "deletion", "items": [{"ok": 1}, {"value": "leaked"}]})


def test_a_timestamp_is_added_when_absent(tmp_path):
    chain = explorer_audit.AuditChain(tmp_path)
    chain.append({"event": "deletion"})

    record = next(iter(chain.read_all()))
    assert "timestamp" in record


def test_a_supplied_timestamp_is_preserved(tmp_path):
    """The sweeper records the sweep's own time, not the write's."""
    chain = explorer_audit.AuditChain(tmp_path)
    chain.append({"event": "deletion", "timestamp": "2026-01-01T00:00:00+00:00"})

    record = next(iter(chain.read_all()))
    assert record["timestamp"] == "2026-01-01T00:00:00+00:00"
