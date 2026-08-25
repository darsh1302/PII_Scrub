"""Roles and what they permit — task 3.2.

`[R15.2]` requires roles to gate three specific things: tool permissions, approval
authority, and reversal of tokenization. Those are named capabilities here rather than
inferred from a role comparison.

Why capabilities rather than a role ordering
--------------------------------------------

The tempting implementation is an ordered enum and ``if role >= APPROVER``. It reads
well and it is wrong in a way that surfaces late.

An ordering asserts that every higher role includes every lower permission, so each
new capability silently attaches to everything above wherever it is inserted. Add
``REVERSE_TOKENIZATION`` at approver level and admin acquires it without anyone
deciding that. The table below makes each grant explicit, so adding a capability is a
row someone writes and a reviewer reads.

``REVERSE_TOKENIZATION`` is admin-only and, separately, unreachable from any agent
tool — ``pii_agent`` already refuses to register a tool whose name suggests reversal.
The role check is the second lock, not the only one: prompt injection that could reach
a reversal tool would turn the vault into an exfiltration primitive, and one control
between an attacker and every stored value is not enough.
"""

from __future__ import annotations

from enum import Enum

from explorer.storage.records import Role


class Capability(str, Enum):
    """What a role may do. Checked by name, never by comparing roles."""

    READ = "read"
    """See documents, runs, traces and experiments within the workspace."""

    RUN_EXPERIMENT = "run_experiment"
    """Execute a lab. Costs money and emits traces, so not granted to readers."""

    WRITE_CONTENT = "write_content"
    """Upload documents, create experiments and prompt versions."""

    DELETE_CONTENT = "delete_content"
    """Delete a document or a run. Cascades, and `[R14.5]` makes that irreversible,
    so it is deliberately not an author's to do."""

    INVOKE_HIGH_RISK_TOOL = "invoke_high_risk_tool"
    """`[R15.2]`, tool permissions. A tool the policy layer classes as high risk."""

    APPROVE = "approve"
    """`[R15.6]`. Approve a gated tool invocation. An approval records this identity,
    so it cannot be held by an unauthenticated session."""

    REVERSE_TOKENIZATION = "reverse_tokenization"
    """`[R13.5]`. Recover a value from a surrogate. Admin only, audited per access,
    and unreachable from any agent tool by construction."""

    MANAGE_WORKSPACE = "manage_workspace"
    """Membership, roles, retention periods. Includes deleting the workspace."""


# Explicit per role. No inheritance, no ordering.
#
# APPROVER deliberately does not hold WRITE_CONTENT. Someone who both prepares a
# request and approves it has defeated the point of the gate, and separating the two
# is cheaper to enforce here than to detect later in an audit.
_GRANTS: dict[Role, frozenset[Capability]] = {
    Role.READER: frozenset({Capability.READ}),
    Role.AUTHOR: frozenset(
        {
            Capability.READ,
            Capability.RUN_EXPERIMENT,
            Capability.WRITE_CONTENT,
        }
    ),
    Role.APPROVER: frozenset(
        {
            Capability.READ,
            Capability.RUN_EXPERIMENT,
            Capability.APPROVE,
            Capability.INVOKE_HIGH_RISK_TOOL,
        }
    ),
    Role.ADMIN: frozenset(
        {
            Capability.READ,
            Capability.RUN_EXPERIMENT,
            Capability.WRITE_CONTENT,
            Capability.DELETE_CONTENT,
            Capability.INVOKE_HIGH_RISK_TOOL,
            Capability.APPROVE,
            Capability.REVERSE_TOKENIZATION,
            Capability.MANAGE_WORKSPACE,
        }
    ),
}


class NotPermitted(PermissionError):
    """The authenticated identity lacks a capability in this workspace.

    Distinct from :class:`explorer.storage.protocols.NotFound`, and the distinction
    matters for what a caller may reveal. This one means "you are a member and may
    not do that", which is safe to state. A read of something in another workspace
    must stay a not-found, because saying "forbidden" confirms the row exists.
    """


def capabilities_for(role: Role | None) -> frozenset[Capability]:
    """What a role permits. ``None`` — not a member — permits nothing.

    The empty set for a non-member is the important case. A default role here would
    grant access to everyone who authenticates, in every workspace.
    """
    if role is None:
        return frozenset()
    return _GRANTS[role]


def permits(role: Role | None, capability: Capability) -> bool:
    return capability in capabilities_for(role)


def require(role: Role | None, capability: Capability) -> None:
    """Raise unless the role permits the capability."""
    if not permits(role, capability):
        holder = role.value if role else "non-member"
        raise NotPermitted(
            f"{holder} may not {capability.value} in this workspace"
        )


def roles_with(capability: Capability) -> frozenset[Role]:
    """Which roles hold a capability. For the UI, and for the tests below.

    Lets a test assert "only admin may reverse tokenization" against the grant table
    rather than restating it, so the assertion cannot drift from the implementation
    while continuing to pass.
    """
    return frozenset(
        role for role, granted in _GRANTS.items() if capability in granted
    )
