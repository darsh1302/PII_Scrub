"""The bind decision — task 3.5, `[R15.5]`.

`[R15.5]` says the platform must not bind to a non-loopback address until
Requirements 15.1 to 15.3 are satisfied, and that the PII agent's existing refusal
stays in force until authentication exists to replace it.

Authentication now exists, so the refusal becomes conditional rather than absolute.
The condition is checked here, in one function, returning a decision rather than
calling ``sys.exit`` — a startup gate that terminates the process cannot be tested
except by starting processes, and a gate nobody tests is a gate that eventually
permits everything.

Why "authentication is configured" is not the same as "the code exists"
-----------------------------------------------------------------------

The tempting check is ``if auth_module_is_importable``. That would have been satisfied
the moment task 3.1 landed, which is exactly the failure this requirement anticipates:
shipping the mechanism and enabling the port before anyone has created an account or
switched it on.

Three things are required, and all three are runtime facts rather than facts about the
codebase:

* authentication is explicitly enabled by configuration — an operator decision, not a
  default;
* the schema is migrated far enough to hold sessions, so a login can actually be
  recorded;
* at least one account exists, because a login page with no accounts is an open door
  wearing a lock.

The third is the one most likely to be argued about. An empty user table with a
first-run setup flow is a common pattern and a common breach: the setup flow is
reachable by whoever finds the port first.
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field

_ENV_BIND_ADDRESS = "EXPLORER_BIND_ADDRESS"
_ENV_AUTH_ENABLED = "EXPLORER_AUTH_ENABLED"

DEFAULT_BIND_ADDRESS = "127.0.0.1"


@dataclass(frozen=True)
class BindDecision:
    """Whether the platform may listen on the requested address, and why not.

    ``permitted`` is the answer; ``blockers`` is what to show an operator. Returning
    both means the caller can refuse *and* explain, which is the difference between a
    fixable message and "startup failed".
    """

    address: str
    permitted: bool
    is_loopback: bool
    blockers: tuple[str, ...] = field(default_factory=tuple)

    def message(self) -> str:
        if self.permitted and self.is_loopback:
            return f"Listening on {self.address} — loopback only."
        if self.permitted:
            return (
                f"Listening on {self.address} with authentication enabled. "
                f"Every request is authenticated before any data access."
            )
        listing = "\n  ".join(self.blockers)
        return (
            f"Refusing to bind {self.address}.\n"
            f"[R15.5] permits a non-loopback bind only once authentication is in "
            f"force. Outstanding:\n  {listing}\n"
            f"Set {_ENV_BIND_ADDRESS}={DEFAULT_BIND_ADDRESS} to run locally."
        )


def is_loopback(address: str) -> bool:
    """Whether an address reaches only this host.

    ``localhost`` is accepted by name because that is what people type. Anything
    unparseable is treated as non-loopback: a hostname this function cannot reason
    about must not be assumed safe, and DNS can point a friendly name anywhere.
    """
    if address in ("localhost", ""):
        return True
    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def evaluate_bind(
    *,
    address: str | None = None,
    auth_enabled: bool | None = None,
    sessions_table_present: bool = False,
    account_count: int = 0,
) -> BindDecision:
    """Decide whether the requested bind is permitted.

    Every input is a parameter with a conservative default, so a caller that forgets
    to pass one gets a refusal rather than an accidental permit. That ordering matters:
    the failure mode of this function should be a service that will not start, never a
    service that starts open.
    """
    resolved_address = (
        address
        if address is not None
        else os.environ.get(_ENV_BIND_ADDRESS, DEFAULT_BIND_ADDRESS).strip()
        or DEFAULT_BIND_ADDRESS
    )
    loopback = is_loopback(resolved_address)

    if loopback:
        return BindDecision(
            address=resolved_address, permitted=True, is_loopback=True
        )

    resolved_auth = (
        auth_enabled
        if auth_enabled is not None
        else os.environ.get(_ENV_AUTH_ENABLED, "").strip().lower() == "true"
    )

    blockers: list[str] = []
    if not resolved_auth:
        blockers.append(
            f"{_ENV_AUTH_ENABLED} is not true. Authentication must be switched on "
            f"deliberately [R15.1]."
        )
    if not sessions_table_present:
        blockers.append(
            "the user_session table is absent — migrations have not been applied, "
            "so a login could not be recorded."
        )
    if account_count < 1:
        blockers.append(
            "no accounts exist. A login page with an empty user table and a "
            "first-run setup flow is reachable by whoever finds the port first."
        )

    return BindDecision(
        address=resolved_address,
        permitted=not blockers,
        is_loopback=False,
        blockers=tuple(blockers),
    )


def evaluate_bind_from_database(database, *, address: str | None = None) -> BindDecision:
    """The same decision, reading the two runtime facts from the database.

    Kept separate from :func:`evaluate_bind` so the policy stays testable without a
    database and the query stays in one place. A loopback bind returns before any
    query runs, so local development needs no database to start.
    """
    resolved_address = (
        address
        if address is not None
        else os.environ.get(_ENV_BIND_ADDRESS, DEFAULT_BIND_ADDRESS).strip()
        or DEFAULT_BIND_ADDRESS
    )
    if is_loopback(resolved_address):
        return evaluate_bind(address=resolved_address)

    tables = database.table_names()
    sessions_present = "user_session" in tables
    accounts = 0
    if "app_user" in tables:
        accounts = int(
            database.execute_scalar("SELECT count(*) FROM app_user WHERE NOT disabled")
        )

    return evaluate_bind(
        address=resolved_address,
        sessions_table_present=sessions_present,
        account_count=accounts,
    )
