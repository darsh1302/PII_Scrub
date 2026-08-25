"""Password verification with a memory-hard KDF — task 3.1.

Why scrypt from the standard library
------------------------------------

`[R15.1]` requires authentication; the task requires a memory-hard KDF and requires
the parameters to be recorded so they can be raised later.

Argon2id is the better modern choice and OWASP's first recommendation. It is not used
here because it needs a compiled third-party wheel, and this project pins every
dependency exactly for reproducibility reasons that have nothing to do with
passwords — adding a build-dependent package to the pinned set has a cost.
``hashlib.scrypt`` is memory-hard, in the standard library since 3.6, and OWASP lists
it as acceptable at the parameters below.

The decision is recoverable rather than permanent, which is the point of recording
the algorithm name in every verifier string. Adding Argon2id later means teaching
:func:`verify` a second prefix and rehashing on next login; it needs no migration and
no password reset. A scheme that stored only a bare digest would need both.

Verifier format
---------------

``scrypt$n=<N>$r=<r>$p=<p>$<salt-b64>$<digest-b64>``

Self-describing on purpose. Parameters live in the row, not in a module constant, so
raising the cost factor does not invalidate every existing password: an old verifier
is checked at the parameters it was created with, and
:func:`needs_rehash` reports that it should be upgraded on next successful login.
A module-level constant would make the same change a forced password reset for
everyone.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

ALGORITHM = "scrypt"

# N = 2^16, r = 8, p = 1 → about 64 MiB per verification.
#
# Chosen against the cost of a login rather than a benchmark maximum. 64 MiB and
# roughly 100 ms on a modern core is comfortably inside a request budget, and it makes
# large-scale offline cracking expensive per guess. Raising N is a one-line change
# whose only consequence is that old verifiers get upgraded as people sign in.
#
# hashlib.scrypt enforces maxmem, which defaults low enough to reject these
# parameters, so it is passed explicitly below. Omitting it produces a confusing
# ValueError about memory limits rather than anything about passwords.
DEFAULT_N = 1 << 16
DEFAULT_R = 8
DEFAULT_P = 1
DEFAULT_MAXMEM = 128 * DEFAULT_N * DEFAULT_R * 2  # scrypt's own formula, doubled

SALT_BYTES = 16
KEY_BYTES = 32

# Above scrypt's own limit, which is a defence against a long password being used as a
# denial-of-service vector: the KDF cost is fixed, but hashing a 10 MB "password"
# still costs something, and the request has to read it first.
MAX_PASSWORD_BYTES = 1024


class InvalidVerifier(ValueError):
    """A stored verifier string cannot be parsed.

    Distinct from a wrong password. This means stored data is malformed — a
    truncating column, a bad migration — and it must never be reported to a caller
    as a failed login, because that would make corruption look like a typo and hide
    it indefinitely.
    """


@dataclass(frozen=True)
class KdfParameters:
    """The cost parameters a particular verifier was created with."""

    n: int = DEFAULT_N
    r: int = DEFAULT_R
    p: int = DEFAULT_P

    @property
    def maxmem(self) -> int:
        return 128 * self.n * self.r * 2

    def is_weaker_than_current(self) -> bool:
        return (self.n, self.r, self.p) < (DEFAULT_N, DEFAULT_R, DEFAULT_P)


def hash_password(
    password: str, *, parameters: KdfParameters | None = None
) -> str:
    """Derive a verifier string for storage.

    Salt is per-password and from ``secrets``. A shared salt would let one derivation
    be reused across every account, which is the whole value of salting.
    """
    _check_length(password)
    params = parameters or KdfParameters()
    salt = secrets.token_bytes(SALT_BYTES)
    digest = _derive(password, salt, params)

    return "$".join(
        [
            ALGORITHM,
            f"n={params.n}",
            f"r={params.r}",
            f"p={params.p}",
            _b64(salt),
            _b64(digest),
        ]
    )


def verify(password: str, verifier: str) -> bool:
    """Whether ``password`` matches ``verifier``.

    Compared with :func:`hmac.compare_digest`. A plain ``==`` on digests leaks how
    many leading bytes matched through timing, which over enough attempts recovers
    the digest — and a recovered digest is a login.

    An over-length password returns False rather than raising. Length is attacker
    controlled, so raising here would turn a request into a 500 and make the limit a
    way to generate error noise.
    """
    try:
        params, salt, expected = _parse(verifier)
    except InvalidVerifier:
        raise
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False

    candidate = _derive(password, salt, params)
    return hmac.compare_digest(candidate, expected)


def needs_rehash(verifier: str) -> bool:
    """Whether a successful login should be re-hashed at current parameters.

    Called after verification succeeds, so the plaintext is in hand exactly once and
    the upgrade costs nothing extra. This is what makes raising ``DEFAULT_N`` a
    gradual migration rather than a password reset for every user.
    """
    params, _, _ = _parse(verifier)
    return params.is_weaker_than_current()


def describe(verifier: str) -> str:
    """The algorithm and parameters, for a health panel or an audit record.

    Never includes the salt or the digest. A "which KDF are we on" question should be
    answerable without a query that returns credential material.
    """
    params, _, _ = _parse(verifier)
    return f"{ALGORITHM} n={params.n} r={params.r} p={params.p}"


def _derive(password: str, salt: bytes, params: KdfParameters) -> bytes:
    return hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=params.n,
        r=params.r,
        p=params.p,
        maxmem=params.maxmem,
        dklen=KEY_BYTES,
    )


def _parse(verifier: str) -> tuple[KdfParameters, bytes, bytes]:
    parts = verifier.split("$")
    if len(parts) != 6 or parts[0] != ALGORITHM:
        raise InvalidVerifier(
            f"unrecognised verifier format (expected 6 {ALGORITHM}-prefixed "
            f"fields, got {len(parts)})"
        )

    try:
        n = int(parts[1].removeprefix("n="))
        r = int(parts[2].removeprefix("r="))
        p = int(parts[3].removeprefix("p="))
        salt = base64.b64decode(parts[4], validate=True)
        digest = base64.b64decode(parts[5], validate=True)
    except (ValueError, TypeError) as exc:
        raise InvalidVerifier(f"malformed verifier fields: {exc}") from exc

    if not salt or not digest:
        raise InvalidVerifier("verifier has an empty salt or digest")

    return KdfParameters(n=n, r=r, p=p), salt, digest


def _check_length(password: str) -> None:
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(
            f"password exceeds {MAX_PASSWORD_BYTES} bytes; scrypt's cost is fixed "
            f"but reading and hashing an arbitrarily long input is not"
        )


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")
