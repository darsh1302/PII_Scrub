"""Storage configuration, read from the environment once.

Follows the PII agent's convention: environment through ``python-dotenv``, never a
hardcoded value, and a missing setting produces a message saying what to set rather
than a ``KeyError`` several frames deep.

Nothing here reads ``PII_AGENT_*``. The two products configure independently — D1
is not only an import rule, it means the security product must keep running with
none of this present.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

_ENV_DATABASE_URL = "EXPLORER_DATABASE_URL"
_ENV_TEST_DATABASE_URL = "EXPLORER_TEST_DATABASE_URL"
_ENV_OBJECT_STORE = "EXPLORER_OBJECT_STORE"
_ENV_OBJECT_STORE_ROOT = "EXPLORER_OBJECT_STORE_ROOT"
_ENV_OBJECT_STORE_BUCKET = "EXPLORER_OBJECT_STORE_BUCKET"
_ENV_OBJECT_STORE_ENDPOINT = "EXPLORER_OBJECT_STORE_ENDPOINT"

_SETUP_HINT = (
    "Set it in .env. A local instance is provided by:\n"
    "    python tools_dev/pg_local.py install\n"
    "    python tools_dev/pg_local.py start\n"
    "which prints both URLs."
)


class StorageNotConfigured(RuntimeError):
    """A required storage setting is absent.

    Raised rather than falling back to a default. A default database URL would
    connect somewhere nobody chose, and a default object-store root would write
    content to a path nobody is watching.
    """


@dataclass(frozen=True)
class ObjectStoreSettings:
    """Which payload store, and where."""

    kind: str
    root: Path | None = None
    bucket: str | None = None
    endpoint: str | None = None

    def __post_init__(self) -> None:
        if self.kind not in ("filesystem", "s3"):
            raise StorageNotConfigured(
                f"{_ENV_OBJECT_STORE}={self.kind!r} is not recognised. "
                f"Use 'filesystem' or 's3'."
            )
        if self.kind == "filesystem" and self.root is None:
            raise StorageNotConfigured(
                f"{_ENV_OBJECT_STORE}=filesystem requires "
                f"{_ENV_OBJECT_STORE_ROOT}."
            )
        if self.kind == "s3" and not self.bucket:
            raise StorageNotConfigured(
                f"{_ENV_OBJECT_STORE}=s3 requires {_ENV_OBJECT_STORE_BUCKET}."
            )


def database_url(*, testing: bool = False) -> str:
    """The connection URL.

    ``testing=True`` reads a *separate* variable and never falls back to the
    development one. A fallback here would let a test run truncate whatever the
    developer was looking at, which is how people stop running the tests.
    """
    variable = _ENV_TEST_DATABASE_URL if testing else _ENV_DATABASE_URL
    value = os.environ.get(variable, "").strip()
    if not value:
        raise StorageNotConfigured(f"{variable} is not set.\n{_SETUP_HINT}")
    return value


def object_store_settings() -> ObjectStoreSettings:
    kind = os.environ.get(_ENV_OBJECT_STORE, "filesystem").strip() or "filesystem"
    root_value = os.environ.get(_ENV_OBJECT_STORE_ROOT, "").strip()
    return ObjectStoreSettings(
        kind=kind,
        root=Path(root_value).resolve() if root_value else None,
        bucket=os.environ.get(_ENV_OBJECT_STORE_BUCKET, "").strip() or None,
        endpoint=os.environ.get(_ENV_OBJECT_STORE_ENDPOINT, "").strip() or None,
    )


def is_configured(*, testing: bool = False) -> bool:
    """Whether a database URL is present, without raising.

    Used by the test suite's skip decision and by the health panel. Deliberately
    not used by application code: a code path that silently does nothing when
    storage is unconfigured is worse than one that fails.
    """
    variable = _ENV_TEST_DATABASE_URL if testing else _ENV_DATABASE_URL
    return bool(os.environ.get(variable, "").strip())


def redacted(url: str) -> str:
    """A connection URL safe to log or show in a health panel.

    The password is the only secret in the string, and it is the part most likely
    to be pasted into an issue report along with the rest.
    """
    if "@" not in url or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    credentials, host = rest.rsplit("@", 1)
    user = credentials.split(":", 1)[0]
    return f"{scheme}://{user}:***@{host}"
