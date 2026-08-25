"""Content payload storage: filesystem locally, S3-compatible in deployment.

Content lives here rather than in Postgres for two reasons from the design. Deleting
a large artifact should not rewrite a table, and `[R14.4]` wants originals and
sanitized output on independently configurable clocks — which is easier when they
are separate objects than when they are columns.

Encryption at rest `[R14.2]`, named rather than implied
-------------------------------------------------------

The mechanism is the store's, not ours, and it differs by adapter:

* **Filesystem** — whole-volume encryption provided by the operating system
  (BitLocker on Windows, LUKS or FileVault elsewhere). This adapter does **not**
  encrypt individual objects, so on a volume without full-disk encryption the
  payloads are plaintext on disk. That is stated plainly because the alternative is
  a reader assuming otherwise. It is the local-development adapter.
* **S3** — server-side encryption, requested explicitly on every ``put`` rather
  than relying on a bucket default, because a bucket default is a setting someone
  else can change.

Application-level envelope encryption is deliberately absent. It would put a key in
this process, and a key held next to the ciphertext it protects buys less than it
appears to; the honest version is to name what the platform relies on and let an
operator verify it.

Path containment
----------------

The filesystem adapter treats every key as untrusted. Keys are constructed by
:func:`payload_key`, but an adapter that is only safe when its caller is correct is
not safe. ``_resolve`` refuses anything escaping the root, and the check is on the
resolved path rather than on the string, since ``a/../../b`` contains no suspicious
character.

This duplicates a little of ``pii_agent.utils.paths``. That is deliberate:
dependency rule D1 keeps the security product free of platform imports, and D2
allows the reverse only through the PII service seam. Twenty lines of containment is
a smaller cost than a second import path into the agent.
"""

from __future__ import annotations

import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from uuid import UUID

from explorer.storage.config import ObjectStoreSettings, object_store_settings
from explorer.storage.protocols import ObjectStore, ObjectStoreError

PAYLOAD_KINDS = ("original", "sanitized", "chunk")
"""``original`` and ``sanitized`` are separate kinds because `[R14.4]` puts them on
separate retention clocks, and a clock cannot be applied to a distinction the key
does not record."""


def payload_key(*, workspace_id: UUID, kind: str, object_id: UUID) -> str:
    """A workspace-prefixed, opaque key.

    Workspace-first so a prefix listing cannot walk out of a workspace, and opaque
    so a leaked key does not name a document. Putting the label in the key would
    disclose "2024-termination-letters.pdf" to anyone who sees a log line.
    """
    if kind not in PAYLOAD_KINDS:
        raise ValueError(
            f"unknown payload kind {kind!r}; expected one of {PAYLOAD_KINDS}"
        )
    return f"{workspace_id}/{kind}/{object_id}"


def workspace_prefix(workspace_id: UUID) -> str:
    """Everything a workspace owns, for cascade deletion `[R14.5]`."""
    return f"{workspace_id}/"


class FilesystemObjectStore:
    """Local development adapter. See the module docstring on encryption."""

    def __init__(self, root: Path) -> None:
        self._root = root.resolve()
        self._root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        if not key or key.startswith("/") or "\\" in key:
            raise ObjectStoreError(f"invalid object key {key!r}")

        candidate = (self._root / key).resolve()

        # On the resolved path, not the string: "a/../../b" contains nothing that
        # looks wrong and resolves outside the root.
        if candidate != self._root and self._root not in candidate.parents:
            raise ObjectStoreError(
                f"object key {key!r} resolves outside the object store root"
            )
        return candidate

    def put(self, key: str, data: bytes, *, content_type: str) -> None:
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Write-then-rename. A reader must never observe a partial payload, and a
        # crash mid-write would otherwise leave a truncated document that hashes
        # differently from its recorded sha256 — a corruption that looks like
        # tampering.
        temporary = path.with_name(path.name + ".partial")
        temporary.write_bytes(data)
        os.replace(temporary, path)

    def get(self, key: str) -> bytes:
        path = self._resolve(key)
        try:
            return path.read_bytes()
        except FileNotFoundError as exc:
            raise ObjectStoreError(f"no payload at {key!r}") from exc

    def delete(self, key: str) -> bool:
        path = self._resolve(key)
        try:
            path.unlink()
        except FileNotFoundError:
            # Idempotent by design: the retention sweeper and the cascade both
            # re-run, and a sweeper that raises on its second pass is a sweeper
            # someone disables.
            return False
        return True

    def exists(self, key: str) -> bool:
        return self._resolve(key).is_file()

    def iter_keys(self, prefix: str) -> Iterator[str]:
        base = self._resolve(prefix) if prefix else self._root
        if not base.exists():
            return
        for path in sorted(base.rglob("*")):
            if path.is_file() and not path.name.endswith(".partial"):
                yield path.relative_to(self._root).as_posix()

    def delete_prefix(self, prefix: str) -> int:
        """Remove everything under a prefix. Used by workspace deletion."""
        base = self._resolve(prefix)
        if not base.is_dir():
            return 0
        count = sum(1 for _ in self.iter_keys(prefix))
        shutil.rmtree(base)
        return count


class S3ObjectStore:
    """S3-compatible adapter behind the same interface.

    ``boto3`` is already a dependency for the CloudWatch source, so this adds
    nothing to install. Imported inside ``__init__`` rather than at module scope so
    the filesystem path does not pay for a client library it never uses — the same
    deferred-import pattern the PII agent uses for spaCy.
    """

    def __init__(self, bucket: str, *, endpoint: str | None = None) -> None:
        import boto3

        self._bucket = bucket
        self._client = boto3.client("s3", endpoint_url=endpoint)

    def put(self, key: str, data: bytes, *, content_type: str) -> None:
        # ServerSideEncryption is passed on every request rather than left to a
        # bucket default, because a bucket default is a setting someone else can
        # change and this call site is where [R14.2] is actually satisfied.
        self._client.put_object(
            Bucket=self._bucket,
            Key=key,
            Body=data,
            ContentType=content_type,
            ServerSideEncryption="AES256",
        )

    def get(self, key: str) -> bytes:
        from botocore.exceptions import ClientError

        try:
            response = self._client.get_object(Bucket=self._bucket, Key=key)
        except ClientError as exc:
            raise ObjectStoreError(f"no payload at {key!r}") from exc
        return response["Body"].read()

    def delete(self, key: str) -> bool:
        existed = self.exists(key)
        self._client.delete_object(Bucket=self._bucket, Key=key)
        return existed

    def exists(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._client.head_object(Bucket=self._bucket, Key=key)
        except ClientError:
            return False
        return True

    def iter_keys(self, prefix: str) -> Iterator[str]:
        paginator = self._client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self._bucket, Prefix=prefix):
            for item in page.get("Contents", []):
                yield item["Key"]

    def delete_prefix(self, prefix: str) -> int:
        count = 0
        for key in list(self.iter_keys(prefix)):
            self._client.delete_object(Bucket=self._bucket, Key=key)
            count += 1
        return count


def build_object_store(settings: ObjectStoreSettings | None = None) -> ObjectStore:
    """The configured adapter."""
    resolved = settings or object_store_settings()
    if resolved.kind == "filesystem":
        assert resolved.root is not None  # guaranteed by ObjectStoreSettings
        return FilesystemObjectStore(resolved.root)
    return S3ObjectStore(resolved.bucket or "", endpoint=resolved.endpoint)
