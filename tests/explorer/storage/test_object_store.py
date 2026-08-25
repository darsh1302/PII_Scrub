"""The filesystem object store, including its containment — task 2.1.

No database needed, so these run everywhere. The S3 adapter is not tested here:
asserting against a mocked boto3 client would test the mock, and the parts that can
actually be wrong — that server-side encryption is requested, that a paginator is
used — are better read than stubbed. Task 15 exercises it against a real
S3-compatible endpoint.
"""

from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from explorer.storage.object_store import (
    FilesystemObjectStore,
    payload_key,
    workspace_prefix,
)
from explorer.storage.protocols import ObjectStore, ObjectStoreError


@pytest.fixture
def store(tmp_path: Path) -> FilesystemObjectStore:
    return FilesystemObjectStore(tmp_path / "objects")


def test_the_filesystem_adapter_satisfies_the_protocol(store):
    """Structural, not nominal — the adapter subclasses nothing."""
    assert isinstance(store, ObjectStore)


def test_put_then_get_round_trips_bytes_exactly(store):
    key = payload_key(workspace_id=uuid4(), kind="original", object_id=uuid4())
    # Bytes that would not survive a text round-trip: a BOM, a lone high byte, a
    # CRLF. Documents arrive as bytes and must leave as the same bytes, or a
    # recorded sha256 stops matching and corruption looks like tampering.
    payload = b"\xef\xbb\xbfline one\r\nline two\x00\xff"
    store.put(key, payload, content_type="text/plain")

    assert store.get(key) == payload


def test_getting_an_absent_key_raises(store):
    with pytest.raises(ObjectStoreError, match="no payload"):
        store.get("00000000-0000-0000-0000-000000000000/original/missing")


def test_delete_reports_whether_something_went(store):
    key = payload_key(workspace_id=uuid4(), kind="original", object_id=uuid4())
    store.put(key, b"x", content_type="text/plain")

    assert store.delete(key) is True
    # Idempotent on the second pass. The retention sweeper and the deletion cascade
    # both re-run, and a sweeper that raises the second time is a sweeper someone
    # disables.
    assert store.delete(key) is False


def test_keys_are_workspace_prefixed_and_opaque():
    workspace = uuid4()
    document = uuid4()
    key = payload_key(workspace_id=workspace, kind="original", object_id=document)

    assert key.startswith(f"{workspace}/")
    # No label in the key. A leaked key must not disclose
    # "2026-terminations.pdf" to whoever reads the log line it appears in.
    assert str(document) in key
    assert key == f"{workspace}/original/{document}"


def test_original_and_sanitized_are_distinct_kinds():
    """`[R14.4]` puts them on separate retention clocks.

    A clock cannot be applied to a distinction the key does not record, so the
    separation has to exist here rather than only in the database.
    """
    workspace, identifier = uuid4(), uuid4()
    original = payload_key(workspace_id=workspace, kind="original", object_id=identifier)
    sanitized = payload_key(
        workspace_id=workspace, kind="sanitized", object_id=identifier
    )
    assert original != sanitized


def test_an_unknown_kind_is_refused():
    with pytest.raises(ValueError, match="unknown payload kind"):
        payload_key(workspace_id=uuid4(), kind="temporary", object_id=uuid4())


@pytest.mark.parametrize(
    "key",
    [
        "../escaped",
        "a/../../escaped",
        "/absolute",
        "c:\\windows\\system32",
        "",
    ],
)
def test_keys_escaping_the_root_are_refused(store, key):
    """Containment is checked on the resolved path, not the string.

    ``a/../../b`` contains no suspicious character and resolves outside the root, so
    a substring check would pass it. Keys come from ``payload_key`` today, but an
    adapter that is only safe when its caller is correct is not safe.
    """
    with pytest.raises(ObjectStoreError):
        store.put(key, b"x", content_type="text/plain")


def test_a_partial_write_is_never_visible(store, monkeypatch):
    """Write-then-rename, asserted by making the rename fail.

    A reader must never observe a truncated payload: it would hash differently from
    the recorded sha256, and that reads as tampering rather than as a crash.
    """
    key = payload_key(workspace_id=uuid4(), kind="original", object_id=uuid4())

    def exploding_replace(src, dst):
        raise OSError("interrupted")

    monkeypatch.setattr("explorer.storage.object_store.os.replace", exploding_replace)

    with pytest.raises(OSError, match="interrupted"):
        store.put(key, b"half a document", content_type="text/plain")

    assert not store.exists(key)


def test_partial_files_are_not_listed(store):
    """A leftover .partial must not look like a payload to the orphan check."""
    workspace = uuid4()
    key = payload_key(workspace_id=workspace, kind="original", object_id=uuid4())
    store.put(key, b"real", content_type="text/plain")

    leftover = Path(store._resolve(key).parent / "abandoned.partial")  # noqa: SLF001
    leftover.write_bytes(b"junk")

    listed = list(store.iter_keys(workspace_prefix(workspace)))
    assert listed == [key]


def test_iter_keys_does_not_cross_the_workspace_prefix(store):
    mine, theirs = uuid4(), uuid4()
    my_key = payload_key(workspace_id=mine, kind="original", object_id=uuid4())
    their_key = payload_key(workspace_id=theirs, kind="original", object_id=uuid4())
    store.put(my_key, b"a", content_type="text/plain")
    store.put(their_key, b"b", content_type="text/plain")

    assert list(store.iter_keys(workspace_prefix(mine))) == [my_key]


def test_delete_prefix_removes_a_whole_workspace(store):
    """`[R14.5]`, the object-store half of workspace deletion."""
    mine, theirs = uuid4(), uuid4()
    for i in range(3):
        store.put(
            payload_key(workspace_id=mine, kind="original", object_id=uuid4()),
            f"doc {i}".encode(),
            content_type="text/plain",
        )
    survivor = payload_key(workspace_id=theirs, kind="original", object_id=uuid4())
    store.put(survivor, b"theirs", content_type="text/plain")

    removed = store.delete_prefix(workspace_prefix(mine))

    assert removed == 3
    assert list(store.iter_keys(workspace_prefix(mine))) == []
    assert store.exists(survivor)


def test_overwriting_a_key_replaces_the_payload(store):
    key = payload_key(workspace_id=uuid4(), kind="sanitized", object_id=uuid4())
    store.put(key, b"first", content_type="text/plain")
    store.put(key, b"second", content_type="text/plain")

    assert store.get(key) == b"second"
