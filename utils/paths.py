"""Sandboxed filesystem path resolution.

Guardrails G8 and G9. Addresses review finding SEC-07.

The reviewed design described path validation only as "no traversal", and
Requirement 12.8's symlink handling had been dropped entirely. Neither an
extension allowlist nor a traversal check is sufficient on its own:

* ``~/.aws/sso/cache/*.json`` holds live bearer tokens and passes any
  extension allowlist.
* A symlink inside an approved root can point anywhere.
* Validating a path and then opening it is a time-of-check-to-time-of-use race:
  the file can be swapped in between.

So containment is verified **after** opening, against the open handle, and a
denylist applies regardless of which root a file sits in.

Ordering matters here. Cheap string checks run first, then the open, then
handle-based verification. The open is the point after which we hold a stable
reference; everything before it is advisory.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from fnmatch import fnmatch
from pathlib import Path, PurePath
from typing import IO

from utils.config import (
    MAX_FILE_SIZE_MB,
    SENSITIVE_PATH_DIRS,
    SENSITIVE_PATH_PATTERNS,
    SUPPORTED_FILE_EXTENSIONS,
    Settings,
)


class PathRefused(PermissionError):
    """Raised when a path is outside the sandbox or otherwise not permitted.

    Messages name the reason but not the resolved location of denied targets,
    so a refusal does not become a filesystem-probing oracle.
    """


@dataclass(frozen=True)
class ResolvedFile:
    """A file that passed every check, with its verified identity."""

    display_path: str  # filename only — never the full resolved path
    real_path: Path
    size_bytes: int
    extension: str
    inode_key: tuple  # (st_dev, st_ino) — identity of the opened handle

    @property
    def size_mb(self) -> float:
        return round(self.size_bytes / (1024 * 1024), 2)


def _is_traversal_shaped(raw: str) -> bool:
    """Reject obvious traversal before touching the filesystem."""
    normalized = raw.replace("\\", "/")

    for part in PurePath(normalized).parts:
        stripped = part.strip()
        # Any component that is nothing but dots is either traversal or a
        # padded variant of it (".." / "..." / "...."). None are legitimate
        # filenames, so refuse the whole class rather than enumerating forms.
        if len(stripped) >= 2 and set(stripped) == {"."}:
            return True

    # Percent-encoded forms that arrive via URL-ish inputs.
    lowered = normalized.lower()
    return any(token in lowered for token in ("%2e%2e", "..%2f", "%252e"))


def _matches_sensitive_name(path: Path) -> bool:
    """Filename-based denylist, applied regardless of scan root."""
    name = path.name.lower()
    return any(fnmatch(name, pattern) for pattern in SENSITIVE_PATH_PATTERNS)


def _within_sensitive_dir(path: Path) -> bool:
    """Directory-based denylist (``.aws``, ``.ssh``, ``.kube``, ...)."""
    parts = [p.lower() for p in path.parts]
    for entry in SENSITIVE_PATH_DIRS:
        segments = [s.lower() for s in entry.replace("\\", "/").split("/") if s]
        if len(segments) == 1:
            if segments[0] in parts:
                return True
        else:
            # Multi-segment entry such as ".config/gcloud"
            for i in range(len(parts) - len(segments) + 1):
                if parts[i : i + len(segments)] == segments:
                    return True
    return False


def _contained_in_roots(candidate: Path, roots: tuple[Path, ...]) -> bool:
    """True when ``candidate`` sits inside one of ``roots``.

    Both sides are already resolved. ``is_relative_to`` is used rather than
    string prefixing, which would treat ``/data-secret`` as inside ``/data``.
    """
    for root in roots:
        try:
            if candidate == root or candidate.is_relative_to(root):
                return True
        except ValueError:  # pragma: no cover - differing drives on Windows
            continue
    return False


def check_path_allowed(raw_path: str, settings: Settings) -> Path:
    """Pre-open validation. Returns the resolved candidate path.

    These checks are advisory: the path could change before the open. They exist
    to reject cheaply and to give clear errors. Authoritative verification
    happens in :func:`open_verified`.
    """
    if not raw_path or not raw_path.strip():
        raise PathRefused("no file path was provided")

    raw = raw_path.strip().strip('"').strip("'")

    if _is_traversal_shaped(raw):
        raise PathRefused(
            "path contains directory traversal and was refused"
        )

    candidate = Path(raw).expanduser()

    if not candidate.is_absolute():
        # Relative paths are ambiguous against a multi-root allowlist.
        raise PathRefused(
            "path must be absolute so it can be checked against the "
            "configured scan roots"
        )

    if _matches_sensitive_name(candidate) or _within_sensitive_dir(candidate):
        raise PathRefused(
            f"'{candidate.name}' matches the sensitive-path denylist "
            "(credentials, keys, and cloud config are never scanned)"
        )

    extension = candidate.suffix.lower()
    if extension not in SUPPORTED_FILE_EXTENSIONS:
        supported = ", ".join(sorted(SUPPORTED_FILE_EXTENSIONS))
        raise PathRefused(
            f"unsupported file type '{extension or candidate.name}'. "
            f"Supported: {supported}"
        )

    if not settings.scan_roots:
        raise PathRefused(
            "no scan roots are configured, so local file paths cannot be "
            "read. Set PII_AGENT_SCAN_ROOTS, or upload the file instead."
        )

    # Resolve to collapse symlinks and normalise case/separators, then contain.
    try:
        resolved = candidate.resolve()
    except OSError:
        raise PathRefused("path could not be resolved") from None

    if not _contained_in_roots(resolved, settings.scan_roots):
        raise PathRefused(
            "path resolves outside every configured scan root and was refused"
        )

    # Reject directories here rather than letting the open fail: on Windows,
    # opening a directory raises PermissionError, which would surface as a
    # misleading "permission denied" message.
    if resolved.is_dir():
        raise PathRefused(
            f"'{candidate.name}' is not a regular file "
            "(directories, pipes, and device files are refused)"
        )

    return resolved


def open_verified(
    raw_path: str, settings: Settings, *, max_size_mb: int | None = None
) -> tuple[IO[bytes], ResolvedFile]:
    """Open a file and verify containment against the open handle.

    This is the authoritative check. The sequence is deliberate:

    1. Pre-validate the path string (cheap rejections, clear errors).
    2. Open the handle — from here we hold a stable reference.
    3. ``fstat`` the handle to confirm it is a regular file.
    4. Re-resolve and re-verify containment, then confirm the resolved path
       still refers to the same object as the handle.

    Step 4 is what closes both symlink escape and the TOCTOU window: a file
    swapped between validation and open no longer matches the handle identity.

    Caller owns the returned handle and must close it.
    """
    candidate = check_path_allowed(raw_path, settings)
    limit_mb = MAX_FILE_SIZE_MB if max_size_mb is None else max_size_mb

    try:
        handle = candidate.open("rb")
    except FileNotFoundError:
        raise PathRefused(f"'{candidate.name}' was not found") from None
    except PermissionError:
        raise PathRefused(
            f"permission denied reading '{candidate.name}'"
        ) from None
    except OSError as exc:
        raise PathRefused(
            f"could not open '{candidate.name}' ({exc.__class__.__name__})"
        ) from None

    try:
        info = os.fstat(handle.fileno())

        # Regular files only. A FIFO would block forever; a device file could
        # produce unbounded output.
        if not stat.S_ISREG(info.st_mode):
            raise PathRefused(
                f"'{candidate.name}' is not a regular file "
                "(directories, pipes, and device files are refused)"
            )

        size_limit = limit_mb * 1024 * 1024
        if info.st_size > size_limit:
            raise PathRefused(
                f"'{candidate.name}' is {info.st_size / 1048576:.1f} MB, "
                f"over the {limit_mb} MB limit. Scan a smaller extract, or "
                f"raise MAX_FILE_SIZE_MB if the host can afford it."
            )

        # Re-verify after opening. If a symlink was swapped in, or the path was
        # replaced, the resolved location will differ or no longer be contained.
        try:
            post_open = candidate.resolve()
        except OSError:
            raise PathRefused("path could not be re-resolved after open") from None

        if not _contained_in_roots(post_open, settings.scan_roots):
            raise PathRefused(
                "path resolved outside the configured scan roots after "
                "opening and was refused"
            )

        # Confirm the resolved path still names the object we hold open.
        try:
            on_disk = os.stat(post_open)
        except OSError:
            raise PathRefused(
                "file changed while it was being opened and was refused"
            ) from None

        handle_key = (info.st_dev, info.st_ino)
        disk_key = (on_disk.st_dev, on_disk.st_ino)
        # st_ino is 0 on some Windows filesystems; only compare when meaningful.
        if info.st_ino and on_disk.st_ino and handle_key != disk_key:
            raise PathRefused(
                "file was substituted while it was being opened and was "
                "refused"
            )

        resolved_file = ResolvedFile(
            display_path=candidate.name,
            real_path=post_open,
            size_bytes=info.st_size,
            extension=candidate.suffix.lower(),
            inode_key=handle_key,
        )
        return handle, resolved_file

    except Exception:
        handle.close()
        raise


def list_scannable(
    settings: Settings, pattern: str = "*"
) -> list[ResolvedFile]:
    """Enumerate files under the configured roots that could be scanned.

    Applies the same denylist and extension rules, so the listing never
    advertises a file the reader would refuse.
    """
    found: list[ResolvedFile] = []
    for root in settings.scan_roots:
        if not root.is_dir():
            continue
        for path in sorted(root.rglob(pattern)):
            if not path.is_file():
                continue
            if path.suffix.lower() not in SUPPORTED_FILE_EXTENSIONS:
                continue
            if _matches_sensitive_name(path) or _within_sensitive_dir(path):
                continue
            try:
                info = path.stat()
            except OSError:  # pragma: no cover - race with deletion
                continue
            found.append(
                ResolvedFile(
                    display_path=str(path.relative_to(root)),
                    real_path=path,
                    size_bytes=info.st_size,
                    extension=path.suffix.lower(),
                    inode_key=(info.st_dev, info.st_ino),
                )
            )
    return found
