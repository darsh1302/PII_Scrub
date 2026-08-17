"""Guardrails G8 and G9 — filesystem sandbox.

Addresses review finding SEC-07. The reviewed design described path validation
only as "no traversal", and symlink handling from Requirement 12.8 had been
dropped. Neither an extension allowlist nor a traversal check suffices:
``~/.aws/sso/cache/*.json`` holds live bearer tokens and passes both.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from utils.config import Settings
from utils.paths import PathRefused, check_path_allowed, list_scannable, open_verified


LOG_BODY = "2026-08-16 INFO hello\n"


@pytest.fixture
def sandbox(tmp_path):
    """A scan root with one allowed file, plus an out-of-root secret."""
    root = tmp_path / "scanroot"
    root.mkdir()
    # newline="" so byte length matches the string: Windows would otherwise
    # translate \n to \r\n and shift every size assertion by one.
    (root / "app.log").write_text(LOG_BODY, encoding="utf-8", newline="")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secrets.log").write_text(
        "API_KEY=sk-live-real\n", encoding="utf-8", newline=""
    )

    settings = Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"salt",
        scan_roots=(root.resolve(),),
        audit_dir=tmp_path / "audit",
    )
    return settings, root, outside


# ---------------------------------------------------------------------------
# Containment
# ---------------------------------------------------------------------------


def test_file_inside_scan_root_is_allowed(sandbox):
    settings, root, _ = sandbox
    resolved = check_path_allowed(str(root / "app.log"), settings)
    assert resolved.name == "app.log"


def test_file_outside_scan_root_is_refused(sandbox):
    settings, _, outside = sandbox
    with pytest.raises(PathRefused) as exc:
        check_path_allowed(str(outside / "secrets.log"), settings)
    assert "outside every configured scan root" in str(exc.value)


@pytest.mark.parametrize(
    "traversal",
    [
        r"..\..\..\Windows\System32\drivers\etc\hosts",
        "../../../etc/passwd",
        "subdir/../../../../outside/secrets.log",
        "%2e%2e/secrets.log",
        "....//....//secrets.log",
    ],
)
def test_traversal_shapes_are_refused(sandbox, traversal):
    settings, root, _ = sandbox
    with pytest.raises(PathRefused):
        check_path_allowed(str(root / traversal), settings)


def test_sibling_directory_with_shared_prefix_is_refused(tmp_path):
    """String prefixing would treat /data-secret as inside /data."""
    allowed = tmp_path / "data"
    allowed.mkdir()
    sneaky = tmp_path / "data-secret"
    sneaky.mkdir()
    (sneaky / "leak.log").write_text("x", encoding="utf-8")

    settings = Settings(
        openai_api_key="k", scan_roots=(allowed.resolve(),), audit_dir=tmp_path / "a"
    )
    with pytest.raises(PathRefused):
        check_path_allowed(str(sneaky / "leak.log"), settings)


def test_relative_path_is_refused(sandbox):
    """Ambiguous against a multi-root allowlist."""
    settings, _, _ = sandbox
    with pytest.raises(PathRefused) as exc:
        check_path_allowed("app.log", settings)
    assert "absolute" in str(exc.value)


def test_empty_scan_roots_refuses_all_local_paths(tmp_path):
    """Empty allowlist means uploads only — never 'whole filesystem'."""
    target = tmp_path / "app.log"
    target.write_text("x", encoding="utf-8")
    settings = Settings(openai_api_key="k", scan_roots=(), audit_dir=tmp_path / "a")
    with pytest.raises(PathRefused) as exc:
        check_path_allowed(str(target), settings)
    assert "no scan roots are configured" in str(exc.value)


# ---------------------------------------------------------------------------
# Sensitive-path denylist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        ".env",
        ".env.production",
        "id_rsa",
        "id_ed25519",
        "server.pem",
        "cert.pfx",
        "signing.key",
        "credentials",
    ],
)
def test_sensitive_filenames_refused_even_inside_scan_root(sandbox, name):
    settings, root, _ = sandbox
    target = root / name
    target.write_text("secret", encoding="utf-8")
    with pytest.raises(PathRefused) as exc:
        check_path_allowed(str(target), settings)
    assert "denylist" in str(exc.value)


@pytest.mark.parametrize("directory", [".aws", ".ssh", ".kube", ".gnupg", ".docker"])
def test_sensitive_directories_refused(sandbox, directory):
    """The extension allowlist does not save us here.

    ~/.aws/sso/cache/*.json contains live bearer tokens and is a .json file.
    """
    settings, root, _ = sandbox
    nested = root / directory / "cache"
    nested.mkdir(parents=True)
    target = nested / "token.json"
    target.write_text('{"accessToken":"real"}', encoding="utf-8")

    with pytest.raises(PathRefused) as exc:
        check_path_allowed(str(target), settings)
    assert "denylist" in str(exc.value)


def test_aws_sso_cache_json_is_refused(sandbox):
    """The concrete case named in the review."""
    settings, root, _ = sandbox
    cache = root / ".aws" / "sso" / "cache"
    cache.mkdir(parents=True)
    target = cache / "abc123.json"
    target.write_text('{"accessToken":"live-bearer"}', encoding="utf-8")

    with pytest.raises(PathRefused):
        check_path_allowed(str(target), settings)


# ---------------------------------------------------------------------------
# Extensions and file kinds
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("name", ["app.exe", "lib.dll", "archive.zip", "notes"])
def test_unsupported_extensions_refused(sandbox, name):
    settings, root, _ = sandbox
    (root / name).write_text("x", encoding="utf-8")
    with pytest.raises(PathRefused) as exc:
        check_path_allowed(str(root / name), settings)
    assert "unsupported file type" in str(exc.value)


def test_directory_is_refused(sandbox):
    """A directory named like a log file must be refused clearly.

    Opening a directory on Windows raises PermissionError, which would surface
    as a misleading "permission denied", so the kind check happens first.
    """
    settings, root, _ = sandbox
    subdir = root / "logs.log"
    subdir.mkdir()
    with pytest.raises(PathRefused) as exc:
        open_verified(str(subdir), settings)
    assert "not a regular file" in str(exc.value)


def test_oversize_file_is_refused(sandbox):
    settings, root, _ = sandbox
    big = root / "huge.log"
    big.write_text("x" * 4096, encoding="utf-8")
    with pytest.raises(PathRefused) as exc:
        open_verified(str(big), settings, max_size_mb=0)
    assert "over the" in str(exc.value)


def test_missing_file_is_refused_by_name_only(sandbox):
    """The error names the file but not its resolved location."""
    settings, root, _ = sandbox
    with pytest.raises(PathRefused) as exc:
        open_verified(str(root / "absent.log"), settings)
    assert "absent.log" in str(exc.value)
    assert "was not found" in str(exc.value)


# ---------------------------------------------------------------------------
# Symlink escape (G9)
# ---------------------------------------------------------------------------


def _can_symlink(tmp_path) -> bool:
    """Windows requires privilege or developer mode for symlinks."""
    probe = tmp_path / "_probe"
    target = tmp_path / "_target"
    target.write_text("x", encoding="utf-8")
    try:
        probe.symlink_to(target)
        probe.unlink()
        return True
    except (OSError, NotImplementedError):
        return False


def test_symlink_pointing_outside_root_is_refused(sandbox, tmp_path):
    settings, root, outside = sandbox
    if not _can_symlink(tmp_path):
        pytest.skip("symlink creation not permitted on this host")

    link = root / "innocent.log"
    link.symlink_to(outside / "secrets.log")

    with pytest.raises(PathRefused) as exc:
        check_path_allowed(str(link), settings)
    assert "outside" in str(exc.value)


def test_symlinked_directory_escape_is_refused(sandbox, tmp_path):
    settings, root, outside = sandbox
    if not _can_symlink(tmp_path):
        pytest.skip("symlink creation not permitted on this host")

    link_dir = root / "shortcut"
    try:
        link_dir.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("directory symlink not permitted")

    with pytest.raises(PathRefused):
        check_path_allowed(str(link_dir / "secrets.log"), settings)


# ---------------------------------------------------------------------------
# TOCTOU (G9)
# ---------------------------------------------------------------------------


def test_open_verified_reads_the_validated_handle(sandbox):
    """Containment is re-checked against the open handle, not the path."""
    settings, root, _ = sandbox
    handle, resolved = open_verified(str(root / "app.log"), settings)
    try:
        assert handle.read() == LOG_BODY.encode("utf-8")
        assert resolved.display_path == "app.log"
    finally:
        handle.close()


def test_substitution_after_open_does_not_affect_read_content(sandbox):
    """The handle is stable: replacing the path does not change what we read.

    This is what makes the TOCTOU window non-exploitable — bytes come from the
    handle opened during validation, not from a re-resolved path.

    Windows holds a mandatory lock on an open file, so the substitution itself
    usually fails there. That is a stronger outcome than the check we are
    asserting, so either result is acceptable.
    """
    settings, root, outside = sandbox
    target = root / "app.log"

    handle, _ = open_verified(str(target), settings)
    try:
        substituted = False
        try:
            target.unlink()
            try:
                target.symlink_to(outside / "secrets.log")
            except (OSError, NotImplementedError):
                target.write_text(
                    "API_KEY=sk-live-real\n", encoding="utf-8", newline=""
                )
            substituted = True
        except OSError:
            # Windows refused the swap because the handle is open.
            pass

        content = handle.read()
        assert b"sk-live-real" not in content
        assert content == LOG_BODY.encode("utf-8")
        _ = substituted
    finally:
        handle.close()


def test_resolved_file_reports_size_and_extension(sandbox):
    settings, root, _ = sandbox
    handle, resolved = open_verified(str(root / "app.log"), settings)
    try:
        assert resolved.size_bytes == len(LOG_BODY.encode("utf-8"))
        assert resolved.extension == ".log"
        assert resolved.size_mb == 0.0
    finally:
        handle.close()


# ---------------------------------------------------------------------------
# Enumeration
# ---------------------------------------------------------------------------


def test_list_scannable_excludes_denylisted_and_unsupported(sandbox):
    """The listing must never advertise a file the reader would refuse."""
    settings, root, _ = sandbox
    (root / ".env").write_text("KEY=v", encoding="utf-8")
    (root / "app.exe").write_text("MZ", encoding="utf-8")
    (root / "data.json").write_text("{}", encoding="utf-8")

    names = {f.display_path for f in list_scannable(settings)}
    assert "app.log" in names
    assert "data.json" in names
    assert ".env" not in names
    assert "app.exe" not in names


def test_list_scannable_is_empty_without_roots(tmp_path):
    settings = Settings(openai_api_key="k", scan_roots=(), audit_dir=tmp_path / "a")
    assert list_scannable(settings) == []
