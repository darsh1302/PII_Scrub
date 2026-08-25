"""Branch coverage for the sandbox error paths.

Guardrails G8, G9. These are the paths where an untested branch has the worst
consequence — a missed rejection is a sandbox escape — so each is exercised
explicitly even where the OS condition is awkward to reproduce.

Some conditions (FIFOs, mid-open substitution, cross-device paths) cannot be
created reliably on Windows. Those are simulated by patching the syscall, which
verifies our handling logic rather than the platform's behaviour. The distinction
is called out per test.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from pii_agent.utils.config import Settings
from pii_agent.utils.paths import (
    PathRefused,
    _contained_in_roots,
    _within_sensitive_dir,
    check_path_allowed,
    list_scannable,
    open_verified,
)


@pytest.fixture
def sandbox(tmp_path):
    root = tmp_path / "scanroot"
    root.mkdir()
    (root / "app.log").write_text("hello\n", encoding="utf-8", newline="")

    settings = Settings(
        openai_api_key="sk-test",
        token_vault_salt=b"salt",
        scan_roots=(root.resolve(),),
        audit_dir=tmp_path / "audit",
    )
    return settings, root


# ---------------------------------------------------------------------------
# Empty and whitespace input
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw", ["", "   ", "\t", "\n"])
def test_empty_path_is_refused(sandbox, raw):
    settings, _ = sandbox
    with pytest.raises(PathRefused) as exc:
        check_path_allowed(raw, settings)
    assert "no file path" in str(exc.value)


def test_quoted_path_is_unwrapped(sandbox):
    """Paths pasted from a shell often arrive quoted."""
    settings, root = sandbox
    resolved = check_path_allowed(f'"{root / "app.log"}"', settings)
    assert resolved.name == "app.log"


def test_single_quoted_path_is_unwrapped(sandbox):
    settings, root = sandbox
    resolved = check_path_allowed(f"'{root / 'app.log'}'", settings)
    assert resolved.name == "app.log"


# ---------------------------------------------------------------------------
# Multi-segment sensitive directory entries
# ---------------------------------------------------------------------------


def test_multi_segment_sensitive_dir_is_matched():
    """``.config/gcloud`` must match as a sequence, not as two loose names."""
    assert _within_sensitive_dir(Path("/home/u/.config/gcloud/creds.json"))
    assert _within_sensitive_dir(Path(r"C:\Users\u\.config\gcloud\x.json"))


def test_multi_segment_entry_does_not_match_when_split():
    """``.config/other`` and ``elsewhere/gcloud`` are not the denied sequence."""
    assert not _within_sensitive_dir(Path("/home/u/.config/other/x.json"))
    assert not _within_sensitive_dir(Path("/home/u/elsewhere/gcloud/x.json"))


def test_gcloud_config_path_is_refused_end_to_end(sandbox):
    settings, root = sandbox
    nested = root / ".config" / "gcloud"
    nested.mkdir(parents=True)
    target = nested / "credentials.json"
    target.write_text("{}", encoding="utf-8")

    with pytest.raises(PathRefused) as exc:
        check_path_allowed(str(target), settings)
    assert "denylist" in str(exc.value)


# ---------------------------------------------------------------------------
# Containment helper
# ---------------------------------------------------------------------------


def test_containment_returns_false_when_no_root_matches(tmp_path):
    outside = (tmp_path / "outside" / "f.log").resolve()
    roots = ((tmp_path / "a").resolve(), (tmp_path / "b").resolve())
    assert _contained_in_roots(outside, roots) is False


def test_containment_matches_the_root_itself(tmp_path):
    root = (tmp_path / "a").resolve()
    assert _contained_in_roots(root, (root,)) is True


def test_containment_handles_cross_drive_paths_without_raising(tmp_path):
    """``is_relative_to`` raises ValueError across Windows drives.

    Simulated so the handler is exercised on any platform.
    """
    class Hostile(type(tmp_path)):
        def is_relative_to(self, _other):  # type: ignore[override]
            raise ValueError("different drive")

    candidate = Hostile(str(tmp_path / "x.log"))
    assert _contained_in_roots(candidate, ((tmp_path / "root").resolve(),)) is False


# ---------------------------------------------------------------------------
# Open failure modes
# ---------------------------------------------------------------------------


def test_permission_denied_is_reported_by_name_only(sandbox, monkeypatch):
    """Simulated: reliably denying read access is awkward on Windows."""
    settings, root = sandbox
    target = root / "app.log"

    real_open = Path.open

    def denied(self, *args, **kwargs):
        if self.name == "app.log":
            raise PermissionError(13, "Permission denied")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)

    with pytest.raises(PathRefused) as exc:
        open_verified(str(target), settings)
    message = str(exc.value)
    assert "permission denied" in message
    assert "app.log" in message
    # Must not disclose the resolved location.
    assert str(root) not in message


def test_generic_os_error_on_open_is_wrapped(sandbox, monkeypatch):
    settings, root = sandbox
    real_open = Path.open

    def failing(self, *args, **kwargs):
        if self.name == "app.log":
            raise OSError(5, "I/O error")
        return real_open(self, *args, **kwargs)

    monkeypatch.setattr(Path, "open", failing)

    with pytest.raises(PathRefused) as exc:
        open_verified(str(root / "app.log"), settings)
    assert "could not open" in str(exc.value)
    assert "OSError" in str(exc.value)


def test_non_regular_file_is_refused_after_open(sandbox, monkeypatch):
    """FIFOs and device files.

    Simulated via fstat: a FIFO would block a read indefinitely, and creating
    one is not portable to Windows. The check itself must still be proven.
    """
    settings, root = sandbox
    real_fstat = os.fstat

    def fifo_like(fd):
        info = real_fstat(fd)
        fields = list(info)
        fields[0] = stat.S_IFIFO | 0o644  # st_mode
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", fifo_like)

    with pytest.raises(PathRefused) as exc:
        open_verified(str(root / "app.log"), settings)
    assert "not a regular file" in str(exc.value)


def test_handle_is_closed_when_a_post_open_check_fails(sandbox, monkeypatch):
    """A refusal must not leak the file handle."""
    settings, root = sandbox
    opened: list = []

    real_open = Path.open

    def tracking(self, *args, **kwargs):
        handle = real_open(self, *args, **kwargs)
        opened.append(handle)
        return handle

    monkeypatch.setattr(Path, "open", tracking)

    # Pass the pre-open containment check, fail the post-open one — otherwise
    # the file is never opened and the test proves nothing.
    calls = {"n": 0}

    def only_first_call_passes(_candidate, _roots):
        calls["n"] += 1
        return calls["n"] == 1

    monkeypatch.setattr("pii_agent.utils.paths._contained_in_roots", only_first_call_passes)

    with pytest.raises(PathRefused):
        open_verified(str(root / "app.log"), settings)

    assert opened, "test setup must have opened a handle"
    assert all(h.closed for h in opened)


# ---------------------------------------------------------------------------
# Post-open re-verification (G9)
# ---------------------------------------------------------------------------


def test_reresolve_failure_after_open_is_refused(sandbox, monkeypatch):
    settings, root = sandbox
    calls = {"n": 0}
    real_resolve = Path.resolve

    def flaky(self, *args, **kwargs):
        # First call is the pre-open check; fail the post-open one.
        if self.name == "app.log":
            calls["n"] += 1
            if calls["n"] > 1:
                raise OSError("vanished")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", flaky)

    with pytest.raises(PathRefused) as exc:
        open_verified(str(root / "app.log"), settings)
    assert "re-resolved after open" in str(exc.value)


def test_path_escaping_containment_after_open_is_refused(sandbox, monkeypatch):
    """The symlink-swap case: contained before the open, outside after."""
    settings, root = sandbox
    calls = {"n": 0}

    def only_first_call_passes(candidate, roots):
        calls["n"] += 1
        return calls["n"] == 1

    monkeypatch.setattr("pii_agent.utils.paths._contained_in_roots", only_first_call_passes)

    with pytest.raises(PathRefused) as exc:
        open_verified(str(root / "app.log"), settings)
    assert "outside the configured scan roots after" in str(exc.value)


def test_stat_failure_after_open_is_refused(sandbox, monkeypatch):
    """The file was removed between opening and re-checking.

    ``Path.resolve`` also calls ``os.stat`` internally, so the failure is armed
    only once ``os.fstat`` has run — which marks the start of the post-open
    block. Patching ``os.stat`` unconditionally would break resolution and never
    reach the branch under test.
    """
    settings, root = sandbox
    real_stat = os.stat
    real_fstat = os.fstat
    armed = {"yes": False}

    def arming_fstat(fd):
        armed["yes"] = True
        return real_fstat(fd)

    def vanishing(path, *args, **kwargs):
        if armed["yes"] and str(path).endswith("app.log"):
            raise OSError("gone")
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "fstat", arming_fstat)
    monkeypatch.setattr(os, "stat", vanishing)

    with pytest.raises(PathRefused) as exc:
        open_verified(str(root / "app.log"), settings)
    assert "changed while it was being opened" in str(exc.value)


def test_inode_mismatch_after_open_is_refused(sandbox, monkeypatch):
    """The TOCTOU detection itself.

    Simulated because winning the race deterministically is not feasible, and
    Windows locks the open file so the swap usually cannot happen at all.
    """
    settings, root = sandbox
    real_stat = os.stat

    def different_inode(path, *args, **kwargs):
        info = real_stat(path, *args, **kwargs)
        if str(path).endswith("app.log"):
            fields = list(info)
            fields[1] = (info.st_ino or 1) + 9999  # st_ino
            return os.stat_result(fields)
        return info

    monkeypatch.setattr(os, "stat", different_inode)

    with pytest.raises(PathRefused) as exc:
        open_verified(str(root / "app.log"), settings)
    assert "substituted while it was being opened" in str(exc.value)


def test_zero_inode_filesystems_do_not_trigger_false_substitution(
    sandbox, monkeypatch
):
    """st_ino is 0 on some Windows filesystems.

    Comparing it there would refuse every legitimate read, so the check is
    skipped when either side is 0.
    """
    settings, root = sandbox
    real_fstat = os.fstat
    real_stat = os.stat

    def zero_ino_fstat(fd):
        fields = list(real_fstat(fd))
        fields[1] = 0
        return os.stat_result(fields)

    def zero_ino_stat(path, *args, **kwargs):
        fields = list(real_stat(path, *args, **kwargs))
        fields[1] = 0
        return os.stat_result(fields)

    monkeypatch.setattr(os, "fstat", zero_ino_fstat)
    monkeypatch.setattr(os, "stat", zero_ino_stat)

    handle, resolved = open_verified(str(root / "app.log"), settings)
    try:
        assert resolved.display_path == "app.log"
    finally:
        handle.close()


# ---------------------------------------------------------------------------
# Enumeration branches
# ---------------------------------------------------------------------------


def test_list_scannable_skips_a_root_that_is_not_a_directory(tmp_path):
    bogus = tmp_path / "not_a_dir.txt"
    bogus.write_text("x", encoding="utf-8")
    settings = Settings(
        openai_api_key="k", scan_roots=(bogus,), audit_dir=tmp_path / "a"
    )
    assert list_scannable(settings) == []


def test_list_scannable_skips_directories_matching_the_pattern(sandbox):
    settings, root = sandbox
    (root / "nested.log").mkdir()
    names = {f.display_path for f in list_scannable(settings)}
    assert "nested.log" not in names
    assert "app.log" in names


def test_list_scannable_skips_unsupported_extensions(sandbox):
    settings, root = sandbox
    (root / "binary.exe").write_text("MZ", encoding="utf-8")
    names = {f.display_path for f in list_scannable(settings)}
    assert "binary.exe" not in names


def test_list_scannable_skips_sensitive_directories(sandbox):
    settings, root = sandbox
    secret_dir = root / ".ssh"
    secret_dir.mkdir()
    (secret_dir / "known_hosts.log").write_text("x", encoding="utf-8")

    paths = {f.display_path for f in list_scannable(settings)}
    assert not any(".ssh" in p for p in paths)


def test_list_scannable_honours_a_glob_pattern(sandbox):
    settings, root = sandbox
    (root / "other.json").write_text("{}", encoding="utf-8")

    names = {f.display_path for f in list_scannable(settings, "*.json")}
    assert names == {"other.json"}


def test_list_scannable_reports_relative_display_paths(sandbox):
    settings, root = sandbox
    nested = root / "sub" / "deep"
    nested.mkdir(parents=True)
    (nested / "trace.log").write_text("x", encoding="utf-8")

    names = {f.display_path for f in list_scannable(settings)}
    assert str(Path("sub") / "deep" / "trace.log") in names


def test_list_scannable_tolerates_a_file_removed_mid_scan(sandbox, monkeypatch):
    """Racing deletion must skip the entry, not abort the listing."""
    settings, root = sandbox
    (root / "second.log").write_text("x", encoding="utf-8")

    real_stat = Path.stat
    seen = {"second.log": 0}

    def vanishing(self, *args, **kwargs):
        # ``is_file()`` stats first. Let that succeed so the entry is considered,
        # then fail the explicit stat in the loop body — which is the branch
        # under test.
        if self.name == "second.log":
            seen["second.log"] += 1
            if seen["second.log"] > 1:
                raise OSError("removed")
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", vanishing)

    names = {f.display_path for f in list_scannable(settings)}
    assert "app.log" in names
    assert "second.log" not in names


# ---------------------------------------------------------------------------
# ResolvedFile reporting
# ---------------------------------------------------------------------------


def test_size_mb_is_rounded(sandbox):
    settings, root = sandbox
    big = root / "sized.log"
    big.write_bytes(b"x" * (1024 * 1024 + 512))

    handle, resolved = open_verified(str(big), settings)
    try:
        assert resolved.size_mb == pytest.approx(1.0, abs=0.01)
    finally:
        handle.close()


def test_explicit_max_size_overrides_the_default(sandbox):
    settings, root = sandbox
    target = root / "small.log"
    target.write_bytes(b"x" * 2048)

    with pytest.raises(PathRefused) as exc:
        open_verified(str(target), settings, max_size_mb=0)
    assert "over the 0 MB limit" in str(exc.value)


def test_unresolvable_path_is_refused_before_opening(sandbox, monkeypatch):
    """Pre-open resolution failure.

    Reached on malformed or unreachable paths — a dead network mount, or a name
    the OS rejects. Simulated because producing it reliably is platform-specific.
    """
    settings, root = sandbox
    real_resolve = Path.resolve

    def failing(self, *args, **kwargs):
        if self.name == "app.log":
            raise OSError("cannot resolve")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", failing)

    with pytest.raises(PathRefused) as exc:
        check_path_allowed(str(root / "app.log"), settings)
    assert "could not be resolved" in str(exc.value)
