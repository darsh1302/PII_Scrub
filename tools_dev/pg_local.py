"""Manage a local PostgreSQL instance for development, inside the repository.

    python tools_dev/pg_local.py install
    python tools_dev/pg_local.py start | stop | status
    python tools_dev/pg_local.py psql -- -c "select version()"

Why the portable binaries rather than the installer
---------------------------------------------------

The EnterpriseDB graphical installer needs administrator rights, registers a
Windows service, and puts a cluster under ``C:\\Program Files``. All three are
wrong for this project.

Elevation cannot be scripted without a UAC prompt, so a contributor following the
README would hit an interactive dialog. A machine-wide service on port 5432 collides
with any other Postgres the developer already runs. And a cluster outside the
repository is state the project cannot clean up, which is the same problem
``var/`` exists to solve for the audit trail and the scan workspace.

The binaries archive needs no elevation, so everything lands under ``var/`` —
gitignored in full — and the instance listens on a non-default port so it cannot be
confused with a system one.

What this is not
----------------

Not a production deployment. Trust authentication is deliberately *not* used, even
locally: the port is loopback-only, but a trust-auth cluster is one
``listen_addresses`` edit away from being open, and that edit is usually made while
debugging something else. The password lands in ``.env``, which is already the file
holding the OpenAI key and the token vault salt.

CI does not use this script. GitHub Actions provides Postgres as a service
container, which is simpler there and exercises the same wire protocol.
"""

from __future__ import annotations

import argparse
import os
import secrets
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# 18.2 is the current release. Pinned rather than "latest" for the same reason
# requirements.txt is pinned: a server version change can change planner
# behaviour, and a test that passes on one and fails on another is a bad afternoon.
PG_VERSION = "18.2-1"
PG_URL = (
    f"https://get.enterprisedb.com/postgresql/"
    f"postgresql-{PG_VERSION}-windows-x64-binaries.zip"
)

VAR = REPO_ROOT / "var"
DOWNLOAD = VAR / "tmp" / f"postgresql-{PG_VERSION}-x64.zip"
INSTALL_DIR = VAR / "pgsql"           # the archive's own pgsql/ root lands here
EXTRACTED_MARKER = VAR / "pgsql" / ".extracted"
DATA_DIR = VAR / "pgdata"

WANTED_SUBDIRS = ("bin", "lib", "share", "include")
"""What the server needs. Deliberately excludes ``pgAdmin 4`` and
``StackBuilder``: unused here, two thirds of the download, and pgAdmin's bundled
Python has paths long enough that Windows cannot delete them afterwards."""
LOG_FILE = VAR / "pg_server.log"
PWFILE = VAR / ".pg_superuser_password"
"""Deliberately outside DATA_DIR. ``initdb`` refuses a non-empty data directory, so
a credential file written there before initialisation makes the install fail with
"directory is not empty" — which reads like a stale cluster rather than a file the
script itself just created."""

PORT = 5433
"""Not 5432. A developer with a system Postgres should not have this instance
silently shadow it, and a connection string that works by accident is worse than
one that fails."""

SUPERUSER = "explorer_admin"
DEV_DB = "explorer_dev"
TEST_DB = "explorer_test"


def _rmtree_windows(path: Path) -> None:
    """Delete a tree that ``shutil.rmtree`` refuses.

    ``rmtree`` raises ``WinError 145`` on directories whose children exceed the
    Windows path limit, which is not a permissions problem and not fixed by
    retrying. The extended-length prefix bypasses the limit.
    """
    try:
        shutil.rmtree(path)
        return
    except OSError:
        pass

    long_path = f"\\\\?\\{path.resolve()}"
    result = subprocess.run(
        ["cmd", "/c", "rmdir", "/s", "/q", long_path],
        capture_output=True,
        text=True,
    )
    if path.exists():
        raise SystemExit(
            f"could not remove {path}: {result.stderr.strip() or 'unknown error'}\n"
            f"Delete it manually and re-run."
        )


def _bin(name: str) -> Path:
    exe = INSTALL_DIR / "bin" / f"{name}.exe"
    if not exe.is_file():
        raise SystemExit(
            f"{name} not found at {exe}\nRun: python tools_dev/pg_local.py install"
        )
    return exe


def _run(args: list[str | Path], **kw) -> subprocess.CompletedProcess:
    """Run with the install's own lib directory reachable.

    The archive's binaries resolve their DLLs relative to ``bin``, so invoking
    them by absolute path from another directory works, but only because Windows
    searches the executable's directory first. Being explicit avoids depending on
    that.
    """
    env = dict(os.environ)
    env["PATH"] = f"{INSTALL_DIR / 'bin'};{env.get('PATH', '')}"
    return subprocess.run([str(a) for a in args], env=env, **kw)


def _password() -> str:
    """Read the generated superuser password, or make one."""
    if PWFILE.is_file():
        return PWFILE.read_text(encoding="utf-8").strip()
    pw = secrets.token_urlsafe(24)
    PWFILE.parent.mkdir(parents=True, exist_ok=True)
    PWFILE.write_text(pw, encoding="utf-8")
    return pw


def _database_url(database: str) -> str:
    return (
        f"postgresql://{SUPERUSER}:{_password()}@127.0.0.1:{PORT}/{database}"
    )


# ---------------------------------------------------------------------------
# install
# ---------------------------------------------------------------------------
def _download() -> None:
    if DOWNLOAD.is_file() and DOWNLOAD.stat().st_size > 100_000_000:
        print(f"  archive already present ({DOWNLOAD.stat().st_size / 1e6:.0f} MB)")
        return

    DOWNLOAD.parent.mkdir(parents=True, exist_ok=True)
    print(f"  downloading {PG_URL}")

    partial = DOWNLOAD.with_suffix(".part")
    with urllib.request.urlopen(PG_URL, timeout=120) as resp:  # noqa: S310
        total = int(resp.headers.get("Content-Length", 0))
        done = 0
        with partial.open("wb") as fh:
            while chunk := resp.read(1 << 20):
                fh.write(chunk)
                done += len(chunk)
                if total:
                    pct = 100 * done / total
                    print(f"\r  {done / 1e6:6.0f} / {total / 1e6:.0f} MB  {pct:4.1f}%",
                          end="", flush=True)
    print()
    partial.replace(DOWNLOAD)


def cmd_install(_: argparse.Namespace) -> int:
    print(f"Installing PostgreSQL {PG_VERSION} under {VAR}")
    _download()

    # A completion marker, not a probe for one binary. An interrupted extractall
    # leaves a tree that has bin/initdb.exe but no share/postgres.bki, and initdb
    # then fails with "corrupted installation" pointing at the data directory —
    # which is not where the problem is. Cost half an hour to diagnose once.
    if EXTRACTED_MARKER.is_file():
        print("  binaries already extracted")
    else:
        if INSTALL_DIR.is_dir():
            print(f"  removing incomplete extraction at {INSTALL_DIR}")
            _rmtree_windows(INSTALL_DIR)
        print(f"  extracting to {INSTALL_DIR}")
        # The archive contains a single top-level pgsql/ directory, so extracting
        # to var/ produces var/pgsql. Only the server directories are taken:
        # pgAdmin 4 and StackBuilder are two thirds of the archive, are not used
        # here, and pgAdmin bundles its own Python whose site-packages paths
        # exceed the Windows path limit — which makes the directory undeletable by
        # ordinary means once written.
        with zipfile.ZipFile(DOWNLOAD) as zf:
            wanted = [
                n
                for n in zf.namelist()
                if n.startswith(tuple(f"pgsql/{d}/" for d in WANTED_SUBDIRS))
            ]
            if not wanted:
                raise SystemExit(
                    "archive layout unexpected — no pgsql/bin/ entries found"
                )
            zf.extractall(VAR, members=wanted)
        if not (INSTALL_DIR / "share" / "postgres.bki").is_file():
            raise SystemExit(
                f"extraction finished but {INSTALL_DIR / 'share' / 'postgres.bki'} "
                f"is absent — the archive may be truncated. Delete {DOWNLOAD} and "
                f"re-run install."
            )
        EXTRACTED_MARKER.write_text(PG_VERSION, encoding="utf-8")

    if (DATA_DIR / "PG_VERSION").is_file():
        print(f"  cluster already initialised at {DATA_DIR}")
    else:
        print(f"  initdb at {DATA_DIR}")
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        pw_path = VAR / "tmp" / ".initpw"
        pw_path.parent.mkdir(parents=True, exist_ok=True)
        pw_path.write_text(_password(), encoding="utf-8")
        try:
            result = _run(
                [
                    _bin("initdb"),
                    "-D", DATA_DIR,
                    "-U", SUPERUSER,
                    "--auth-local=scram-sha-256",
                    "--auth-host=scram-sha-256",
                    f"--pwfile={pw_path}",
                    "-E", "UTF8",
                    "--locale=C",
                ],
                capture_output=True,
                text=True,
            )
        finally:
            pw_path.unlink(missing_ok=True)

        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            return result.returncode

    _harden_config()
    print("\nInstalled. Next: python tools_dev/pg_local.py start")
    return 0


def _harden_config() -> None:
    """Loopback-only, non-default port, and no more connections than needed.

    ``listen_addresses`` is set explicitly rather than left at its default. The
    default for the binaries archive is already localhost, but an explicit line in
    the file is the difference between a property that holds and one that happens
    to hold.
    """
    conf = DATA_DIR / "postgresql.auto.conf"
    settings = "\n".join(
        [
            "# Written by tools_dev/pg_local.py — development instance.",
            "listen_addresses = '127.0.0.1'",
            f"port = {PORT}",
            "max_connections = 40",
            "fsync = off",
            "# fsync off is safe here and only here: this cluster holds nothing",
            "# that matters. Losing it costs one `pg_local.py install`.",
            "synchronous_commit = off",
            "full_page_writes = off",
            "log_min_duration_statement = 500",
        ]
    )
    conf.write_text(settings + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# start / stop / status
# ---------------------------------------------------------------------------
def cmd_start(_: argparse.Namespace) -> int:
    if _is_running():
        print(f"already running on port {PORT}")
        # Still ensure the databases. An early return here meant that a server
        # left running from a previous attempt could never acquire them, and
        # `start` reported success against a cluster with no explorer databases.
        _ensure_databases()
        _print_urls()
        return 0

    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)

    # Deliberately a file handle rather than capture_output. pg_ctl spawns the
    # postmaster, which inherits whatever stdio it is given and holds it for the
    # life of the server. With a pipe, subprocess.run waits for EOF that never
    # arrives and the start command hangs after the server is already up — which
    # looks exactly like a failure to start.
    ctl_log = VAR / "tmp" / "pg_ctl.log"
    ctl_log.parent.mkdir(parents=True, exist_ok=True)
    with ctl_log.open("w", encoding="utf-8") as sink:
        result = _run(
            [_bin("pg_ctl"), "-D", DATA_DIR, "-l", LOG_FILE, "-w", "start"],
            stdout=sink,
            stderr=subprocess.STDOUT,
        )

    print(ctl_log.read_text(encoding="utf-8", errors="replace").strip())
    if result.returncode != 0:
        if LOG_FILE.is_file():
            print("\n--- server log tail ---")
            print("\n".join(LOG_FILE.read_text(errors="replace").splitlines()[-25:]))
        return result.returncode

    _ensure_databases()
    _print_urls()
    return 0


def cmd_stop(_: argparse.Namespace) -> int:
    result = _run(
        [_bin("pg_ctl"), "-D", DATA_DIR, "-m", "fast", "-w", "stop"],
        capture_output=True,
        text=True,
    )
    print((result.stdout or result.stderr).strip())
    return 0 if result.returncode == 0 else result.returncode


def _is_running() -> bool:
    result = _run(
        [_bin("pg_ctl"), "-D", DATA_DIR, "status"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def cmd_status(_: argparse.Namespace) -> int:
    running = _is_running()
    print(f"data dir : {DATA_DIR}")
    print(f"port     : {PORT}")
    print(f"status   : {'running' if running else 'stopped'}")
    if running:
        _print_urls()
    return 0 if running else 1


def _ensure_databases() -> None:
    """Create the dev and test databases if absent.

    Two databases, not one. The test suite truncates and drops freely; sharing a
    database with development data would mean a test run destroys whatever was
    being looked at, which is how people stop running the tests.
    """
    # Through psycopg rather than the psql binary. The psql route failed here
    # without printing anything, which is the worst kind of failure: the script
    # reported success and the databases did not exist. psycopg raises.
    import psycopg

    with psycopg.connect(_database_url("postgres"), autocommit=True) as conn:
        existing = {
            row[0] for row in conn.execute("select datname from pg_database")
        }
        for name in (DEV_DB, TEST_DB):
            if name in existing:
                continue
            # Identifier interpolation, so it cannot be parameterised. The values
            # are module constants, not input.
            conn.execute(f'create database "{name}"')  # noqa: S608
            print(f"  created database {name}")


def _print_urls() -> None:
    print()
    print("Add to .env (both, so the suite never touches development data):")
    print(f"EXPLORER_DATABASE_URL={_database_url(DEV_DB)}")
    print(f"EXPLORER_TEST_DATABASE_URL={_database_url(TEST_DB)}")


def cmd_psql(args: argparse.Namespace) -> int:
    result = _run([_bin("psql"), _database_url(args.database), *args.rest])
    return result.returncode


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("install").set_defaults(func=cmd_install)
    sub.add_parser("start").set_defaults(func=cmd_start)
    sub.add_parser("stop").set_defaults(func=cmd_stop)
    sub.add_parser("status").set_defaults(func=cmd_status)

    p_psql = sub.add_parser("psql")
    p_psql.add_argument("--database", default=DEV_DB)
    p_psql.add_argument("rest", nargs=argparse.REMAINDER)
    p_psql.set_defaults(func=cmd_psql)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
