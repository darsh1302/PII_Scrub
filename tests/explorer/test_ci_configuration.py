"""Guards on the test suite's own configuration.

A skipped security test reads as a passing one in a summary line. These assert that
the accommodations made for local development cannot silently apply in CI.

Deliberately a test file rather than part of ``conftest.py``: pytest does not collect
test functions from conftest modules, so a guard placed there would never run while
looking as though it did.
"""

from __future__ import annotations

import pytest

from tests.explorer.conftest import ci_is_set, database_available


def test_a_database_is_configured_in_ci():
    """Without this, forgetting the Postgres service turns the storage suite off.

    Every isolation assertion — the cross-workspace parenting constraints, the
    cascade completeness checks, and later the full isolation matrix `[R15.4]` — is
    skipped when no database URL is present. The run stays green. This is the same
    failure mode as a renamed no-LLM test that no longer imports anything, and it is
    worth one explicit test to close.
    """
    if not ci_is_set():
        pytest.skip("not running in CI")

    assert database_available(), (
        "CI is set but EXPLORER_TEST_DATABASE_URL is not. The storage and "
        "isolation tests would silently skip, which reads as success. Configure "
        "the Postgres service in .github/workflows/tests.yml."
    )


def test_the_storage_suite_is_not_entirely_skipped_locally_without_notice():
    """Report the skip loudly enough to notice, without failing a local run.

    Not an assertion — a contributor exploring the repository should not be blocked
    on installing Postgres. But a warning in the output is the difference between
    knowing the storage layer is untested on this machine and assuming it passed.
    """
    if database_available() or ci_is_set():
        return

    pytest.skip(
        "no test database configured — the storage, cascade and cross-workspace "
        "suites did not run on this machine. python tools_dev/pg_local.py install"
    )
