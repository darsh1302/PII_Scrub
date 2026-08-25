"""The data statement stays in step with the registry — task 4.5, `[R14.8]`.

`[R14.8]` wants a statement "maintained as part of the deliverable rather than as tribal
knowledge". A document is not maintained by being written once. This test is what makes
the requirement true: change the registry without regenerating, and the suite fails.
"""

from __future__ import annotations

from explorer.storage.classification import (
    REGISTRY,
    RETENTION_REQUIRED_CATEGORIES,
    TABLE_CATEGORY,
    render_data_statement,
)
from tests.paths import REPO_ROOT

STATEMENT = REPO_ROOT / "docs" / "05-data-statement.md"


def test_the_statement_exists():
    assert STATEMENT.is_file(), (
        "docs/05-data-statement.md is missing. Run:\n"
        "  python tools_dev/build_data_statement.py"
    )


def test_the_statement_on_disk_matches_the_registry():
    """The control that makes `[R14.8]` a live requirement rather than a document.

    Compared with line endings normalised, because Git may hand a contributor CRLF for
    a file committed with LF — and a failure about invisible characters teaches people
    to distrust the test rather than to regenerate the file.
    """
    on_disk = STATEMENT.read_text(encoding="utf-8").replace("\r\n", "\n")
    rendered = render_data_statement().replace("\r\n", "\n")

    assert on_disk == rendered, (
        "docs/05-data-statement.md is out of date with "
        "explorer/storage/classification.py. Run:\n"
        "  python tools_dev/build_data_statement.py"
    )


def test_every_category_appears_in_the_statement():
    rendered = render_data_statement()
    for classification in REGISTRY:
        assert f"`{classification.category}`" in rendered, classification.category


def test_every_table_appears_in_the_statement():
    rendered = render_data_statement()
    for table in TABLE_CATEGORY:
        assert f"`{table}`" in rendered, table


def test_the_statement_names_the_encryption_mechanism():
    """`[R14.2]` requires the mechanism to be named, not assumed.

    Including the uncomfortable part: the filesystem adapter does not encrypt
    individual objects, so on an unencrypted volume the payloads are plaintext. A
    statement that omitted that would be worse than none, because a reader would assume
    otherwise.
    """
    rendered = render_data_statement()

    assert "Encryption at rest" in rendered
    assert "whole-volume encryption" in rendered
    assert "plaintext on disk" in rendered
    assert "server-side encryption" in rendered


def test_the_statement_lists_the_startup_required_categories():
    rendered = render_data_statement()
    for category in RETENTION_REQUIRED_CATEGORIES:
        assert f"- `{category}`" in rendered, category


def test_the_statement_says_what_is_never_persisted():
    """The absences matter as much as the contents.

    Someone assessing this platform will ask where the API keys and the session tokens
    are stored, and "nowhere" needs to be written down.
    """
    rendered = render_data_statement()

    assert "never persists" in rendered
    assert "SHA-256" in rendered
    assert "R15.7" in rendered


def test_the_statement_is_in_the_docs_build():
    """Otherwise it exists as Markdown and never appears in the published set.

    The build's page list is hardcoded, which is deliberate — it also supplies nav
    labels and ordering — but a hardcoded list is one someone forgets to extend. This
    caught exactly that.
    """
    build_script = REPO_ROOT / "tools_dev" / "build_docs.py"
    assert "05-data-statement.md" in build_script.read_text(encoding="utf-8"), (
        "docs/05-data-statement.md is not in tools_dev/build_docs.py's PAGES list, so "
        "it will never be published as HTML"
    )
