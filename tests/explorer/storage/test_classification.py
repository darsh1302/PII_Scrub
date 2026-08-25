"""The classification registry — Requirement 14.1, task 2.3.

The load-bearing test here is
:func:`test_every_table_created_by_migrations_is_classified`. It runs against a live
database rather than parsing the SQL, so it sees what the schema actually is rather
than what the migration file appears to say.
"""

from __future__ import annotations

import pytest

from explorer.storage.classification import (
    BY_CATEGORY,
    CONTENT_CATEGORIES,
    REGISTRY,
    RETENTION_REQUIRED_CATEGORIES,
    TABLE_CATEGORY,
    Classification,
    DataClass,
    RetentionDriver,
    Store,
    classify,
)
from explorer.storage.engine import Database
from tests.explorer.conftest import requires_database


def test_every_category_appears_once():
    categories = [c.category for c in REGISTRY]
    assert len(categories) == len(set(categories)), (
        "a duplicated category means one of the two classifications is being "
        "ignored, and which one depends on iteration order"
    )


def test_every_classification_states_a_rationale():
    for classification in REGISTRY:
        assert classification.rationale.strip()


def test_registry_covers_all_four_required_classes():
    """`[R14.1]` names four categories. All four should be in use.

    An unused class usually means data was filed under a neighbouring one to avoid
    a decision — most often content recorded as derived metadata.
    """
    present = {c.data_class for c in REGISTRY}
    assert present == set(DataClass)


def test_content_cannot_be_retained_indefinitely():
    """The construction-time guard, exercised.

    Marking something content and giving it indefinite retention is exactly the
    unbounded default `[R14.3]` refuses, and it would pass every other check here.
    """
    with pytest.raises(ValueError, match="indefinitely"):
        Classification(
            category="sneaky",
            data_class=DataClass.CONTENT,
            store=Store.POSTGRES,
            retention=RetentionDriver.INDEFINITE,
            rationale="we'll tidy it up later",
        )


def test_a_classification_without_a_rationale_is_refused():
    with pytest.raises(ValueError, match="rationale"):
        Classification(
            category="unexplained",
            data_class=DataClass.CONFIGURATION,
            store=Store.POSTGRES,
            retention=RetentionDriver.INDEFINITE,
            rationale="   ",
        )


def test_embeddings_are_classified_as_content():
    """`[R4.8]`, Property 14.

    An embedding looks like derived metadata — it is a list of floats with no
    readable text in it. Inversion recovers substantial source content, so filing it
    as metadata would give it a long retention clock and exclude it from the
    deletion cascade. This is the single classification most likely to be
    "corrected" by someone reasonably.
    """
    embedding = BY_CATEGORY["embedding"]
    assert embedding.data_class is DataClass.CONTENT
    assert embedding.retention is RetentionDriver.FOLLOWS_SOURCE


def test_low_entropy_vault_mappings_are_content():
    """Surrogate-to-value mappings are plaintext PII by definition."""
    mapping = BY_CATEGORY["token_vault_mapping"]
    assert mapping.data_class is DataClass.CONTENT
    assert mapping.category in CONTENT_CATEGORIES


def test_audit_is_not_a_database_table():
    """`[R14.6]`, and the reason the audit trail stays as hash-chained JSONL.

    A row the application can rewrite is not tamper-evident, and an audit record
    foreign-keyed to content cannot outlive it.
    """
    audit = BY_CATEGORY["audit_record"]
    assert audit.store is Store.AUDIT_CHAIN
    assert audit.retention is RetentionDriver.SURVIVES_DELETION
    assert "audit_record" not in TABLE_CATEGORY.values()


def test_retention_required_set_is_derived_not_listed():
    """The startup refusal set must follow from the registry.

    If it were a separate list, a new content category could be added without
    acquiring the requirement to configure a period for it — and `[R14.3]` would
    pass while the category was unbounded.
    """
    expected = {
        c.category
        for c in REGISTRY
        if c.retention is RetentionDriver.POLICY_PER_WORKSPACE
    }
    assert RETENTION_REQUIRED_CATEGORIES == expected
    assert expected, "no category requires retention configuration — suspicious"


def test_classify_names_the_requirement_for_an_unknown_category():
    with pytest.raises(KeyError, match="14.1"):
        classify("something_nobody_classified")


def test_table_category_values_all_exist_in_the_registry():
    unknown = {
        table: category
        for table, category in TABLE_CATEGORY.items()
        if category not in BY_CATEGORY
    }
    assert unknown == {}, f"tables mapped to categories that do not exist: {unknown}"


@requires_database
def test_every_table_created_by_migrations_is_classified(migrated_database: Database):
    """The control that makes the registry more than a document.

    Against a live database, so it reflects the schema rather than the migration
    file's apparent contents. A table added without a classification fails here.
    """
    tables = migrated_database.table_names()
    assert tables, "no tables found — did the migration run?"

    unclassified = sorted(tables - set(TABLE_CATEGORY))
    assert unclassified == [], (
        f"these tables have no classification: {unclassified}\n"
        f"[R14.1] requires every persisted category to be classified. Add each to "
        f"TABLE_CATEGORY in explorer/storage/classification.py, and add a "
        f"Classification to REGISTRY if the category is new. The question the "
        f"registry is really asking is: when does this data get deleted?"
    )


@requires_database
def test_no_classified_table_is_missing_from_the_schema(migrated_database: Database):
    """The other direction: a mapping entry for a table that does not exist.

    Usually a rename where only one side was updated, which would leave the
    classification check passing while covering a table nobody has.
    """
    tables = migrated_database.table_names()
    stale = sorted(set(TABLE_CATEGORY) - tables)
    assert stale == [], f"TABLE_CATEGORY names tables that do not exist: {stale}"
