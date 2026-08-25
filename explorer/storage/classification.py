"""The content classification registry — Requirement 14.1, task 2.3.

`[R14.1]` requires every persisted category to be classified as content, derived
metadata, configuration or telemetry. The classification is not documentation: it
decides where a category is stored and which retention clock governs it, so the
registry is the thing the schema and the sweeper both read.

The control that makes it hold is in ``test_classification.py``: the registry is
compared against the set of tables the migrations create, and a table that exists
without a classification fails the suite. That is deliberately the loud direction
of failure — adding a table is easy to do while forgetting the retention question,
and a category nobody classified is a category nobody deletes.

Design document, "Why PostgreSQL, and what goes elsewhere".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class DataClass(str, Enum):
    """`[R14.1]`'s four categories. The enum is closed on purpose.

    Adding a fifth means revisiting retention, encryption and the deletion
    cascade together, which is a decision worth forcing into review rather than
    allowing a new string to slip through.
    """

    CONTENT = "content"
    """May contain sensitive data. Encrypted at rest, retention configurable per
    workspace, deletion cascades."""

    DERIVED_METADATA = "derived_metadata"
    """Counts, scores, offsets, entity types. No values by contract."""

    CONFIGURATION = "configuration"
    """Experiments, templates, policies, price tables. Retained indefinitely."""

    TELEMETRY = "telemetry"
    """Trace events, redacted before write `[R6.8]`."""


class Store(str, Enum):
    """Where a category physically lives."""

    POSTGRES = "postgres"
    OBJECT_STORE = "object_store"
    AUDIT_CHAIN = "audit_chain"
    """The existing append-only hash-chained JSONL. Not a database table: a row
    the application can rewrite is not tamper-evident, and `[R14.6]` needs audit
    to outlive the data it describes."""


class RetentionDriver(str, Enum):
    """What determines when a category is swept.

    ``FOLLOWS_SOURCE`` exists because of `[R4.8]`: an embedding is as sensitive as
    the text it encodes, since inversion recovers substantial source content. It
    therefore cannot carry its own, longer, clock.
    """

    POLICY_PER_WORKSPACE = "policy_per_workspace"
    """A ``retention_policy`` row is required, and startup refuses without one
    `[R14.3]`."""

    FOLLOWS_SOURCE = "follows_source"
    """Deleted with the content it derives from `[R14.5]`."""

    INDEFINITE = "indefinite"
    """Configuration. Retained until explicitly removed."""

    SURVIVES_DELETION = "survives_deletion"
    """Audit. Deliberately outlives its subject `[R14.6]`."""


@dataclass(frozen=True)
class Classification:
    """One persisted category, classified.

    ``rationale`` is required rather than optional. The value of this registry is
    that a reader can tell whether a classification was reasoned about or copied
    from the row above.
    """

    category: str
    data_class: DataClass
    store: Store
    retention: RetentionDriver
    rationale: str

    def __post_init__(self) -> None:
        if not self.rationale.strip():
            raise ValueError(
                f"{self.category}: a classification without a rationale is a "
                f"guess with a label on it"
            )

        # Content must be governed by a real clock. Marking something CONTENT and
        # then giving it INDEFINITE retention is exactly the unbounded default
        # [R14.3] exists to prevent, and it would pass every other check.
        if self.data_class is DataClass.CONTENT and self.retention in (
            RetentionDriver.INDEFINITE,
            RetentionDriver.SURVIVES_DELETION,
        ):
            raise ValueError(
                f"{self.category}: content cannot be retained indefinitely — "
                f"[R14.3] requires a configured period and refuses an unbounded "
                f"default"
            )


REGISTRY: tuple[Classification, ...] = (
    # --- content -----------------------------------------------------------
    Classification(
        category="document",
        data_class=DataClass.CONTENT,
        store=Store.OBJECT_STORE,
        retention=RetentionDriver.POLICY_PER_WORKSPACE,
        rationale=(
            "Uploaded source text. In the object store rather than Postgres so "
            "deleting a large payload does not rewrite a table, and so [R14.4] "
            "can put originals on a different clock from sanitized output."
        ),
    ),
    Classification(
        category="sanitized_artifact",
        data_class=DataClass.CONTENT,
        store=Store.OBJECT_STORE,
        retention=RetentionDriver.POLICY_PER_WORKSPACE,
        rationale=(
            "Scrubbed output. [R14.4] requires a clock independent of the "
            "original: the reason to keep a redacted copy for review rarely "
            "applies to the source it came from."
        ),
    ),
    Classification(
        category="chunk_text",
        data_class=DataClass.CONTENT,
        store=Store.OBJECT_STORE,
        retention=RetentionDriver.FOLLOWS_SOURCE,
        rationale=(
            "A chunk is a substring of its document, so it is exactly as "
            "sensitive. It follows the document rather than holding a clock of "
            "its own, which would let a copy outlive the original."
        ),
    ),
    Classification(
        category="embedding",
        data_class=DataClass.CONTENT,
        store=Store.POSTGRES,
        retention=RetentionDriver.FOLLOWS_SOURCE,
        rationale=(
            "Classified as content, not as derived metadata, because embedding "
            "inversion recovers substantial source text [R4.8]. In Postgres "
            "because similarity and the workspace predicate must be one SQL "
            "statement [R15.3]."
        ),
    ),
    Classification(
        category="token_vault_mapping",
        data_class=DataClass.CONTENT,
        store=Store.POSTGRES,
        retention=RetentionDriver.POLICY_PER_WORKSPACE,
        rationale=(
            "Surrogate-to-value mappings are plaintext PII by definition. "
            "Encrypted at rest and separately retained; task 13 builds it. "
            "Registered now so the schema cannot add it unclassified later."
        ),
    ),
    # --- derived metadata --------------------------------------------------
    Classification(
        category="chunk_metadata",
        data_class=DataClass.DERIVED_METADATA,
        store=Store.POSTGRES,
        retention=RetentionDriver.FOLLOWS_SOURCE,
        rationale=(
            "Offsets, token counts and sequence. Offsets are not values, but "
            "they locate values in a document, so they are useless once the "
            "document is gone and are deleted with it."
        ),
    ),
    Classification(
        category="finding_metadata",
        data_class=DataClass.DERIVED_METADATA,
        store=Store.POSTGRES,
        retention=RetentionDriver.FOLLOWS_SOURCE,
        rationale=(
            "Entity types, counts, confidence and the detector that fired. "
            "Carries no raw value by contract — the same contract the PII "
            "service response is shaped around [R11.5]."
        ),
    ),
    Classification(
        category="run_metrics",
        data_class=DataClass.DERIVED_METADATA,
        store=Store.POSTGRES,
        retention=RetentionDriver.INDEFINITE,
        rationale=(
            "Tokens, cost, latency and completion reason. The comparison lab "
            "exists to show change over time, which needs history."
        ),
    ),
    # --- configuration -----------------------------------------------------
    Classification(
        category="workspace",
        data_class=DataClass.CONFIGURATION,
        store=Store.POSTGRES,
        retention=RetentionDriver.INDEFINITE,
        rationale="The isolation boundary itself. Removed only by explicit "
        "deletion, which cascades to everything it owns [R14.5].",
    ),
    Classification(
        category="identity",
        data_class=DataClass.CONFIGURATION,
        store=Store.POSTGRES,
        retention=RetentionDriver.INDEFINITE,
        rationale=(
            "Users and memberships. Password verifiers are held here; the "
            "secrets [R15.7] refers to are provider credentials, which are "
            "never persisted by us."
        ),
    ),
    Classification(
        category="experiment",
        data_class=DataClass.CONFIGURATION,
        store=Store.POSTGRES,
        retention=RetentionDriver.INDEFINITE,
        rationale="A saved lab configuration and its purpose. No content.",
    ),
    Classification(
        category="prompt_template",
        data_class=DataClass.CONFIGURATION,
        store=Store.POSTGRES,
        retention=RetentionDriver.INDEFINITE,
        rationale=(
            "Versioned, and a run references a specific version [R2.1]. "
            "Deleting a version would make an old run unexplainable."
        ),
    ),
    Classification(
        category="price_table",
        data_class=DataClass.CONFIGURATION,
        store=Store.POSTGRES,
        retention=RetentionDriver.INDEFINITE,
        rationale=(
            "Versioned pricing; a run records the version it used [R1.8], so "
            "removing a version would make a historical cost figure unverifiable."
        ),
    ),
    Classification(
        category="retention_policy",
        data_class=DataClass.CONFIGURATION,
        store=Store.POSTGRES,
        retention=RetentionDriver.INDEFINITE,
        rationale=(
            "The policy cannot be governed by itself. Startup reads it to "
            "decide whether to run at all [R14.3]."
        ),
    ),
    Classification(
        category="approval",
        data_class=DataClass.CONFIGURATION,
        store=Store.POSTGRES,
        retention=RetentionDriver.INDEFINITE,
        rationale=(
            "Approver identity, decision and the exact executed parameters "
            "[R10.4]. An approval record that can expire is not a record."
        ),
    ),
    # --- telemetry ---------------------------------------------------------
    Classification(
        category="trace_event",
        data_class=DataClass.TELEMETRY,
        store=Store.POSTGRES,
        retention=RetentionDriver.POLICY_PER_WORKSPACE,
        rationale=(
            "Redacted on the write path, not at render time [R6.8], so the store "
            "never holds a raw value. Still on a retention clock: redaction "
            "reduces exposure, it does not eliminate it."
        ),
    ),
    # --- audit -------------------------------------------------------------
    Classification(
        category="audit_record",
        data_class=DataClass.DERIVED_METADATA,
        store=Store.AUDIT_CHAIN,
        retention=RetentionDriver.SURVIVES_DELETION,
        rationale=(
            "Hash-chained JSONL rather than a table, because a row the "
            "application can rewrite is not tamper-evident. Not foreign-keyed "
            "to content, so it survives the deletion it records [R14.6]."
        ),
    ),
)

BY_CATEGORY: dict[str, Classification] = {c.category: c for c in REGISTRY}

CONTENT_CATEGORIES: frozenset[str] = frozenset(
    c.category for c in REGISTRY if c.data_class is DataClass.CONTENT
)

RETENTION_REQUIRED_CATEGORIES: frozenset[str] = frozenset(
    c.category
    for c in REGISTRY
    if c.retention is RetentionDriver.POLICY_PER_WORKSPACE
)
"""Categories for which a ``retention_policy`` row must exist per workspace.

Task 4.1 turns this into a startup refusal. It is derived from the registry
rather than listed separately, so a new content category cannot be added without
also acquiring the requirement to configure it.
"""


def classify(category: str) -> Classification:
    """Look up a category, failing loudly for an unknown one.

    A ``KeyError`` here is the correct outcome: it means a caller persisted
    something the registry has never heard of.
    """
    try:
        return BY_CATEGORY[category]
    except KeyError:
        known = ", ".join(sorted(BY_CATEGORY))
        raise KeyError(
            f"unclassified persisted category {category!r}. [R14.1] requires "
            f"every category to be classified before it is stored. Known: {known}"
        ) from None


# ---------------------------------------------------------------------------
# Table to category
# ---------------------------------------------------------------------------
TABLE_CATEGORY: dict[str, str] = {
    "workspace": "workspace",
    "app_user": "identity",
    "membership": "identity",
    "experiment": "experiment",
    "run": "run_metrics",
    "tool_invocation": "run_metrics",
    "approval": "approval",
    "document": "document",
    "chunk": "chunk_metadata",
    "embedding": "embedding",
    "trace_event": "trace_event",
    "prompt_template": "prompt_template",
    "prompt_template_version": "prompt_template",
    "retention_policy": "retention_policy",
    "price_table": "price_table",
}
"""Which classification governs each table.

Not every category has a table, and that asymmetry is intentional rather than an
omission:

* ``document`` and ``sanitized_artifact`` payloads live in the object store; the
  ``document`` table holds only metadata and the reference.
* ``chunk_text`` likewise — ``chunk`` holds offsets, the text is a payload.
* ``audit_record`` is the hash-chained JSONL, deliberately not a table `[R14.6]`.
* ``finding_metadata`` and ``token_vault_mapping`` arrive with tasks 11 and 13.
  They are classified now so their migration cannot introduce them unclassified.

The direction that must hold is the other one: **every table must appear here.**
``tests/explorer/storage/test_classification.py`` compares this mapping against the
tables the migrations actually create, against a live database. A new table without
an entry fails the suite — which is the point, because adding a table is easy to do
while forgetting the retention question, and a category nobody classified is a
category nobody deletes.
"""
