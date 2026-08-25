-- 0001_initial — the storage foundation.  Task 2.2.
--
-- Three constraints shape every table below, and all three are here rather than in
-- application code because application code is where they get forgotten.
--
--   workspace_id NOT NULL on every table carrying data [R15.3].  It is on the row,
--   not reachable only by join, because a join can be omitted and an omitted join
--   is a cross-tenant read.
--
--   Composite foreign keys carrying workspace_id, so a child cannot be parented
--   across a workspace boundary.  See the note below -- this is the structural
--   half of Property 10 and the reason plain single-column references were not
--   good enough.
--
--   ON DELETE CASCADE wherever a child cannot outlive its parent [R14.5].
--   Property 14 asserts the whole cascade.  The database handles rows; the
--   application still removes object-store payloads, which is why
--   DocumentRepository.delete returns and the caller must act on it.
--
--
-- Why composite foreign keys
-- --------------------------
-- With a plain `chunk.document_id REFERENCES document(id)`, nothing stops a row
-- from having workspace_id = W2 while its document belongs to W1.  Every read
-- filters on workspace_id, so such a chunk is invisible to W1 and returns nothing
-- for W2 -- which sounds harmless until embeddings are involved.  A vector search
-- in W2 filters `embedding.workspace_id = W2` and would happily score a vector
-- computed from W1's text.  That is a cross-workspace disclosure reachable through
-- one mistake in one caller.
--
-- Referencing (workspace_id, parent_id) against a parent's UNIQUE (workspace_id,
-- id) makes the mismatched row impossible to insert.  Isolation then does not
-- depend on every future caller getting it right, which is the only form of it
-- worth asserting [R15.4].
--
-- The cost is a redundant unique index per parent table.  Cheap, and it is the
-- index a workspace-scoped lookup wants anyway.
--
-- Deliberately no ORM-generated schema.  The workspace predicate and these
-- constraints have to be visible in the statements a reviewer reads.

CREATE TABLE workspace (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL
);

-- "user" is reserved; app_user avoids quoting it at every call site, and an
-- unquoted reserved word works until one statement forgets.
--
-- Global rather than workspace-scoped: one person holds one account and joins
-- several workspaces.  Membership is what scopes them.
CREATE TABLE app_user (
    id                 UUID PRIMARY KEY,
    email              TEXT NOT NULL,
    password_verifier  TEXT NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL,
    disabled           BOOLEAN NOT NULL DEFAULT FALSE
);

-- Case-insensitive uniqueness.  Two accounts differing only in the case of the
-- local part are indistinguishable to a human reading an approval record, and
-- [R15.6] makes approver identity load-bearing.
CREATE UNIQUE INDEX app_user_email_key ON app_user (lower(email));

-- Role lives here, not on app_user: the same person may approve in one workspace
-- and only read in another [R15.2].
CREATE TABLE membership (
    id            UUID PRIMARY KEY,
    workspace_id  UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    user_id       UUID NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    role          TEXT NOT NULL
                  CHECK (role IN ('reader', 'author', 'approver', 'admin')),
    created_at    TIMESTAMPTZ NOT NULL,
    UNIQUE (workspace_id, user_id)
);

CREATE INDEX membership_user_idx ON membership (user_id);

CREATE TABLE retention_policy (
    id              UUID PRIMARY KEY,
    workspace_id    UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    category        TEXT NOT NULL,
    -- At least 1.  A zero or negative period would delete data on write, and
    -- "keep forever" has to be spelled as a long period someone chose rather than
    -- left blank -- an unbounded default is precisely what [R14.3] refuses.
    retention_days  INTEGER NOT NULL CHECK (retention_days >= 1),
    updated_at      TIMESTAMPTZ NOT NULL,
    UNIQUE (workspace_id, category)
);

CREATE TABLE experiment (
    id             UUID PRIMARY KEY,
    workspace_id   UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    lab            TEXT NOT NULL,
    name           TEXT NOT NULL,
    -- Not nullable.  A saved configuration without a stated purpose is unusable
    -- three weeks later, and the comparison lab's value depends on knowing what a
    -- run was trying to show.
    purpose        TEXT NOT NULL,
    configuration  JSONB NOT NULL,
    created_at     TIMESTAMPTZ NOT NULL,
    created_by     UUID REFERENCES app_user(id) ON DELETE SET NULL,
    -- The composite-reference target for run.
    UNIQUE (workspace_id, id)
);

CREATE INDEX experiment_workspace_idx
    ON experiment (workspace_id, lab, created_at DESC);

CREATE TABLE prompt_template (
    id            UUID PRIMARY KEY,
    workspace_id  UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    UNIQUE (workspace_id, name),
    UNIQUE (workspace_id, id)
);

CREATE TABLE prompt_template_version (
    id            UUID PRIMARY KEY,
    workspace_id  UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    template_id   UUID NOT NULL,
    version       INTEGER NOT NULL CHECK (version >= 1),
    body          TEXT NOT NULL,
    variables     TEXT[] NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL,
    UNIQUE (template_id, version),
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, template_id)
        REFERENCES prompt_template (workspace_id, id) ON DELETE CASCADE
);

-- Versioned pricing.  Global rather than per-workspace: provider list prices are
-- not a tenant's business decision, and a run records the version it used [R1.8]
-- so a historical cost figure stays verifiable.
CREATE TABLE price_table (
    version         TEXT PRIMARY KEY,
    effective_from  TIMESTAMPTZ NOT NULL,
    entries         JSONB NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL
);

CREATE TABLE run (
    id                          UUID PRIMARY KEY,
    workspace_id                UUID NOT NULL
                                REFERENCES workspace(id) ON DELETE CASCADE,
    experiment_id               UUID,
    status                      TEXT NOT NULL
                                CHECK (status IN ('running', 'terminal')),
    completion_reason           TEXT
                                CHECK (completion_reason IN (
                                    'completed', 'max_steps', 'budget_exhausted',
                                    'policy_blocked', 'provider_error', 'timeout',
                                    'cancelled', 'awaiting_approval'
                                )),
    started_at                  TIMESTAMPTZ NOT NULL,
    finished_at                 TIMESTAMPTZ,
    prompt_template_version_id  UUID,
    price_table_version         TEXT REFERENCES price_table(version)
                                ON DELETE SET NULL,
    total_input_tokens          INTEGER NOT NULL DEFAULT 0,
    total_output_tokens         INTEGER NOT NULL DEFAULT 0,
    total_cost_micros           BIGINT NOT NULL DEFAULT 0,
    -- [R1.4].  Where a provider does not report usage the gateway estimates and
    -- says so, rather than presenting an estimate as a measurement.
    token_counts_are_estimated  BOOLEAN NOT NULL DEFAULT FALSE,
    latency_ms                  INTEGER,
    error_detail                TEXT,

    UNIQUE (workspace_id, id),

    -- MATCH SIMPLE (the default) skips the check when any referencing column is
    -- NULL, which is what a run with no experiment needs.
    FOREIGN KEY (workspace_id, experiment_id)
        REFERENCES experiment (workspace_id, id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, prompt_template_version_id)
        REFERENCES prompt_template_version (workspace_id, id) ON DELETE SET NULL,

    -- Property 7, and a deliberate reading of [R6.9].
    --
    -- The requirement says completion_reason is NOT NULL.  Taken literally that
    -- forces a value at INSERT, before the run has finished -- so every run would
    -- start life claiming a reason it has not reached, and the column would record
    -- whatever the first guess was.  That is weaker than no column at all.
    --
    -- The guarantee that matters is: a run cannot be *terminal* without a reason.
    -- As a CHECK it is still the database refusing rather than the application
    -- remembering, and a run that ends without one fails loudly at the write.
    CONSTRAINT run_terminal_requires_reason CHECK (
        (status = 'running'  AND completion_reason IS NULL)
        OR
        (status = 'terminal' AND completion_reason IS NOT NULL)
    ),
    CONSTRAINT run_terminal_requires_finished_at CHECK (
        status = 'running' OR finished_at IS NOT NULL
    )
);

CREATE INDEX run_workspace_idx ON run (workspace_id, started_at DESC);
CREATE INDEX run_experiment_idx ON run (experiment_id, started_at DESC);

-- Metadata only.  The payload lives in the object store under payload_ref, so
-- deleting a large document does not rewrite this table and originals can sit on a
-- different retention clock from sanitized output [R14.4].
CREATE TABLE document (
    id            UUID PRIMARY KEY,
    workspace_id  UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    label         TEXT NOT NULL,
    media_type    TEXT NOT NULL,
    byte_size     BIGINT NOT NULL CHECK (byte_size >= 0),
    sha256        TEXT NOT NULL,
    payload_ref   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL,
    source_kind   TEXT NOT NULL DEFAULT 'upload',
    page_count    INTEGER,
    -- Scoped to the workspace, so an identical upload elsewhere is neither
    -- disclosed nor shared.  Deduplicating across workspaces would let one
    -- tenant's retention decision delete another tenant's only copy.
    UNIQUE (workspace_id, sha256),
    UNIQUE (workspace_id, id)
);

CREATE INDEX document_workspace_idx ON document (workspace_id, created_at DESC);

CREATE TABLE chunk (
    id               UUID PRIMARY KEY,
    workspace_id     UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    document_id      UUID NOT NULL,
    sequence         INTEGER NOT NULL CHECK (sequence >= 0),
    -- Offsets into the ORIGINAL document, never into a normalized intermediate
    -- (Property 13).  A normalized intermediate is a different string, so an
    -- offset into it cannot locate a citation or a redaction in what was uploaded.
    start_offset     INTEGER NOT NULL CHECK (start_offset >= 0),
    end_offset       INTEGER NOT NULL,
    token_count      INTEGER NOT NULL CHECK (token_count >= 0),
    strategy         TEXT NOT NULL,
    text_ref         TEXT,
    page_or_section  TEXT,
    UNIQUE (document_id, sequence),
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, document_id)
        REFERENCES document (workspace_id, id) ON DELETE CASCADE,
    CONSTRAINT chunk_offsets_ordered CHECK (end_offset >= start_offset)
);

CREATE INDEX chunk_document_idx ON chunk (document_id, sequence);

CREATE TABLE embedding (
    id                       UUID PRIMARY KEY,
    workspace_id             UUID NOT NULL
                             REFERENCES workspace(id) ON DELETE CASCADE,
    chunk_id                 UUID NOT NULL,
    -- Denormalized from chunk on purpose, so delete_by_document is a single
    -- statement with the workspace predicate in it rather than a join a future
    -- edit could drop.  The composite reference below is what keeps the
    -- denormalized column honest -- without it, this is the exact column that
    -- could disagree with the chunk's workspace and leak a vector across the
    -- boundary.
    document_id              UUID NOT NULL,
    -- NOT NULL because Property 12 forbids comparing across models, and a search
    -- cannot refuse a mismatch it has no record of.  Cosine distance between two
    -- embedding spaces is a number with no meaning.
    embedding_model          TEXT NOT NULL,
    embedding_model_version  TEXT NOT NULL,
    dimensions               INTEGER NOT NULL CHECK (dimensions >= 1),
    -- float8[] rather than pgvector.  The exact adapter computes similarity in
    -- SQL, so the workspace predicate and the scoring are one statement; pgvector
    -- arrives later as a second adapter and becomes the lab exercise.
    vector                   DOUBLE PRECISION[] NOT NULL,
    created_at               TIMESTAMPTZ NOT NULL,
    UNIQUE (chunk_id, embedding_model, embedding_model_version),
    FOREIGN KEY (workspace_id, chunk_id)
        REFERENCES chunk (workspace_id, id) ON DELETE CASCADE,
    FOREIGN KEY (workspace_id, document_id)
        REFERENCES document (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX embedding_workspace_model_idx
    ON embedding (workspace_id, embedding_model, embedding_model_version);
CREATE INDEX embedding_document_idx ON embedding (document_id);

CREATE TABLE trace_event (
    id               UUID PRIMARY KEY,
    workspace_id     UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    run_id           UUID NOT NULL,
    sequence         INTEGER NOT NULL CHECK (sequence >= 0),
    event_type       TEXT NOT NULL,
    occurred_at      TIMESTAMPTZ NOT NULL,
    duration_ms      INTEGER,
    -- Already redacted when it arrives [R6.8], Property 11.  Redacting at render
    -- time would mean the store holds the values and every future reader is one
    -- forgotten call away from them.
    payload          JSONB NOT NULL,
    -- Lets a trace say "3 values redacted" without holding them [R6.7].
    redaction_count  INTEGER NOT NULL DEFAULT 0 CHECK (redaction_count >= 0),
    UNIQUE (run_id, sequence),
    FOREIGN KEY (workspace_id, run_id)
        REFERENCES run (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX trace_event_run_idx ON trace_event (run_id, sequence);

CREATE TABLE tool_invocation (
    id                 UUID PRIMARY KEY,
    workspace_id       UUID NOT NULL REFERENCES workspace(id) ON DELETE CASCADE,
    run_id             UUID NOT NULL,
    sequence           INTEGER NOT NULL CHECK (sequence >= 0),
    tool_name          TEXT NOT NULL,
    risk_level         TEXT NOT NULL,
    status             TEXT NOT NULL,
    started_at         TIMESTAMPTZ NOT NULL,
    finished_at        TIMESTAMPTZ,
    requires_approval  BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (run_id, sequence),
    UNIQUE (workspace_id, id),
    FOREIGN KEY (workspace_id, run_id)
        REFERENCES run (workspace_id, id) ON DELETE CASCADE
);

CREATE TABLE approval (
    id                     UUID PRIMARY KEY,
    workspace_id           UUID NOT NULL
                           REFERENCES workspace(id) ON DELETE CASCADE,
    tool_invocation_id     UUID NOT NULL,
    -- RESTRICT, not SET NULL.  [R15.6] requires an approval to record who
    -- approved it; a row saying "approved by nobody" is not a record, so removing
    -- a user who has approved something must fail rather than quietly erase the
    -- attribution.
    approver_user_id       UUID NOT NULL REFERENCES app_user(id) ON DELETE RESTRICT,
    decision               TEXT NOT NULL
                           CHECK (decision IN ('approved', 'rejected')),
    decided_at             TIMESTAMPTZ NOT NULL,
    requested_parameters   JSONB NOT NULL,
    -- Held separately from requested_parameters so Property 9 can assert they are
    -- equal.  Substituting a value at execution time and calling it approved is
    -- the failure this shape exists to make visible.
    executed_parameters    JSONB,
    note                   TEXT,
    UNIQUE (tool_invocation_id),
    FOREIGN KEY (workspace_id, tool_invocation_id)
        REFERENCES tool_invocation (workspace_id, id) ON DELETE CASCADE
);

CREATE INDEX approval_approver_idx ON approval (approver_user_id);
