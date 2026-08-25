# What the platform stores, and where

**Generated from `explorer/storage/classification.py`. Do not edit by hand.**
Run `python tools_dev/build_data_statement.py` after changing the registry;
`tests/explorer/storage/test_data_statement.py` fails if this file is stale.

Requirement 14.8. Every persisted category is classified as content, derived
metadata, configuration or telemetry (`[R14.1]`), and the classification
decides both where the data lives and which retention clock governs it.

## Encryption at rest (`[R14.2]`)

Named rather than implied, and it differs by store.

- **Postgres** — whole-volume encryption provided by the operating system.
  This platform does not encrypt individual columns, so on an unencrypted
  volume the rows are plaintext on disk.
- **Object store, filesystem adapter** — the same. It is the
  local-development adapter.
- **Object store, S3 adapter** — server-side encryption, requested explicitly
  on every `put` rather than relying on a bucket default, because a bucket
  default is a setting someone else can change.
- **Audit chain** — not encrypted. It holds identifiers and counts by
  contract, enforced at write time.

Application-level envelope encryption is deliberately absent: it would put a
key in the same process as the ciphertext it protects, which buys less than it
appears to. The honest position is to name what the platform relies on so an
operator can verify it.

## Categories

### Content

May contain sensitive data. Retention is configurable per workspace and startup refuses when a period is missing (`[R14.3]`).

| Category | Store | Retention | Why |
|---|---|---|---|
| `chunk_text` | object_store | follows_source | A chunk is a substring of its document, so it is exactly as sensitive. It follows the document rather than holding a clock of its own, which would let a copy outlive the original. |
| `document` | object_store | policy_per_workspace | Uploaded source text. In the object store rather than Postgres so deleting a large payload does not rewrite a table, and so [R14.4] can put originals on a different clock from sanitized output. |
| `embedding` | postgres | follows_source | Classified as content, not as derived metadata, because embedding inversion recovers substantial source text [R4.8]. In Postgres because similarity and the workspace predicate must be one SQL statement [R15.3]. |
| `sanitized_artifact` | object_store | policy_per_workspace | Scrubbed output. [R14.4] requires a clock independent of the original: the reason to keep a redacted copy for review rarely applies to the source it came from. |
| `token_vault_mapping` | postgres | policy_per_workspace | Surrogate-to-value mappings are plaintext PII by definition. Encrypted at rest and separately retained; task 13 builds it. Registered now so the schema cannot add it unclassified later. |

### Derived metadata

Counts, scores, offsets and entity types. No values, by contract.

| Category | Store | Retention | Why |
|---|---|---|---|
| `audit_record` | audit_chain | survives_deletion | Hash-chained JSONL rather than a table, because a row the application can rewrite is not tamper-evident. Not foreign-keyed to content, so it survives the deletion it records [R14.6]. |
| `chunk_metadata` | postgres | follows_source | Offsets, token counts and sequence. Offsets are not values, but they locate values in a document, so they are useless once the document is gone and are deleted with it. |
| `finding_metadata` | postgres | follows_source | Entity types, counts, confidence and the detector that fired. Carries no raw value by contract — the same contract the PII service response is shaped around [R11.5]. |
| `run_metrics` | postgres | indefinite | Tokens, cost, latency and completion reason. The comparison lab exists to show change over time, which needs history. |

### Configuration

Settings and definitions. Retained until explicitly removed.

| Category | Store | Retention | Why |
|---|---|---|---|
| `approval` | postgres | indefinite | Approver identity, decision and the exact executed parameters [R10.4]. An approval record that can expire is not a record. |
| `experiment` | postgres | indefinite | A saved lab configuration and its purpose. No content. |
| `identity` | postgres | indefinite | Users and memberships. Password verifiers are held here; the secrets [R15.7] refers to are provider credentials, which are never persisted by us. |
| `price_table` | postgres | indefinite | Versioned pricing; a run records the version it used [R1.8], so removing a version would make a historical cost figure unverifiable. |
| `prompt_template` | postgres | indefinite | Versioned, and a run references a specific version [R2.1]. Deleting a version would make an old run unexplainable. |
| `retention_policy` | postgres | indefinite | The policy cannot be governed by itself. Startup reads it to decide whether to run at all [R14.3]. |
| `workspace` | postgres | indefinite | The isolation boundary itself. Removed only by explicit deletion, which cascades to everything it owns [R14.5]. |

### Telemetry

Redacted before persistence (`[R6.8]`), and still on a retention clock — redaction reduces exposure, it does not eliminate it.

| Category | Store | Retention | Why |
|---|---|---|---|
| `session` | postgres | policy_per_workspace | Telemetry rather than configuration, because a session row records that a named person was active at a given time — which is a fact about behaviour, not a setting. It therefore gets a clock: identity is retained indefinitely, a record of when someone logged in is not. Holds only the token's SHA-256, so a database read yields nothing replayable. |
| `trace_event` | postgres | policy_per_workspace | Redacted on the write path, not at render time [R6.8], so the store never holds a raw value. Still on a retention clock: redaction reduces exposure, it does not eliminate it. |

## Tables

Which classification governs each table. Asserted against a live database by
`tests/explorer/storage/test_classification.py`, so a table cannot exist here
without an answer to the question of when its data is deleted.

| Table | Category |
|---|---|
| `app_user` | `identity` |
| `approval` | `approval` |
| `chunk` | `chunk_metadata` |
| `document` | `document` |
| `embedding` | `embedding` |
| `experiment` | `experiment` |
| `membership` | `identity` |
| `price_table` | `price_table` |
| `prompt_template` | `prompt_template` |
| `prompt_template_version` | `prompt_template` |
| `retention_policy` | `retention_policy` |
| `run` | `run_metrics` |
| `tool_invocation` | `run_metrics` |
| `trace_event` | `trace_event` |
| `user_session` | `session` |
| `workspace` | `workspace` |

Not every category has a table, which is intentional. Document and artifact
payloads live in the object store, with Postgres holding only metadata and a
reference. Chunk text is likewise a payload. The audit trail is hash-chained
JSONL rather than a table, because a row the application can rewrite is not
tamper-evident and `[R14.6]` needs audit records to outlive the data they
describe.

## Deletion (`[R14.5]`, `[R14.6]`)

Deleting a document removes its chunks, embeddings and object-store payloads.
Deleting a workspace removes everything it owns, in both stores. Payloads are
removed *before* rows: the residual failure mode is then a row pointing at a
missing payload, which is visible and recoverable, rather than bytes on disk
with nothing referencing them.

Every deletion writes a record to the audit chain, including a deletion that
failed partway — that is the case most needing intervention, so it is the
last case that should lack evidence. The record carries identifiers and
counts, never a label or content.

## Retention periods required at startup

Derived from the registry, not listed separately, so a new content category
acquires the requirement by being classified as content:

- `document`
- `sanitized_artifact`
- `session`
- `token_vault_mapping`
- `trace_event`

## What the platform never persists

- **Provider credentials and API keys** (`[R15.7]`). Read from the
  environment or a secret provider, never written to a table, a trace or a
  prompt.
- **Session bearer tokens.** Only their SHA-256, so a database read yields
  nothing replayable.
- **Entity values in traces or audit records.** Redaction happens on the write
  path, and forbidden field names are rejected at write time rather than
  trusted to review.
