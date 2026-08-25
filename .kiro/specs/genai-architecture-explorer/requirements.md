# Requirements Document

GenAI Architecture Explorer — an explainable, secure, agentic AI learning platform.

## Introduction

The GenAI Architecture Explorer is a hands-on AI systems laboratory: a platform
where each major Generative AI and Agentic AI concept is a configurable, observable
module. Its purpose is to make the internals of an AI system inspectable — prompt
construction, chunking, embeddings, retrieval, memory, tool calls, policy
decisions, tokens, cost and latency — rather than hiding them behind a chat box.

Source: `GenAI_Architecture_Explorer_Business_Design_Requirements.docx` (BD/BRD
v1.0, 24 August 2026). Requirement identifiers from that document are cited as
`[BRD LLM-001]` so every requirement here is traceable to the business intent.

### Relationship to the existing PII Scrubbing Agent

The PII Scrubbing Agent already exists and is complete through its Phase 6: a
deterministic detection and redaction pipeline with a LangGraph agent, 966 tests,
and a security architecture built on one claim — **the language model never
receives content, entity offsets, or scrub-action authority.**

In this platform it becomes Deliverable 5, capability C11, exposed as a reusable
security service. It is treated as a **dependency with a typed contract**, not as
code to be absorbed and rewritten. Its fail-closed gates, coverage ledger,
hash-chained audit trail and policy ratchet are assets the platform inherits.

### Scope of this document

The BRD defines 12 deliverables. This document specifies the **MVP boundary**
(BRD section 23 — Deliverables 1 to 5) at implementation resolution, and later
phases at intent resolution only. Writing 120 detailed requirements for
capabilities eight deliverables away would be documenting guesses.

---

## Glossary

| Term | Definition |
|---|---|
| **Agent** | A runtime that selects actions or tools and progresses through multiple steps toward a goal. |
| **Agent harness** | The runtime around a model providing state, prompts, tools, memory, retries, policies, budgets, tracing and approvals. |
| **Chunk** | A segment of source content used for embedding or model context. |
| **Deterministic detection** | Detection by pattern, checksum or structural validator, with no model involvement. Reproducible for a given engine version. |
| **Embedding** | A numeric vector representing semantic characteristics of content. Not opaque — inversion recovers substantial source text. |
| **Fail-closed gate** | A checkpoint that withholds an artifact when a precondition is unmet, while still reporting findings. |
| **Groundedness** | The degree to which an answer is supported by retrieved evidence. |
| **Human-in-the-loop (HITL)** | A control requiring identified human approval before a specified action executes. |
| **LLM-assisted detection** | Detection in which content is transmitted to a model provider. A distinct processing mode with a different trust posture, not a detector option. See Requirement 12. |
| **Low-entropy type** | An entity type whose value space is small enough to exhaust by brute force, making digests and deterministic surrogates reversible. Currently `US_SSN`, `CREDIT_CARD`, `PAN`, `CVV`, `CVC`, `PIN`, `US_BANK_NUMBER`. |
| **Memory** | Information retained across a run, conversation, or longer period and made available to an agent. |
| **Policy ratchet** | Resolution of a scrub action as the maximum over a strictness ordering, so a request can only increase restrictiveness. |
| **Prompt injection** | Instructions embedded in untrusted content intended to override intended behaviour. Indirect when the content arrives via a document, retrieval result or tool output. |
| **RAG** | Retrieval-augmented generation: retrieval of external knowledge inserted into model context before generation. |
| **Run** | One execution of an experiment or agent, identified by a run id and described by an ordered trace. |
| **Surrogate** | A replacement value standing in for a detected entity. Random and vault-backed, or deterministic where the value space permits. |
| **Trace event** | One ordered, observable record within a run. |
| **Trust boundary** | A point at which data changes trust classification, such as content leaving the platform for a model provider. |
| **Untrusted data** | User input, retrieved documents, tool outputs and third-party responses — regardless of who submitted them. |
| **Workspace** | The isolation boundary for stored data and configuration. |

## Conflict resolutions

Four requirements in the BRD contradict guarantees the existing PII agent is built
on. They are resolved here rather than in design, because a design that silently
picks a side would remove a control without anyone deciding to.

### CR-1 — LLM-enhanced PII detection

`[BRD SEC-002, PII-002]` asks for "optional LLM-enhanced detection" as a **Must**.

This is the pattern a prior architecture review rejected as blocker SEC-03. The
existing core proves by test that it imports no LLM library, because sending
content to a model means disclosing it to a third-party processor and reopening
the indirect prompt-injection surface. `[BRD SEC-006]` separately requires that
untrusted content be kept out of instruction context — the BRD is in tension with
itself.

**Resolution: available, off by default, and never a silent upgrade.** It is not a
detector option; it is a distinct processing mode with a different trust posture.
See Requirement 12.

### CR-2 — Deterministic tokenization

`[BRD PII-004]` lists "deterministic token" among replacement strategies.

Deterministic surrogates over a small value space are brute-forceable, which is
why `HASH` is already rejected at profile-validation time for `US_SSN`,
`CREDIT_CARD`, `CVV` and `PIN`. A deterministic token for those types would
reintroduce that weakness under a name that sounds stronger.

**Resolution: deterministic tokens permitted only for types outside the
low-entropy set; low-entropy types require a vault-backed random surrogate.**
Cross-session correlation therefore requires the persisted vault in Requirement
13, which the current in-memory implementation does not provide.

### CR-3 — Persistence reverses a current security property

The PII agent deliberately writes no content to disk. The BRD requires PostgreSQL,
Redis and object storage, including *"original documents, sanitized outputs"*
`[BRD section 13]`.

**Resolution: accepted as a deliberate posture change, conditional on explicit
retention controls.** Data at rest is permitted only with the encryption,
retention and deletion requirements in Requirement 14. "We store documents now"
without those is a downgrade disguised as a feature.

### CR-4 — Multi-tenancy invalidates the single-operator trust model

`[BRD NFR-003, TOOL-005, HITL-004]` assume workspaces, roles and identified
approvers. The PII agent has no authentication and refuses a non-loopback bind
because of it.

**Resolution: authentication and workspace isolation are MVP prerequisites, not
later hardening.** Every requirement below that touches stored data or tool
permissions depends on Requirement 15. The loopback restriction is lifted only
when Requirement 15 is satisfied.

---

## Requirements

### Requirement 1: Model gateway and provider abstraction

**User Story:** As an AI learner, I want to send prompts to a model and see
exactly what was sent, what came back, and what it cost, so that I understand raw
inference before any framework abstracts it.

#### Acceptance Criteria

1. THE system SHALL accept a system message and a user message and submit them to
   a configured model `[BRD LLM-001]`.
2. THE system SHALL expose temperature, top-p, maximum output tokens, and response
   format as user-configurable inference parameters `[BRD LLM-002]`.
3. THE system SHALL display, for every run, the model identifier, input tokens,
   output tokens, total tokens, wall-clock latency, and estimated cost
   `[BRD LLM-003]`.
4. WHERE a provider does not report token counts, THE system SHALL label the
   displayed count as estimated and name the estimation method, rather than
   presenting an approximation as measured.
5. THE system SHALL support repeated execution of an identical configuration so
   non-determinism is observable rather than surprising `[BRD LLM-004]`.
6. THE system SHALL support structured JSON output validated against a caller-
   supplied schema, and SHALL report validation failure as a distinct outcome from
   a model error `[BRD LLM-005]`.
7. THE system SHALL reach providers through an adapter interface, and no business
   logic outside the adapter layer SHALL depend on a specific provider
   `[BRD LLM-007, NFR-012]`.
8. THE cost estimate SHALL be derived from a versioned, configurable price table,
   and THE system SHALL record which price-table version produced an estimate.
   Prices change; a stored cost figure with no basis is not reproducible.

### Requirement 2: Prompt construction and inspection

**User Story:** As a software engineer, I want to see the exact assembled prompt
and know which part came from where, so that I can debug behaviour I did not
expect.

#### Acceptance Criteria

1. THE system SHALL allow prompt templates to be created and versioned
   `[BRD PRM-001]`.
2. THE system SHALL allow two or more prompt variants to be executed against the
   same input set and compared `[BRD PRM-002]`.
3. THE assembled prompt view SHALL distinguish system, developer/application,
   user, retrieved-context, memory, and tool-result sections `[BRD PRM-003]`.
4. THE system SHALL display the exact effective payload sent to the model, subject
   to secret redaction `[BRD PRM-004]`.
5. WHERE redaction alters the displayed payload, THE system SHALL state that it did
   so and how many values were affected. A silently redacted prompt view is
   misleading precisely when a user is debugging.
6. THE system SHALL support reusable template variables `[BRD PRM-005]`.

### Requirement 3: Document ingestion and chunking

**User Story:** As an AI learner, I want to see exactly how my document was split,
so that I understand why retrieval returns what it returns.

#### Acceptance Criteria

1. THE system SHALL accept upload of supported text-oriented documents
   `[BRD DOC-001]`.
2. THE system SHALL extract text and preserve source metadata including document
   identity, page or section, and character offsets where available
   `[BRD DOC-002]`.
3. THE system SHALL support fixed-size, recursive, sentence/paragraph, structural,
   and semantic chunking strategies `[BRD DOC-003]`.
4. THE system SHALL allow chunk size and overlap to be configured `[BRD DOC-004]`.
5. THE UI SHALL display each chunk with its token count and source boundaries
   `[BRD DOC-005]`.
6. THE system SHALL support side-by-side comparison of two chunking configurations
   over the same document `[BRD DOC-006]`.
7. WHERE a document is parsed into chunks, THE offsets recorded SHALL refer to the
   original document, not to a normalized intermediate. An offset that refers to a
   transformed copy cannot be used to cite or redact the source.

### Requirement 4: Embeddings and vector storage

**User Story:** As an AI architect, I want to inspect stored vectors and their
metadata, so that I can reason about retrieval quality rather than guess at it.

#### Acceptance Criteria

1. THE system SHALL generate embeddings for chunks and for queries `[BRD VEC-001]`.
2. THE system SHALL persist embedding vectors together with their source text and
   metadata `[BRD VEC-002]`.
3. THE system SHALL support cosine similarity search, or a provider-supported
   equivalent, and SHALL name the metric used `[BRD VEC-003]`.
4. THE system SHALL allow inspection of retrieved records including score,
   metadata, and source text `[BRD VEC-004]`.
5. THE system SHALL support metadata filtering and collection/namespace isolation
   `[BRD VEC-005]`.
6. THE system SHALL reach vector stores through an adapter interface `[BRD VEC-006]`.
7. THE system SHALL record the embedding model and its version alongside every
   stored vector, and SHALL refuse to compare vectors produced by different
   embedding models. Cosine similarity between two embedding spaces is a number
   with no meaning.
8. AN embedding SHALL be treated as sensitive to the same degree as the text it
   encodes, because inversion recovers substantial source content. Embeddings of
   scanned content are subject to the same retention rules as the content.

### Requirement 5: Retrieval-augmented generation

**User Story:** As a software engineer, I want to see which chunks were considered,
which were selected, and how they reached the prompt, so that a wrong answer is
diagnosable.

#### Acceptance Criteria

1. THE system SHALL execute query embedding, vector retrieval, context
   construction, generation, and citation mapping as observable stages
   `[BRD RAG-001]`.
2. THE system SHALL allow Top-K and a score threshold to be configured
   `[BRD RAG-002]`.
3. THE system SHALL support optional reranking `[BRD RAG-003]`.
4. THE system MAY support hybrid keyword and vector retrieval `[BRD RAG-004]`.
5. THE trace SHALL show candidate chunks, selected chunks, their scores, and the
   final assembled context `[BRD RAG-005]`.
6. Answers SHALL cite the source document and page, or source identifier, where
   available `[BRD RAG-006]`.
7. WHERE a citation cannot be mapped to a retrieved record, THE system SHALL mark
   the answer as uncited rather than presenting an unverifiable citation.
8. THE system SHALL provide an evaluation mode comparing RAG configurations against
   a fixed test set `[BRD RAG-007]`.

### Requirement 6: Trace and observability

**User Story:** As any user, I want a single view that explains what happened
during a run, so that I can understand the execution path without reading logs.

#### Acceptance Criteria

1. EVERY execution SHALL be assigned a unique run identifier `[BRD OBS-001]`.
2. THE system SHALL record ordered events for model calls, retrieval, memory
   access, tool calls, policy checks, approvals, errors, and output validation
   `[BRD OBS-002]`.
3. THE event model SHALL include at minimum `RUN_STARTED`, `MEMORY_RETRIEVED`,
   `RETRIEVAL_COMPLETED`, `MODEL_REQUEST`, `MODEL_RESPONSE`, `TOOL_PROPOSED`,
   `POLICY_DECISION`, `APPROVAL_DECISION`, `TOOL_EXECUTED`,
   `EVALUATION_COMPLETED`, and `RUN_COMPLETED` `[BRD section 19]`.
4. THE UI SHALL present an execution timeline permitting inspection of each event
   `[BRD OBS-003]`.
5. THE system SHALL aggregate token usage, cost, latency, tool-call count, retries,
   and failures per run `[BRD OBS-004]`.
6. THE system SHALL provide a plain-language "what happened" explanation of the
   end-to-end path `[BRD OBS-005]`.
7. Trace export SHALL exclude or mask secrets and PII according to policy
   `[BRD OBS-006, NFR-002]`.
8. Redaction of trace content SHALL occur before persistence, not before display.
   Redacting at render time leaves the raw value in the store, which is where a
   breach reads from.
9. EVERY run SHALL terminate with an explicit completion reason, including runs
   that failed or were blocked `[BRD NFR-004, KPI Reliability]`.

### Requirement 7: Tool contract and permissions

**User Story:** As a security engineer, I want tools declared with typed schemas
and explicit permissions, so that an agent cannot reach a capability nobody
granted.

#### Acceptance Criteria

1. THE runtime SHALL expose tools through typed schemas with descriptions and input
   validation `[BRD TOOL-001]`.
2. A `ToolDefinition` SHALL declare id, name, description, input schema, risk
   level, approval requirement, allowed roles, timeout, and output limit
   `[BRD section 17]`.
3. A `ToolResult` SHALL report status as one of `SUCCESS`, `FAILED`, `BLOCKED`, or
   `APPROVAL_REQUIRED`, together with a safe summary and structured output
   `[BRD section 17]`.
4. THE agent SHALL be able to select only tools permitted for the current actor,
   role, environment, and risk level `[BRD TOOL-002, TOOL-005]`.
5. Tool results SHALL be captured as trace events `[BRD TOOL-003]`.
6. Tools SHALL implement timeout, error handling, retry policy, and output-size
   limits `[BRD TOOL-006]`.
7. Tool arguments SHALL be validated against the declared schema before execution,
   and validation SHALL NOT be delegated to the model that proposed them.
8. THE initial tool set SHALL include PII Scrubber, calculator, document reader,
   vector search, SQL read, HTTP request, and an approval-gated write action
   `[BRD TOOL-004, section 17.1]`.

### Requirement 8: Agent runtime

**User Story:** As an AI architect, I want an agent that maintains explicit state
within enforced budgets, so that its behaviour is bounded and explicable.

#### Acceptance Criteria

1. THE runtime SHALL maintain explicit execution state across steps `[BRD AGT-001]`.
2. THE runtime SHALL support plan/act/observe or graph-based multi-step execution
   `[BRD AGT-002]`.
3. THE runtime SHALL enforce maximum steps, token budget, time budget, and
   tool-call budget `[BRD AGT-003, NFR-011]`.
4. THE runtime SHALL support retry and fallback for transient failures
   `[BRD AGT-004]`.
5. THE runtime SHALL detect non-progressing loops and terminate safely
   `[BRD AGT-006]`.
6. THE runtime SHALL support checkpoints permitting inspection and safe resumption
   `[BRD AGT-005]`.
7. THE final response SHALL distinguish generated content from executed actions and
   their results `[BRD AGT-007]`.
8. Budgets SHALL be scoped to a turn rather than accumulated across a session, so a
   long conversation does not exhaust an allowance and silently stop using tools.

### Requirement 9: Memory

**User Story:** As a user, I want to see what the system remembered about me, where
it came from, and delete it, so that persistent memory is not an unaccountable
store of my data.

#### Acceptance Criteria

1. THE platform SHALL support transient session memory `[BRD MEM-001]`.
2. THE platform SHALL support conversation history with configurable truncation or
   summarization `[BRD MEM-002]`.
3. THE platform SHALL support persisted semantic memories with provenance
   `[BRD MEM-003]`.
4. EVERY retrieved memory SHALL carry provenance, creation time, relevance or
   confidence, and memory type `[BRD MEM-005]`.
5. Users SHALL be able to inspect, delete, and expire persistent memories
   `[BRD MEM-006]`.
6. Memory retrieval SHALL respect workspace and actor boundaries `[BRD MEM-007]`.
7. Content written to persistent memory SHALL pass the PII scrubbing service first
   where the workspace policy requires it, so long-term memory does not become the
   place PII accumulates unscanned.

### Requirement 10: Human-in-the-loop approval

**User Story:** As a security engineer, I want high-risk actions to require an
identified human approval, so that an autonomous agent cannot take a consequential
action alone.

#### Acceptance Criteria

1. Policies SHALL classify each action as auto-allowed, denied, or
   approval-required `[BRD HITL-001]`.
2. THE approval screen SHALL display the requested action, target, parameters, risk
   reason, and sanitized supporting context `[BRD HITL-002]`.
3. An authorized user SHALL be able to approve or reject `[BRD HITL-003]`.
4. THE system SHALL record approver identity, decision, timestamp, and the exact
   parameters executed `[BRD HITL-004]`.
5. THE system SHALL revalidate authorization immediately before executing an
   approved action `[BRD HITL-005]`.
6. THE parameters executed SHALL be the parameters approved. WHERE they differ for
   any reason, execution SHALL be refused rather than proceeding with substituted
   values.

### Requirement 11: PII scrubbing as a platform service

**User Story:** As a workflow author, I want to call the PII scrubber as a typed
service from a pipeline or another agent, so that sanitization is a reusable
control rather than a separate application.

#### Acceptance Criteria

1. THE existing PII Scrubbing Agent SHALL be exposed as a reusable platform
   tool/service `[BRD SEC-001, PII-007]`.
2. THE service contract SHALL accept text or a document reference plus a policy
   profile and destination, and SHALL return a sanitized artifact reference, entity
   counts by type, confidence summary, and a verification outcome `[BRD PII-006]`.
3. THE service SHALL be invocable by a user, by an ingestion pipeline, before
   transmission to an external model, before tool output is persisted, and by
   another agent `[BRD section 10.1]`.
4. THE service SHALL perform a validation re-scan after transformation and SHALL
   withhold the artifact when residual sensitive data is found
   `[BRD PII-005, section 24]`.
5. THE audit report SHALL contain counts, types, and confidence but no raw
   sensitive values `[BRD PII-006, PII-010]`.
6. THE service SHALL record which detector and which policy caused each redaction,
   in protected audit metadata `[BRD PII-008]`.
7. THE service SHALL support batch processing with per-item success and failure and
   resumability `[BRD PII-009]`.
8. THE service SHALL preserve its existing fail-closed behaviour: incomplete
   coverage, a policy block, or a failed verification SHALL withhold the artifact
   while still reporting findings.
9. Integration SHALL NOT require the deterministic core to import an LLM library.
   The existing test asserting this via `sys.modules` inspection SHALL continue to
   pass.

### Requirement 12: Optional LLM-assisted detection (resolves CR-1)

**User Story:** As a security engineer evaluating detection coverage, I want to
compare deterministic detection against LLM-assisted detection, and I want the
privacy cost of doing so to be explicit rather than buried in a setting.

#### Acceptance Criteria

1. LLM-assisted detection SHALL be disabled by default `[resolves BRD SEC-002]`.
2. Enabling it SHALL require an explicit per-request opt-in. A workspace-level
   setting alone SHALL NOT enable it, because the person submitting the content is
   the person who needs to know it will leave the boundary.
3. BEFORE transmission, THE system SHALL state plainly that content will be sent to
   the configured model provider, and name the provider.
4. THE system SHALL run deterministic detection first and SHALL send content for
   LLM-assisted detection only after deterministic detection has completed, so a
   provider outage cannot reduce detection below the deterministic baseline.
5. LLM-assisted detection SHALL be permitted to ADD candidate entities only. It
   SHALL NOT remove, downgrade, or override a deterministic finding, and it SHALL
   NOT influence the resolved scrub action. The policy ratchet remains the sole
   authority.
6. Entities contributed by LLM-assisted detection SHALL be labelled as such in
   findings, traces, and audit records, with a confidence source distinguishing
   them from validator-backed and calibrated detections.
7. THE audit record SHALL record that content was disclosed to an external
   processor, the provider, the model version, and the byte count transmitted.
8. WHERE the destination policy forbids external disclosure, LLM-assisted detection
   SHALL be refused even when opted in.
9. Content sent for LLM-assisted detection SHALL be subject to the existing
   injection scan, and detected injection attempts SHALL be reported. Content that
   reaches a model is an injection vector regardless of why it was sent.
10. A run using LLM-assisted detection SHALL NOT be presented as equivalent to a
    deterministic run in evaluation comparisons; the mode SHALL be a dimension of
    the comparison.

### Requirement 13: Tokenization and reversibility (resolves CR-2)

**User Story:** As a data engineer, I want tokenized identifiers that stay
joinable across exports, without being told a value is protected when it is
guessable.

#### Acceptance Criteria

1. THE platform SHALL support a persisted, encrypted token vault providing
   surrogate-to-value mappings that survive session end and restart.
2. Deterministic surrogates derived from the value SHALL be permitted only for
   entity types outside the low-entropy set `[resolves BRD PII-004]`.
3. FOR low-entropy types — including `US_SSN`, `CREDIT_CARD`, `PAN`, `CVV`, `PIN`,
   and `US_BANK_NUMBER` — surrogates SHALL be random and vault-backed. A
   deterministic surrogate over an exhaustible value space is reversible by anyone,
   which is why `HASH` is already rejected for these types.
4. `CVV`, `CVC`, `PIN`, and `TRACK_DATA` SHALL NOT be reversibly tokenized under
   any configuration.
5. Reversal SHALL require an authenticated operator identity, SHALL be unavailable
   to any agent-reachable tool, and SHALL write an audit record per access.
6. WHERE a profile selects `TOKENIZE` and no persisted vault is configured, THE
   system SHALL state that surrogates are session-scoped and irreversible rather
   than implying durable tokenization.
7. THE vault SHALL support retention and deletion, and deleting a mapping SHALL be
   irreversible and audited.

### Requirement 14: Data at rest, retention and deletion (resolves CR-3)

**User Story:** As a product owner, I want to know exactly what the platform
stores, for how long, and how it is deleted, so that adopting persistence does not
create an unbounded liability.

#### Acceptance Criteria

1. THE platform SHALL classify every persisted data category as one of: content
   (may contain sensitive data), derived metadata (counts, scores, offsets),
   configuration, or telemetry.
2. Content at rest SHALL be encrypted, and THE system SHALL name the mechanism
   relied upon.
3. EVERY content category SHALL have a configured retention period, and THE
   platform SHALL refuse to start when a category has none. An unbounded default
   is how "temporary" storage becomes permanent.
4. Sanitized artifacts and original documents SHALL have independently configurable
   retention, because the reason for keeping one rarely applies to the other.
5. THE platform SHALL provide deletion of a document, a run, a memory, and a
   workspace, and deletion SHALL remove derived artifacts including chunks,
   embeddings and cached values.
6. Deletion SHALL be recorded in the audit trail, and THE audit record SHALL
   survive deletion of the data it describes.
7. Telemetry and traces SHALL be redacted before persistence `[BRD OBS-006]`.
8. THE platform SHALL provide a documented statement of what is stored and where,
   maintained as part of the deliverable rather than as tribal knowledge.

### Requirement 15: Authentication, authorization and workspace isolation (resolves CR-4)

**User Story:** As a platform operator, I want authenticated users scoped to
workspaces, so that stored documents, memories and traces are not readable by
whoever reaches the port.

#### Acceptance Criteria

1. THE platform SHALL authenticate every request before any data access
   `[BRD section 16.2]`.
2. THE platform SHALL support role-based authorization, and roles SHALL gate tool
   permissions, approval authority, and reversal of tokenization
   `[BRD TOOL-005, HITL-003]`.
3. Data SHALL be scoped to a workspace, and retrieval — including vector search and
   memory recall — SHALL be filtered by workspace at the query level, not by
   post-filtering results `[BRD NFR-003]`.
4. A cross-workspace read SHALL be impossible through any tool, retrieval path, or
   trace view, and this SHALL be asserted by test.
5. THE platform SHALL NOT bind to a non-loopback address until Requirements 15.1
   to 15.3 are satisfied. The existing startup refusal remains in force until
   authentication exists to replace it.
6. Approval decisions SHALL record the authenticated identity of the approver, and
   an unauthenticated session SHALL NOT be able to approve `[BRD HITL-004]`.
7. Secrets SHALL be held in a secret provider and SHALL NOT appear in prompts,
   traces, source control, or client-side configuration `[BRD NFR-001]`.

### Requirement 16: Evaluation

**User Story:** As an AI architect, I want to compare two configurations against a
fixed dataset, so that a change can be shown to be an improvement rather than
asserted to be one.

#### Acceptance Criteria

1. Users SHALL define evaluation datasets of inputs, expected characteristics, and
   optional reference answers `[BRD EVAL-001]`.
2. THE platform SHALL support response-quality metrics appropriate to the lab
   `[BRD EVAL-002]`.
3. RAG evaluation SHALL capture retrieval precision and recall, or a named proxy
   `[BRD EVAL-003]`.
4. Agent evaluation SHALL capture task success, tool success, step count, policy
   violations, and completion reason `[BRD EVAL-004]`.
5. Security evaluation SHALL capture PII leakage, injection resistance, unsafe
   action attempts, and blocked versus allowed outcomes `[BRD EVAL-005]`.
6. Users SHALL be able to compare configurations and detect regressions
   `[BRD EVAL-006]`.
7. AN evaluation result SHALL record the configuration and component versions that
   produced it, so a comparison across versions is identifiable as such rather
   than silently invalid `[BRD NFR-009]`.

### Requirement 17: Security model and trust boundaries

**User Story:** As a security engineer, I want untrusted data to be structurally
separated from instructions everywhere, so that injection is contained by design
rather than by prompt wording.

#### Acceptance Criteria

1. User input, retrieved documents, tool outputs, and third-party API responses
   SHALL be treated as untrusted data `[BRD section 16.1, SEC-006]`.
2. Untrusted data SHALL NOT be placed in a position where it can be interpreted as
   a higher-priority instruction.
3. THE runtime SHALL evaluate direct and indirect prompt-injection signals around
   untrusted content and SHALL report findings without acting on the content
   `[BRD SEC-005]`.
4. Tool actions SHALL be validated independently of model-generated text
   `[BRD section 25]`.
5. THE platform SHALL detect likely secrets using deterministic patterns and
   known-prefix or entropy methods `[BRD SEC-004]`.
6. Sensitive values SHALL be redacted from logs and traces by default
   `[BRD SEC-007]`.
7. THE platform SHALL maintain an append-only audit trail of security decisions
   without retaining raw sensitive values `[BRD SEC-008, NFR-008]`.
8. THE platform SHALL include security test cases for leakage, prompt injection,
   excessive permissions, and unsafe tool actions `[BRD SEC-009]`.
9. Recursive agent spawning SHALL be bounded `[BRD MAG-004]`.

### Requirement 18: Extensibility

**User Story:** As a platform engineer, I want to add a model, vector store, tool,
chunker or evaluator without touching unrelated logic, so that the platform grows
without regression risk.

#### Acceptance Criteria

1. Models, vector stores, tools, chunkers, evaluators, and policies SHALL be reached
   through adapter interfaces `[BRD NFR-007]`.
2. Adding an adapter SHALL NOT require changes to unrelated business logic
   `[BRD KPI Extensibility]`.
3. Core business logic SHALL NOT depend on one LLM provider or one UI framework
   `[BRD NFR-012]`.

### Requirement 19: Experience layer

**User Story:** As a beginner, I want to find my way around without being buried in
detail, and as an expert I want the detail one click away, so that the same
interface serves learning and debugging.

#### Acceptance Criteria

1. THE home dashboard SHALL list available labs and recent experiments and runs
   `[BRD section 18]`.
2. EVERY lab SHALL separate configuration, execution, and inspection into distinct
   panels, so a user can see what they set, what ran, and what happened
   `[BRD section 18]`.
3. EVERY response SHALL provide access to a "Show me what happened" trace view from
   the response itself, not only from a separate traces screen `[BRD OBS-005]`.
4. Advanced detail SHALL be progressively disclosed. A beginner SHALL be able to
   complete a lab without opening an expander; an expert SHALL NOT have to leave the
   page to reach token counts, scores, or raw payloads `[BRD section 18]`.
5. Comparisons SHALL use a consistent layout across labs for quality, latency,
   tokens, and cost, so a user learns to read one comparison and can read them all
   `[BRD section 18]`.
6. WHERE an action is blocked by policy, THE UI SHALL state the policy reason
   without disclosing detector internals that would help an attacker evade it
   `[BRD section 18]`.
7. Approval screens SHALL show exactly what will execute before approval is given
   `[BRD HITL-002, section 18]`.
8. Generated artifacts SHALL indicate their source and provenance where applicable
   `[BRD section 18]`.
9. A refusal or a block SHALL be presented with the same visual weight as a
   success, and SHALL state what was protected and what would change the outcome. A
   refusal styled as an error teaches users to look for an override.
10. WHERE a displayed value is estimated, redacted, heuristic, or degraded, THE UI
    SHALL label it as such at the point of display rather than in documentation.
11. THE UI SHALL be reachable through keyboard navigation, SHALL provide text
    alternatives for status conveyed by colour or icon, and SHALL maintain sufficient
    contrast. Full conformance requires manual testing with assistive technology and
    expert review, which is outside automated verification.
12. THE experience layer SHALL be replaceable. Business logic SHALL NOT depend on the
    UI framework, so the Streamlit MVP can be succeeded by a richer frontend without
    rewriting the platform `[BRD section 12, NFR-012]`.

---

## MVP boundary

The MVP is Deliverables 1 to 5 `[BRD section 23]`, plus the prerequisites the
conflict resolutions introduce:

| In MVP | Requirement |
|---|---|
| Model gateway, parameters, run metrics | 1 |
| Prompt templates and effective-prompt inspection | 2 |
| Document upload, chunking, visualization | 3 |
| Embeddings and one persistent vector store | 4 |
| RAG with Top-K, threshold, citations | 5 |
| Run and trace persistence, "what happened" view | 6 |
| PII scrubber as a platform service | 11 |
| Data-at-rest retention and deletion | 14 |
| Authentication and workspace isolation | 15 |
| Basic experiment comparison | 16.1, 16.6 |
| Experience layer — dashboard, panels, trace view, comparisons | 19 |

Requirements 15 and 14 are pulled forward into the MVP against the BRD's phasing,
because Deliverables 3 and 4 persist content — and persisting content without
authentication or retention is the point at which a learning tool becomes a
liability.

Deferred: memory (9), tool contract beyond the PII service (7), agent runtime (8),
human approval (10), full evaluation (16.2 to 16.5), multi-agent, red-team agent.

Out of scope entirely `[BRD section 7.2]`: training foundation models, a
general-purpose SaaS marketplace, unrestricted autonomous high-impact actions,
enterprise identity federation, and replacing dedicated SIEM/DLP products.

---

## Open questions

1. **LLM-assisted detection provider.** Requirement 12 assumes the configured
   platform model provider. If a separate, differently-governed provider is
   intended for content inspection, that changes the disclosure statement in 12.3.
2. **Repository structure.** BRD section 27 proposes a layout that would restructure
   the existing PII agent. This document assumes the agent stays self-contained
   behind the Requirement 11 contract. Confirm before design.
3. **Retention defaults.** Requirement 14.3 requires a configured period per
   category but does not set values. These are policy decisions, not engineering
   ones.
4. **Cost-table source.** Requirement 1.8 requires a versioned price table.
   Whether it is maintained manually or fetched needs deciding.
