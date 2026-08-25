# PII Scrubbing Agent → GenAI Architecture Explorer — Session Handoff

Last updated: 24 August 2026

## What this is

Two products in one repository.

`pii_agent/` is an autonomous AI agent that detects and redacts sensitive data
from logs, files and cloud events. It is complete through Phase 6 and
independently deployable.

`explorer/` is the GenAI Architecture Explorer — an explainable AI systems
laboratory that takes the PII agent as its first capability. Package skeleton
only at present; Phase 0 of its plan is done.

Both built spec-first via Kiro's AIDLC workflow.

PII agent spec, `.kiro/specs/pii-scrubbing-agent/`:
- `requirements.md` — 46 requirements
- `design.md` — design plus a senior architecture review (22 findings)
- `tasks.md` — 9 phases, checkboxes reflect real progress

Explorer spec, `.kiro/specs/genai-architecture-explorer/`:
- `requirements.md` — 19 requirements, four conflicts with the PII agent's
  architecture resolved explicitly (CR-1 to CR-4)
- `design.md` — 17 correctness properties, dependency rules D1–D7
- `tasks.md` — 15 tasks in 11 execution waves

Two HTML dashboards under `docs/dashboards/`: `requirements-dashboard.html` and
`docs/dashboards/design-dashboard.html` (the latter has 17 Mermaid diagrams).

## Current state

| Phase | Content | Status |
|---|---|---|
| 0 | Foundations — session context, content handles, audit sink | ✅ |
| 1 | Data models, profile schema + validation | ✅ |
| 2 | Input boundary — sandbox, safe parsers, chunker | ✅ |
| 3 | Detection, reconciliation | ✅ |
| 4 | **Security core** — PolicyEngine, apply, verify | ✅ |
| 5 | Agent loop — LangGraph, coarse tools | ✅ |
| 6 | Streamlit UI | ✅ |
| 7 | CloudWatch + Windows Event Log adapters | ⬜ deferred |
| 8 | Remaining profiles, golden datasets, adversarial suite | ✅ |

Explorer:

| Phase | Task | Content | Status |
|---|---|---|---|
| 0 | 1 | Restructure — two product packages, import-direction test | ✅ |
| 1 | 2 | Storage foundation — Postgres, migrations, object store | ✅ |
| 2 | 3 | Auth and isolation | ⬜ next |
| 3 | 4 | Retention and deletion | ⬜ |
| 4 | 5 | Observability | ⬜ |
| 5–14 | 6–15 | Model gateway through MVP acceptance | ⬜ |

**1055 tests passing, 3 skipped.** 966 from the PII agent, unchanged in behaviour
through the restructure, 9 architecture tests, and 80 for the storage foundation.

Run: `venv\Scripts\python -m pytest tests\ -q`

The storage tests need PostgreSQL. A local instance lives inside the repository:

```
python tools_dev/pg_local.py install     # 338 MB, no admin rights, all under var/
python tools_dev/pg_local.py start       # prints the two URLs for .env
```

Port 5433, not 5432, so it cannot shadow a system Postgres. Without
`EXPLORER_TEST_DATABASE_URL` those tests skip — and `tests/explorer/
test_ci_configuration.py` fails if `CI` is set while the URL is not, because a
skipped isolation test reads as a passing one.
UI: `venv\Scripts\streamlit run apps/pii_agent_app.py --server.address 127.0.0.1`
Sample files: `data/samples/sample.txt` (3 KB, ~5s) and `data/samples/sample_large.txt` (260 KB, ~110s)

## Repository layout

Two product packages. Everything else is entry points, tests, docs or runtime
state — the root holds no importable code.

```
pii_agent/   utils models session profiles core tools agent ui
explorer/    storage observability llm chunking embeddings retrieval
             security/{pii_service,llm_assist} prompts policy tools
             agents memory evaluation api ui
apps/        pii_agent_app.py  explorer_app.py
tests/       pii_agent/{unit,security,property,integration,fixtures}
             explorer/  architecture/
docs/        *.md plus generated dashboards/; source/ holds the BRD
data/samples/  demo input
var/         audit/ scan_workspace/ tmp/ — runtime state, gitignored entirely
tools_dev/   developer scripts
```

`pyproject.toml` puts the repo root on the pytest path. Deliberately **not** a
`src/` layout and no editable install — "clone it, two commands, it runs" is worth
more here than the convention. `requirements.txt` stays the exact-pinned source of
truth; `pyproject.toml` declares no dependencies.

`apps/pii_agent_app.py` carries a `sys.path` bootstrap because Streamlit puts the
*script's* directory on the path, not the repository root.

## Storage decisions that will look odd without the reasoning

**Composite foreign keys carrying `workspace_id`.** Every child table references
`(workspace_id, parent_id)` against the parent's `UNIQUE (workspace_id, id)`, not
`parent_id` alone. The design specified single-column references and that was not
good enough.

With a plain reference, a `chunk` row can hold `workspace_id = W2` while its
document belongs to W1. Every read filters on `workspace_id`, so the row is
invisible to both — harmless until embeddings. A vector search filters
`embedding.workspace_id = :caller` and scores whatever matches, so an embedding
carrying the caller's workspace and another workspace's `document_id` would be
scored, returned, and its source text fetched for display. One mistake in one
caller, and a cross-workspace disclosure. Filtering correctly at every call site
forever is not a control; a constraint is.

Verified by dropping the constraint and confirming the cross-workspace row is then
accepted. The cost is one redundant unique index per parent table, which is the
index a workspace-scoped lookup wants anyway.

**`run.completion_reason` is a CHECK, not NOT NULL.** `[R6.9]` says NOT NULL.
Taken literally that forces a value at INSERT, before the run has finished, so
every run would start life claiming a reason it has not reached and the column
would record whatever the first guess was. The guarantee worth having is that a run
cannot be *terminal* without one, which is what the constraint says. Still the
database refusing rather than the application remembering.

**Embeddings are classified as content, not derived metadata.** They look like
metadata — a list of floats with no readable text. Inversion recovers substantial
source content `[R4.8]`, so filing them as metadata would give them a long
retention clock and exclude them from the deletion cascade. This is the single
classification most likely to be "corrected" by someone reasonable, and a test
pins it.

**No ORM, and `workspace_id` is an explicit parameter on every repository method.**
An ambient workspace would remove a parameter from perhaps sixty call sites and
make a cross-tenant read look identical in the source to a correct one, with the
difference living in whether some earlier frame set a variable. An ORM's identity
map and lazy loading permit the same thing. `[R15.4]` asks for isolation to be
impossible to bypass rather than unlikely, which is not testable when the scope is
invisible at the call site.

**There were briefly two migration runners.** `explorer/storage/database.py` and
`engine.py` both existed, each with its own `schema_migration` table shape, and the
second silently applied migrations recorded by the first. `database.py` was deleted;
its two better ideas — refusing a gap in the migration sequence, and `reset_schema`
for development — were ported into `engine.py`. Its docstring also claimed the
composite foreign keys described above, which the schema did not have. That claim
was worth implementing.

**Local Postgres lives in the repository, not on the machine.** The EnterpriseDB
graphical installer needs elevation, which cannot be scripted without a UAC prompt,
registers a machine-wide service on 5432, and puts a cluster under
`C:\Program Files` that the project cannot clean up. `tools_dev/pg_local.py` uses
the portable binaries instead: no admin, everything under `var/`, port 5433. It
extracts only `bin`, `lib`, `share` and `include` — pgAdmin is two thirds of the
archive, unused, and bundles a Python whose `site-packages` paths are long enough
that Windows cannot delete them afterwards.

Four traps in that script, all now handled and all worth knowing about:

* An interrupted `extractall` leaves `bin/initdb.exe` present but `share/` absent,
  and `initdb` then reports "corrupted installation" pointing at the *data*
  directory. Completion is recorded by a marker file, not by probing for a binary.
* The generated superuser password must not be written inside the data directory —
  `initdb` correctly refuses a non-empty one, and the error reads like a stale
  cluster.
* `pg_ctl start` hangs forever under `capture_output=True`. The postmaster inherits
  the pipe and holds it for the life of the server, so `subprocess.run` waits on an
  EOF that never comes, and the server is already up while the script looks failed.
* `shutil.rmtree` raises `WinError 145` on paths over the Windows limit. Not a
  permissions problem, and retrying does not help; the extended-length prefix does.

## Dependency rules D1–D7

Enforced by `tests/architecture/test_import_direction.py`, which walks the AST of
every module under `pii_agent/` and `explorer/`.

- **D1** `pii_agent` imports nothing from `explorer` — the security product stays
  independently deployable
- **D2** `explorer` reaches `pii_agent` only through
  `explorer.security.pii_service`
- **D3** `pii_agent.core` imports no LLM library, asserted twice: statically here,
  and by subprocess `sys.modules` inspection
- **D4** `pii_agent.core` imports nothing from `agent` or `tools` — keeps the
  reasoning loop out of the data path
- **D5** deterministic platform services import nothing from `explorer.agents` or
  `explorer.llm`
- **D7** nothing imports a `ui` package; presentation is a leaf

D1, D3, D4 and D7 were each verified by writing a violation, confirming the suite
failed, then removing it. A rule that has never failed has never been tested. The
test landed *before* `explorer/` existed, so the new tree has been under the rules
since its first commit.

The rename exposed exactly the trap the plan predicted: the no-LLM subprocess test
imported its modules as a comma-separated list, so a mechanical rewrite renamed
only the first name in the list. It failed loudly rather than passing vacuously,
and is now one import per line. It was re-verified by adding `import openai` to
`core/detector.py` — 40+ leaked modules detected — then removing it.

## The architecture, in one paragraph

The LLM is treated as an **untrusted component**. A deterministic core does all
detection, policy resolution and redaction; the agent only chooses *what* to scan
and *which profile*, then explains the result. It never receives file content,
never receives entity character offsets, and never decides a scrub action. This
came out of the architecture review, which found that placing the reasoning loop
inside the data and policy path produced five of six blocker findings.

Pipeline: `source → chunk → detect → globalize offsets → reconcile → coverage →
[GATE 1] → policy → [GATE 2] → apply → verify → [GATE 3] → audit`

The three gates fail closed. Task 5.11 asserts via `sys.modules` inspection in a
subprocess that the core imports no LLM library at all.

## Decisions that will look odd without the reasoning

**Profile filtering runs *before* reconciliation.** Otherwise a spaCy
`ORGANIZATION` guess can win an overlap against a checksum-validated `IBAN_CODE`
and then be dropped by the filter, losing the IBAN entirely.

**Reconciliation precedence is credibility-first**, not longest-span-first:
validator-backed → calibrated-vs-heuristic → severity → length → detector →
name. Length first caused the bug above.

**A losing entity is trimmed, not discarded.** Presidio over-extends `PERSON` to
`"Priya Raghunathan ssn=417-82-6390"`; the nested SSN wins, and discarding the
loser whole left the name unscrubbed. Remainder threshold is 6 characters —
shorter remainders are field labels (`card=`, `IBAN `), not values.

**Verification is scoped to types the scan decided to remove**, and ignores
detections abutting a replaced region. Masking a card leaves `card=` against
asterisks, which spaCy reads as a `LOCATION` — that is our own replacement, not a
survivor. Without this, gate 3 refused correct artifacts.

**Approved truncation still refuses an artifact.** A partial scan cannot yield a
verifiable clean copy: the applier would scrub what it saw and leave live values
in what it did not. Found in implementation — a 45 KB budget over an 86 KB file
left 166 unscrubbed SSNs.

**`HASH` is forbidden for low-entropy types** (`US_SSN`, `CREDIT_CARD`, `CVV`,
`PIN`) at profile-schema validation. The SSN space is ~10⁹; a salted digest is
brute-forceable. It is pseudonymization, not anonymization.

**Detokenization is not an agent capability.** `build_registry` raises if any
tool name contains `detokenize`/`reverse`/`unmask`/`reveal`/`decrypt`. Reversal
is out-of-band only — otherwise prompt injection becomes an exfiltration
primitive.

**There is no output file. Downloading is the only way out.** Content is never
written to disk by design, so a cleaned copy lives in the session `ContentStore`
and leaves via `st.download_button`. Results are published to the UI through
`SessionContext.record_result`, called from the scan and scrub tools, and
`_render_results()` redraws them on every rerun — Streamlit discards widgets from
previous runs, so a button drawn only on the producing turn vanishes on the next
interaction.

Until this was wired, the artifact was stranded: `st.session_state.results` was
initialised, read by a `_render_results` that was never called, and never written
to. A scrub verified clean, the agent announced a download, and no download
existed. Download filenames are `<stem>-cleaned<ext>` and `<stem>-findings.json`,
with request-scoped widget keys so several results can coexist on screen.

**`security_findings` is a dict in the LLM projection, not a list.** As a bare
list the agent twice reported it as the cause of a missing artifact — "not
available due to the presence of security findings" — on requests that had
returned `verified_clean: true`. It now carries `blocked_this_request: False` and
a note saying it is an observation about the source. The UI still reads
`result.security_findings`, the dataclass field, which is unchanged.

**Restart Streamlit after editing `pii_agent/agent/prompts.py`.** `_runtime_for` is
`@st.cache_resource` keyed on session id, and `AgentRuntime` builds the system
prompt in its constructor, so cached resources survive script reruns and prompt
edits do not take effect. The reset button calls `st.cache_resource.clear()`,
which also works. This cost real debugging time: a prompt fix looked ineffective
when it had simply never loaded.

**`scan` carries a `next_step` field when it did not refuse.** A scan produces no
artifact, so `artifact_available` is always false in a scan result. The agent read
that as a denial, blamed the `security_findings` list, and told the user a clean
copy was impossible — while `scrub` on the same input returned `verified_clean:
true`. The prompt now states the `scan → scrub → export` order and forbids
inferring a cause from a false field; the `next_step` hint makes it structural
rather than relying on the prompt.

**A bare filename resolves to session-loaded content before hitting the
filesystem.** Uploads and pastes have no path inside a scan root, and the agent
is told the display name rather than the opaque handle. Without the label lookup
in `ContentStore.find_by_label`, an uploaded file fell through to `load_file` and
was refused as outside the sandbox — a file the user had just uploaded appeared
to be missing. Anything containing `/`, `\` or `:` is treated as an explicit
filesystem request and still goes through containment, so a label can never
shadow a path.

**Log timestamps are exempt from `DATE_TIME` scrubbing** via
`field_context_exempt`, and `IP_ADDRESS` is destination-aware (`ALLOW` for
`INTERNAL_SIEM`). The original default shredded every timestamp and source IP,
which destroys the primary use case.

**Do not reset shared detection engines between tests.** The `conftest.py`
autouse fixture deliberately does not. Rebuilding costs 3.1s against 0.011s of
detection work — a 276× overhead that was 10 of the suite's original 12 minutes.

## Known limitations

**Unlabelled numeric fallback patterns are a false economy.** The first cut of
`financial_recognizers.py` had bare patterns for routing numbers, SWIFT codes and
EINs alongside the labelled ones. In a log full of ids and durations they matched
constantly — 379 extra candidates per 40 KB chunk, ~2,650 over a 260 KB file — and
that volume through reconciliation and the verification re-scan pushed the run past
the 180s tool budget, which the coverage gate correctly reported as
`DEGRADED_COVERAGE`. They were removed. Note one in ten nine-digit numbers passes
the ABA checksum by chance, so an unlabelled routing-number match was mostly noise
regardless. Every low-entropy numeric type now requires an adjacent field label.

**Parallelism measured, not assumed.** Threaded chunk detection gives 1.22x at 2
threads and 1.32x at 8, on a 12-core machine — `re` holds the GIL, so the regex
work serialises. A process pool would give a real 3-4x because detection is a pure
`text -> entities` function and only strings cross the boundary, but each worker
loads its own spaCy model and Presidio engine (~600 MB), which rules it out for the
Cloud demo. Not built.

**Presidio's context enhancer is deliberately left on** despite being the single
largest line (10.3s of 28.4s on a 260 KB input). It raises scores when context
words sit near a match, and `DEFAULT_PII` depends on that — `US_SSN` has a 0.4
threshold with `context` among its detection methods. Disabling it would likely drop
SSNs below threshold in terse log lines. It needs the golden datasets from task 9.5
first so the recall change can be measured rather than guessed.

**Throughput: scan ~9.6 KB/s** (median of three runs, 254 KB, one process). A full
scrub is roughly half that, because verification re-scans.

**The duplicated NLP pass is fixed.** Presidio loaded its own spaCy model and ran
its own pass on top of ours, over identical text for identical output.
`build_shared_nlp` runs spaCy once and hands `NlpArtifacts` to
`AnalyzerEngine.analyze`, which then skips its own pass. Measured A/B in a single
process: **33.7s to 26.5s per scan, 21%**, about 14s over a scrub. Golden results
came out byte-identical, which is precisely what task 9.5 was built to prove.

Two details in that change. Artifacts come from Presidio's own
`_doc_to_nlp_artifact` rather than being hand-assembled: its NER configuration
relabels spans on the way through (`GPE` becomes `LOCATION`), and reimplementing
that would be a second source of truth. And `doc.ents` carry *raw* spaCy labels
while `artifacts.entities` carry the relabelled ones, so our spaCy detector must
keep reading `doc.ents`.

**Only the parser is disabled, deliberately.** An earlier version also trimmed the
lemmatizer, tagger and attribute_ruler for 3.9s. That was wrong: Presidio's context
enhancer reads `NlpArtifacts.lemmas` to raise scores when a context word sits near
a match, and DEFAULT_PII depends on it — `US_SSN` has a 0.4 threshold with
`context` among its detection methods. A test asserts those three stay enabled.

The context enhancer itself remains on for the same reason. It is still the largest
single line in Presidio's time (10.3s of 28.4s), and with goldens in place its
removal is now *measurable* — regenerate, diff, and see exactly which entities are
lost. Do not disable it without that diff.

**`TOKENIZE` is session-scoped, and the profiles used to claim otherwise.** Found in
an implementation review. `_mint_surrogate` uses a CSPRNG and stores the mapping in
an in-memory dict cleared on teardown, so:

* the join holds within one session, never across sessions or restarts;
* the values are not recoverable afterwards, by an operator or anyone — the
  `scripts/detokenize.py` the module docstring referenced was never built.

FINANCIAL and PAYMENT_PCI both justified choosing TOKENIZE over MASK on
correlation grounds, which overstated it. Corrected in both profiles, the vault
docstring, the docs, and at the download in the UI.

Do **not** "fix" this by making surrogates deterministic (`HMAC(salt, type+value)`).
It would give stable cross-session tokens and reintroduce precisely the
brute-forcing weakness that guardrail G14 rejects `HASH` for on card numbers and
SSNs. The real fix is a durable encrypted vault, which needs the persistence this
project deliberately avoids. `test_session_retention.py` pins the current
behaviour, including a test that fails if tokens ever become cross-session equal.

**Idle sessions are swept.** `sweep_idle_sessions` runs on every Streamlit rerun,
tearing down sessions untouched for `SESSION_IDLE_TIMEOUT_SECONDS` (3600). This is
a retention control, not memory hygiene: Streamlit never signals a browser close,
so without it every session that ever existed kept its `ContentStore` — the
original file content — for the life of the process. `last_touched` uses
`time.monotonic` and is refreshed on every `get_session_context`, so "idle" means
inactive rather than merely old and a long scan cannot have its own content swept
mid-run.

**Do not increase the chunk size.** Detection cost is superlinear in chunk length.
Measured on 254 KB in one process, 2 runs each: 10 KB 33.4s, 20 KB 32.2s, 40 KB
(default) 34.9s, 80 KB 32.1s, 160 KB 39.7s, single 300 KB chunk **67.3s** — twice
the time for byte-identical output. Everything from 10 to 80 KB is inside the noise
band, so the default is already in the flat part of the curve.

This is also why `max_pattern_span` matters beyond correctness: the span becomes the
chunker's overlap, and a span near the chunk size collapses the document into one
chunk and lands on the expensive end of that curve. Incidentally, sizes below the
default all produced 7 chunks, so the chunker appears to floor near 40960.

**Measurement variance is high here.** The same unchanged scrub measured 110.7s,
86.4s and 118.3s within one session. Single-run wall-clock is not trustworthy: use
medians of repeated runs, and prefer A/B in one process over cross-session
comparison.

`PER_TOOL_TIMEOUT_SECONDS` is 180 (was 30, which capped input at ~70 KB).

Chunks are independent, but threaded parallelism measured only 1.22x at 2 threads
and 1.32x at 8 on 12 cores — `re` holds the GIL. A process pool would give a real
3-4x, at ~600 MB per worker for its own spaCy and Presidio, which rules it out for
the Cloud demo.

**Evasion resistance is proven for character-level attacks, and has three gaps.**
`tests/pii_agent/security/test_adversarial_evasion.py` (34 tests) confirms zero-width and
bidi controls, Cyrillic/Greek homoglyphs, full-width digits, lookalike dashes,
combining marks and case alternation are all defeated — including a stacked attack
that still produces a verified-clean artifact, which exercises the offset map under
normalization.

**Spaced-character evasion is now defended** by `detect_spaced_evasion`, a second
pass in `pii_agent/core/detector.py`. It runs only when a chunk contains a run of
individually-spaced characters, and only for validator-backed types (`US_SSN`,
`CREDIT_CARD`, `IBAN_CODE`, `ROUTING_NUMBER`).

Both restrictions are load-bearing. De-spacing creates adjacencies that were not
in the source, so an unvalidated pattern would invent identifiers — turning
`port=443 id=12 code=48271 9053` into a false SSN, refusing a correct artifact and
destroying real data. Manufacturing a finding is worse than missing a spaced one.

`collapse_spaced_characters` is targeted rather than global for the same reason;
`strip_whitespace_runs` (which removes all whitespace) is still unused and should
stay that way. Two subtleties cost real debugging:

* The run regex needs **both** lookarounds. Without the trailing
  `(?![0-9A-Za-z\-])` the run swallows the next token's first character, so
  `9 0 5 3 status` collapses to `9053status`, the SSN pattern fails its own word
  boundary, and the whole defence silently does nothing while looking correct.
* Offsets pass through **two** maps to reach source coordinates — collapse map into
  normalized coordinates, then the normalization map into the original. Getting the
  composition wrong places the replacement on the wrong span.

Wiring it changed one golden: `sample_adversarial.txt` went from 5 to 6 entities,
the new one being a spaced `US_SSN` at `[255:276]` resolved to `REDACT`. That
fixture had an escaping SSN the whole time, which is a fair advertisement for the
goldens.

Two attacks remain undefended, asserted as passing tests so closing one fails
loudly rather than being forgotten:

* **Base64-encoded values** — no candidate blob is decoded and re-scanned.
* **Hex-encoded values** — same.

Neither emits a warning either, which is the cheap half of that fix.

Worth keeping in perspective: these are *evasion* gaps, not accidental-disclosure
gaps. Someone logging PII by mistake logs it in plaintext; base64 implies intent.

**NER recall on names is imperfect.** Especially in terse log syntax. Findings
are presented as a floor, not a guarantee.

**No RBAC.** Single-operator trust model; startup refuses non-loopback bind
unless `PII_AGENT_ALLOW_REMOTE=true`. Requirement 69 is Phase 2.

## Environment

`.env` holds a working `OPENAI_API_KEY`, a 64-byte `PII_AGENT_TOKEN_VAULT_SALT`,
`PII_AGENT_SCAN_ROOTS=c:\AI\var\scan_workspace`, loopback bind.

Dependencies are exact-pinned — engine versions are recorded in every audit
record, so a floating version would make historical results non-reproducible.
`tests/pii_agent/test_dependency_pins.py` enforces this.

## Suggested next steps

Work has moved to the Explorer plan. Task 1 is complete and pushed
(`17a4256` on `origin/main`).

1. **Explorer task 3 — authentication and isolation.** Identity with a memory-hard
   KDF, workspaces and roles on membership, query-level scoping, and the isolation
   matrix `[R15.4]`. The matrix is the piece to get right: seed two workspaces and
   assert every read path returns nothing from the other, structured so that adding
   a read path without adding a row fails the suite. The composite foreign keys
   already make cross-workspace *parenting* impossible; the matrix covers
   cross-workspace *reading*.
2. **Then task 4 — retention.** A startup precondition, not a policy document.
   `RETENTION_REQUIRED_CATEGORIES` and `missing_categories()` already exist for it
   to build on, derived from the classification registry rather than listed
   separately so a new content category cannot avoid acquiring a period.
3. **PII agent Phase 7** — CloudWatch and Windows Event Log adapters — is deferred,
   not dropped. Both reuse the proven core with no new policy or offset logic, so
   they stay cheap to pick up later.

Not yet built, and deliberately so: the exact-search vector adapter is task 9.2, so
`embedding` rows are stored and deleted but not searched. `VectorStore` is defined
as a protocol only.

Four spec questions are still open: the LLM-assist provider, concrete retention
values, the object store for local development, and who maintains the price table.

## Watch out for

- Windows `write_text` translates `\n` to `\r\n`. Fixtures with byte-exact
  offsets must pass `newline=""`.
- `str()` on an `OSError` renders the filename through `repr()`, so paths arrive
  with doubled backslashes.
- The truncation budget is checked *before* each chunk, so at least one chunk
  always runs and the budget must sit below one chunk size (40960) to bite.
- `re.sub` rejects `\u` escapes in a replacement template — use a literal.
- **Never use PowerShell `Set-Content` on Markdown.** It writes a BOM and
  double-encodes em-dashes; it corrupted a spec document once. Write files through
  the editor or Python with `encoding='utf-8'`.
- Git is installed but not on `PATH`: `$env:Path += ";C:\Program Files\Git\cmd"`.
  PowerShell has no heredoc, so `git commit -F <file>` rather than piping.
- **A Hypothesis example database is keyed on the test's node id.** Moving a test
  file resets it, so a property that had been passing on cached examples can start
  failing. That happened during the restructure and the property turned out to be
  wrong: it asserted a scrubbed value appears nowhere in the output, but an
  identical substring can legitimately occur at a non-entity position. It is now
  count-based — if a value occurs N times and M were actioned, at most N − M may
  remain. Treat a post-move property failure as a possible real finding.
- **Streamlit does not reload already-imported modules**, and `@st.cache_resource`
  values survive reruns. After editing anything under `pii_agent/` or `explorer/`,
  restart the process; a browser refresh is not enough. This presents as "my change
  did nothing".
