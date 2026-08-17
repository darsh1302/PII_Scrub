# PII Scrubbing Agent — Session Handoff

Last updated: 16 August 2026

## What this is

An autonomous AI agent that detects and redacts sensitive data from logs, files
and cloud events. Built spec-first via Kiro's AIDLC workflow.

Spec lives in `.kiro/specs/pii-scrubbing-agent/`:
- `requirements.md` — 46 requirements
- `design.md` — design plus a senior architecture review (22 findings)
- `tasks.md` — 9 phases, checkboxes reflect real progress

Two HTML dashboards at the repo root: `requirements-dashboard.html` and
`design-dashboard.html` (the latter has 17 Mermaid diagrams).

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
| 7 | CloudWatch + Windows Event Log adapters | ⬜ next |
| 8 | Remaining profiles, golden datasets, adversarial suite | ⬜ |

**844 tests passing, 3 skipped, ~1.4 minutes.**

Run: `venv\Scripts\python -m pytest tests\ -q`
UI: `venv\Scripts\streamlit run app.py --server.address 127.0.0.1`
Sample files: `sample.txt` (3 KB, ~5s) and `sample_large.txt` (260 KB, ~110s)

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

**Restart Streamlit after editing `agent/prompts.py`.** `_runtime_for` is
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

**NER recall on names is imperfect.** Especially in terse log syntax. Findings
are presented as a floor, not a guarantee.

**No RBAC.** Single-operator trust model; startup refuses non-loopback bind
unless `PII_AGENT_ALLOW_REMOTE=true`. Requirement 69 is Phase 2.

## Environment

`.env` holds a working `OPENAI_API_KEY`, a 64-byte `PII_AGENT_TOKEN_VAULT_SALT`,
`PII_AGENT_SCAN_ROOTS=c:\AI\scan_workspace`, loopback bind.

Dependencies are exact-pinned — engine versions are recorded in every audit
record, so a floating version would make historical results non-reproducible.
`tests/test_dependency_pins.py` enforces this.

## Suggested next steps

1. **Phase 7** — CloudWatch and Windows Event Log adapters. Both reuse the proven
   core; no new policy or offset logic.
2. **Performance pass** — deduplicate the spaCy work, evaluate disabling the
   context enhancer, consider chunk parallelism. Arguably higher value than
   Phase 7 given the throughput gap against the stated use case.
3. **Phase 8** — remaining profiles (HEALTHCARE, FINANCIAL, PAYMENT_PCI, AI_SAAS
   are specified but only BASE_SECURITY and DEFAULT_PII exist as YAML), golden
   datasets keyed to the engine-version tuple.

## Watch out for

- Windows `write_text` translates `\n` to `\r\n`. Fixtures with byte-exact
  offsets must pass `newline=""`.
- `str()` on an `OSError` renders the filename through `repr()`, so paths arrive
  with doubled backslashes.
- The truncation budget is checked *before* each chunk, so at least one chunk
  always runs and the budget must sit below one chunk size (40960) to bite.
- `re.sub` rejects `\u` escapes in a replacement template — use a literal.
