# Technical Requirements and Setup

## Prerequisites

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.13.5 (3.11+ expected to work) | Verified on 3.13.5 |
| OS | Windows, macOS, Linux | Developed on Windows; `pywin32` installs only on win32 |
| Disk | ~1.5 GB | Dominated by the spaCy `en_core_web_lg` model |
| RAM | 2 GB free | spaCy plus Presidio both load models |
| OpenAI API key | any tier with credit | Conversation only; the scrub core does not use it |

The OpenAI key is needed for the chat interface, not for scrubbing. The
deterministic core runs entirely locally and a test asserts it imports no LLM
library.

## Install

```bat
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

On macOS or Linux use `source venv/bin/activate`.

Every dependency is exact-pinned, including the spaCy model, which is installed
from a wheel URL rather than via `spacy download`. That is a correctness
requirement rather than housekeeping: engine and model versions are recorded in
every audit record, so a floating version would make a historical result
non-reproducible. `tests/test_dependency_pins.py` enforces it.

Key dependencies:

| Package | Version | Role |
|---|---|---|
| `langgraph` | 1.2.11 | Agent reasoning loop |
| `langchain` / `langchain-openai` | 1.3.15 / 1.5.1 | Tool binding and model client |
| `presidio-analyzer` / `presidio-anonymizer` | 2.2.364 | Standard PII detection with validators |
| `spacy` + `en_core_web_lg` | 3.8.15 / 3.8.0 | NER for names and locations |
| `defusedxml` | 0.7.1 | XXE and entity-expansion resistant XML parsing |
| `streamlit` | 1.61.1 | UI |
| `boto3` | 1.42.6 | CloudWatch source (Phase 7) |
| `pytest` / `pytest-cov` / `hypothesis` | 9.0.1 / 7.1.0 / 6.140.3 | Tests, coverage, property tests |

## Configure

Copy the template and fill it in:

```bat
copy .env.example .env
```

### Required

```dotenv
OPENAI_API_KEY=sk-...
```

Startup rejects unreplaced template values, not just empty ones. Leaving
`your-api-key-here` in place fails fast rather than surfacing as a confusing
error later.

### Security

```dotenv
PII_AGENT_TOKEN_VAULT_SALT=<64 hex characters>
PII_AGENT_SCAN_ROOTS=C:\logs;C:\temp\scan
```

Generate the salt:

```bat
python -c "import secrets; print(secrets.token_hex(32))"
```

Without a stable salt, `HASH` output changes on every restart and cross-run
correlation breaks.

`PII_AGENT_SCAN_ROOTS` is an allowlist of directories the agent may read.
Semicolon-separated on Windows, colon-separated elsewhere. Empty means uploads
only — it never means the whole filesystem. Paths that resolve outside the roots
are refused, and sensitive paths are refused even inside a root: `.env`, `id_rsa`,
`*.pem`, `.aws/**`, `.ssh/**`, `.kube/**`.

Keep the roots narrow. Pointing a root at the project directory would put `.env`,
with your API key and vault salt, inside the agent's reach.

### Deployment

```dotenv
PII_AGENT_BIND_ADDRESS=127.0.0.1
PII_AGENT_ALLOW_REMOTE=false
```

This service reads the local filesystem and CloudWatch using the host's
credentials and **has no authentication of its own**. On a non-loopback address
that access is available to any network peer. Startup refuses a non-loopback bind
unless `PII_AGENT_ALLOW_REMOTE=true`, and that should only be set behind an
authenticating reverse proxy.

### Audit

```dotenv
PII_AGENT_AUDIT_DIR=audit
```

Must be writable. If the audit sink cannot write, processing is refused rather
than proceeding unlogged.

### AWS (optional)

```dotenv
AWS_DEFAULT_REGION=us-east-1
```

The standard credential chain is used if keys are unset. Only needed for the
CloudWatch source.

## Directories

Create the working directories referenced by your `.env`:

```bat
mkdir scan_workspace
mkdir audit
```

## Run

```bat
venv\Scripts\streamlit run app.py --server.address 127.0.0.1
```

Then open `http://127.0.0.1:8501`.

The sidebar shows a health panel covering the API key, salt, scan roots, audit
directory, and detection engine versions. Resolve anything flagged there before
scanning — a degraded detector triggers the fail-closed coverage gate.

## Test

```bat
venv\Scripts\python -m pytest tests\ -q
```

844 tests, 3 skipped, roughly 90 seconds. Layout:

| Suite | Focus |
|---|---|
| `tests/unit/` | Module-level behaviour |
| `tests/security/` | Trust boundary, content gate, sandbox, fail-closed gates |
| `tests/property/` | Hypothesis: offset consistency, policy monotonicity, clean output |
| `tests/integration/` | End-to-end pipeline with no LLM |

Branch coverage is held at 100% on the security-critical modules: `core/policy.py`,
`core/reconciler.py`, `models/coverage.py`, `utils/paths.py`,
`session/allowlist.py`.

## Sample data

Two generated files are included:

| File | Size | Scan time |
|---|---|---|
| `sample.txt` | 3.3 KB | ~5 s |
| `sample_large.txt` | 260 KB | ~110 s |

Both contain planted PII, credentials, and deliberate prompt-injection payloads so
that a scan exercises the injection scanner against real input. Generate another
size with:

```bat
venv\Scripts\python tools_dev\make_big_sample.py 500000 scan_workspace\bigger.txt
```

Uploading through the UI bypasses the scan-root allowlist, since you supplied the
bytes directly. Scanning by path requires the file to be inside a configured root.

## Development notes

Restart Streamlit after editing `agent/prompts.py` or `agent/graph.py`.
`_runtime_for` is decorated `@st.cache_resource` and `AgentRuntime` builds the
system prompt in its constructor, so cached resources survive script reruns and
prompt edits will not take effect. The sidebar reset button clears the cache too.

Windows specifics worth knowing: `Path.write_text` translates `\n` to `\r\n`, so
fixtures with byte-exact offsets must pass `newline=""`; and `str()` on an
`OSError` renders the filename through `repr()`, so paths arrive with doubled
backslashes.

## Troubleshooting

| Symptom | Cause |
|---|---|
| "path resolves outside every configured scan root" | File is not under `PII_AGENT_SCAN_ROOTS`. Upload it, or move it into a root. |
| `429 insufficient_quota` | Valid key, no credit on the account. |
| Startup refuses to launch | Placeholder value left in `.env`, unwritable audit directory, or non-loopback bind without the override. |
| Prompt or graph change has no effect | Cached `AgentRuntime`. Restart, or use the reset button. |
| Scan appears to hang | Throughput is ~2.4 KB/s. 260 KB takes about two minutes; the status line sits on EXECUTING. |
