# 🛡️ PII Scrubbing Agent

[![tests](https://github.com/darsh1302/PII_Scrub/actions/workflows/tests.yml/badge.svg)](https://github.com/darsh1302/PII_Scrub/actions/workflows/tests.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![python](https://img.shields.io/badge/python-3.13-blue.svg)](https://www.python.org/)

An AI agent that finds and removes sensitive data from files, logs and cloud
events — built so that the language model is never in a position to compromise the
result.

The model orchestrates. A deterministic core decides everything that matters.

## Why it is built this way

The content this agent reads is attacker-writable. Anyone who can trigger a log
line can put text in a log file, and text in a model's context can carry
instructions. So the model is treated as an untrusted component:

- it never receives file content
- it never receives entity character offsets
- it never decides how a detected entity is handled

It receives counts, type names, coverage figures and opaque handles. Detection,
policy resolution, redaction and verification all happen in Python that imports no
LLM library — asserted by a test that inspects `sys.modules` in a subprocess.

This shape came out of an architecture review of an earlier design that put the
reasoning loop inside the data path. That review produced 22 findings, six
blockers, and five of the six traced to that one decision.

## Quick start

```bat
git clone https://github.com/darsh1302/PII_Scrub.git
cd PII_Scrub
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
copy .env.example .env
```

Install takes a while — the pinned spaCy `en_core_web_lg` model is about 600 MB.

Fill in `.env`. Generate the salt with
`python -c "import secrets; print(secrets.token_hex(32))"`:

```dotenv
OPENAI_API_KEY=sk-...
PII_AGENT_TOKEN_VAULT_SALT=<64 hex characters>
PII_AGENT_SCAN_ROOTS=<absolute path to scan_workspace>
```

Run it:

```bat
mkdir audit
venv\Scripts\streamlit run app.py --server.address 127.0.0.1
```

Open `http://127.0.0.1:8501`, upload `sample.txt`, and ask:

```
scrub sample.txt with DEFAULT_PII for INTERNAL_SIEM
```

You get a findings table, a verified-clean download, and an audit record. About
five seconds for `sample.txt`, about two minutes for the 260 KB `sample_large.txt`.

## Documentation

| Document | Contents |
|---|---|
| [How it works](docs/01-how-it-works.md) | The problem, the trust model, the pipeline, honest limitations |
| [Architecture and flow](docs/02-architecture-and-flow.md) | Layer map, directory reference, request flow, reconciliation, policy ratchet |
| [Setup](docs/03-setup.md) | Prerequisites, install, configuration, tests, troubleshooting |
| [Functionality and prompts](docs/04-functionality-and-prompts.md) | Tools, prompts, destinations, actions, profiles, refusals |
| [Handoff notes](HANDOFF.md) | Current state and decisions that look odd without their reasoning |

An HTML version of each sits beside it. Two additional dashboards cover the spec:
`requirements-dashboard.html` and `design-dashboard.html`, the latter with 17
Mermaid diagrams.

Full specification: `.kiro/specs/pii-scrubbing-agent/` — 46 requirements, a design
document with the architecture review, and a nine-phase task plan.

## How it works, briefly

```
source → chunk → detect → globalize offsets → reconcile → coverage
       → [GATE 1] → policy → [GATE 2] → apply → verify → [GATE 3] → audit
```

Three detection engines run over each chunk: 25 purpose-built security
recognizers, Presidio with validators, and spaCy NER. A reconciler resolves
overlaps by credibility rather than span length, so a checksum-validated IBAN
beats a longer statistical guess.

Policy resolution is a `max()` over a strictness lattice
(`ALLOW < REPLACE < MASK < HASH < TOKENIZE < REDACT < BLOCK`), which makes it a
ratchet: a request can only increase restrictiveness. A fully manipulated
reasoning step cannot select a weaker action than the profile mandates.

The three gates fail closed — incomplete coverage, a policy block, or residual
data found during verification each withhold the cleaned copy while still
reporting every finding.

## Status

| Phase | Content | State |
|---|---|---|
| 0 | Session context, content handles, audit sink | ✅ |
| 1 | Data models, profile schema and validation | ✅ |
| 2 | Input boundary — sandbox, safe parsers, chunker | ✅ |
| 3 | Detection and reconciliation | ✅ |
| 4 | Security core — policy, apply, verify | ✅ |
| 5 | Agent loop — LangGraph, coarse tools | ✅ |
| 6 | Streamlit UI | ✅ |
| 7 | CloudWatch and Windows Event Log adapters | ⬜ |
| 8 | Remaining profiles, golden datasets, adversarial suite | ⬜ |

**844 tests passing, 3 skipped, ~90 seconds.** Branch coverage held at 100% on
`core/policy.py`, `core/reconciler.py`, `models/coverage.py`, `utils/paths.py` and
`session/allowlist.py`.

```bat
venv\Scripts\python -m pytest tests\ -q
```

## Known limitations

**Throughput is ~2.4 KB/s.** Presidio's `analyze` is 79% of it, and within that
Presidio runs its own spaCy pipeline in addition to ours — the NLP work happens
twice. A 10 MB log would take over an hour, which does not meet the "production
logs" framing in the requirements. Chunks are independent, so parallelism is
available.

**NER recall on names is imperfect** in terse log syntax. Findings are a floor, not
a guarantee. "Verified clean" means no residual entities of the types the scan
actioned — not a proof the file is free of all sensitive data.

**No access control.** Single-operator trust model. Startup refuses a non-loopback
bind unless `PII_AGENT_ALLOW_REMOTE=true`, which should only be set behind an
authenticating reverse proxy. RBAC is Phase 2 work.

**Five profiles are built.** `BASE_SECURITY`, `DEFAULT_PII`, `PAYMENT_PCI`,
`FINANCIAL` and `AI_SAAS`. The rest are specified but unbuilt; naming one fails
rather than silently falling back. `AI_SAAS` covers structured LLM telemetry but
deliberately does not claim to detect proprietary source code or free-form
customer content, which have no format. `HEALTHCARE` is deliberately not shipped — Requirement 21
asks for diagnoses, symptoms and medications, which have no format and would need a
clinical vocabulary. A profile that named those types without recognizers behind
them would report full coverage while detecting nothing clinical, and coverage is
what the fail-closed gates depend on.

## Security notes

- Uploads bypass the scan-root allowlist by design — you supplied the bytes, so
  there is no filesystem to escape. Path access is confined to
  `PII_AGENT_SCAN_ROOTS`, with sensitive paths refused even inside a root.
- `HASH` is rejected for `US_SSN`, `CREDIT_CARD`, `CVV` and `PIN` at profile
  validation. Those value spaces are exhaustible, so a salted digest is
  pseudonymization, not anonymization.
- There is no detokenization tool, and the registry raises if one is ever added.
  Reversal is out-of-band only.
- Nothing is written to disk. The cleaned copy lives in the session and leaves via
  download.
- Prompt-injection patterns found in content are reported, never enforced. The
  included samples contain planted payloads so the path stays exercised.

## Repository layout

| Path | Contents |
|---|---|
| `app.py` | Streamlit entry point |
| `agent/` | LangGraph loop, system prompt, session memory |
| `tools/` | The six coarse agent tools |
| `core/` | Deterministic pipeline — chunk, detect, reconcile, policy, apply, verify |
| `models/` | Entities, decisions, results, coverage, enums |
| `session/` | Content store, token vault, audit sink, allowlist |
| `profiles/` | Policy as YAML, plus schema validation |
| `utils/` | Config, sandbox paths, budgets, content gate, safe parsers |
| `ui/` | Presenters and the Streamlit drawing layer |
| `tests/` | unit · security · property · integration |
| `docs/` | Documentation, Markdown source and generated HTML |
| `tools_dev/` | Sample generator and docs builder |
| `.kiro/specs/` | Requirements, design with architecture review, task plan |

`core/` imports no LLM library, and nothing in `core/` imports from `agent/` or
`tools/`. Both constraints are asserted by test.

## License and scope

[MIT](LICENSE).

This assists with detection. It does not certify compliance with HIPAA, PCI-DSS,
GDPR or anything else, and automated detection never catches everything. Verify
output before relying on it.
