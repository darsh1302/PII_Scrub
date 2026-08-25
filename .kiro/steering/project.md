# Project Steering

## Overview
This is a Python LLM application using OpenAI and LangChain with a Streamlit UI.

## Tech Stack
- Python 3.x with virtual environment (venv/)
- OpenAI API via `openai` and `langchain-openai`
- LangChain for orchestration (use LCEL syntax)
- Streamlit for the frontend UI
- python-dotenv for environment variable management

## Conventions
- Always load API keys from .env using python-dotenv, never hardcode secrets
- Use LangChain's expression language (LCEL) with the pipe operator for chains
- Default model: gpt-4o unless otherwise specified
- Keep prompts in separate template variables or files for maintainability
- Use streaming responses where possible for better UX
- Handle API errors gracefully with user-friendly messages in the UI

## File Structure

Two product packages. Everything else is entry points, tests, docs or runtime state.

- `pii_agent/` — the PII Scrubbing Agent, independently deployable
  - `utils/` — config, sandbox paths, budgets, content gate, safe parsers
  - `models/` `profiles/` `session/` — domain types, policy as YAML, per-session state
  - `core/` — deterministic pipeline: chunk, detect, reconcile, policy, apply, verify
  - `tools/` — the six coarse agent tools
  - `agent/` — LangGraph loop, system prompt, session memory (the only LLM-aware package)
  - `ui/` — presenters and the Streamlit drawing layer
- `explorer/` — the GenAI Architecture Explorer platform
  - `storage/` `observability/` — persistence, trace events, redaction
  - `llm/` `chunking/` `embeddings/` `retrieval/` — services
  - `security/pii_service/` — the only module importing `pii_agent`
  - `security/llm_assist/` — the opt-in disclosure path, outside the core by design
  - `prompts/` `policy/` `tools/` `agents/` `memory/` `evaluation/` `api/` `ui/`
- `apps/` — Streamlit entry points (`pii_agent_app.py`, `explorer_app.py`)
- `tests/` — mirrors the source tree; `tests/architecture/` enforces import direction
- `docs/` — Markdown plus generated HTML; `docs/source/` holds source documents
- `data/samples/` — demo input
- `var/` — runtime state: audit trail, scan workspace, temp. Gitignored entirely
- `tools_dev/` — developer scripts
- `.env` — API keys (never commit); `requirements.txt` — exact-pinned

## Architecture constraints

The LLM is an untrusted component. Dependency rules, all enforced by
`tests/architecture/test_import_direction.py`:

- **D1** `pii_agent` imports nothing from `explorer` — the security product must
  stay independently deployable
- **D2** `explorer` reaches `pii_agent` only via `explorer.security.pii_service`
- **D3** `pii_agent.core` imports no LLM library, also asserted by subprocess
  `sys.modules` inspection
- **D4** `pii_agent.core` imports nothing from `agent` or `tools` — keeps the
  reasoning loop out of the data path
- **D5** deterministic platform services import nothing from `explorer.agents` or
  `explorer.llm`
- **D7** nothing imports a `ui` package; presentation is a leaf

Content, entity offsets and scrub-action decisions never reach the model. An earlier
`chains/` + `prompts/` scaffold that sent content to gpt-4o was removed for this
reason — do not reintroduce that pattern. `explorer/security/llm_assist/` is the one
sanctioned disclosure path, and it is opt-in, audited, and add-only.

## Development note

Streamlit re-executes the entry script on save but does **not** reload
already-imported modules, and `@st.cache_resource` values survive reruns. After
editing anything under `pii_agent/` or `explorer/`, restart the process — a refresh
is not enough. This presents as "my change did nothing".
