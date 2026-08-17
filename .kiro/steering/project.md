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
- `app.py` — main Streamlit application
- `agent/` — LangGraph reasoning loop, system prompt, session memory
- `tools/` — the six coarse agent tools
- `core/` — deterministic pipeline: chunk, detect, reconcile, policy, apply, verify
- `models/` — entities, decisions, results, coverage, enums
- `session/` — content store, token vault, audit sink, allowlist
- `profiles/` — policy as YAML, plus schema validation
- `utils/` — config, sandbox paths, budgets, content gate, safe parsers
- `ui/` — presenters and the Streamlit drawing layer
- `docs/` — published documentation, Markdown source plus generated HTML
- `tools_dev/` — developer scripts (sample generator, docs builder)
- `.env` — API keys (never commit)
- `requirements.txt` — exact-pinned dependencies

## Architecture constraint
The LLM is an untrusted component. `core/` must never import an LLM library, and
nothing in `core/` may import from `agent/` or `tools/`. Content, entity offsets,
and scrub-action decisions never reach the model. An earlier `chains/` +
`prompts/` scaffold that sent content to gpt-4o was removed for this reason —
do not reintroduce that pattern.
