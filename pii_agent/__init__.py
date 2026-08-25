"""PII Scrubbing Agent — a deterministic detection and redaction product.

Independently deployable and independently trustworthy. This package imports
nothing from ``explorer`` (dependency rule D1), so its security guarantees do not
depend on the platform that consumes it.

Layering, innermost first:

    utils                       configuration, paths, budgets, content gate
    models, profiles, session   domain types, policy as data, per-session state
    core                        the deterministic pipeline — no LLM library (D3)
    tools                       coarse capabilities exposed to the agent
    agent                       LangGraph loop — the only LLM-aware package
    ui                          presentation, a leaf (D7)

The central claim: the language model never receives content, entity offsets, or
scrub-action authority. ``core`` is where that is enforced, and a test asserts by
subprocess ``sys.modules`` inspection that it imports no LLM library.
"""
