"""GenAI Architecture Explorer — the platform.

An AI systems laboratory: each major Generative AI and Agentic AI concept is a
configurable, observable module, so a learner can see prompt construction,
chunking, retrieval, memory, tool calls, policy decisions, tokens, cost and
latency rather than only a final answer.

Layering, innermost first:

    storage, observability      persistence, trace events, redaction on the write path
    llm, chunking, embeddings,
    retrieval, security         services — deterministic ones may not reach a model
    prompts, policy, agents     runtime — untrusted orchestration
    api, ui                     presentation, leaves

Two dependency rules matter most (design document D1 and D2):

* This package must never be imported by ``pii_agent``. The security product stays
  independently deployable, because the reason to trust it is that it is small
  enough to audit on its own.
* This package reaches ``pii_agent`` only through
  ``explorer.security.pii_service``. One contract, one place to change, one place
  to review.

Both are enforced by ``tests/architecture/test_import_direction.py``.
"""
