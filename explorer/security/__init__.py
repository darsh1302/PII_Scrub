"""Platform security services.

Two subpackages with deliberately different trust postures:

* ``pii_service`` — the typed contract over the PII Scrubbing Agent. The only
  module in the platform permitted to import ``pii_agent`` (rule D2).
* ``llm_assist`` — the opt-in path that discloses content to a model provider.
  Placed here rather than inside ``pii_agent`` precisely so the deterministic core
  keeps its no-LLM-import guarantee.
"""
