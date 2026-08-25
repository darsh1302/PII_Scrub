"""The typed contract over the PII Scrubbing Agent.

The single seam between platform and security product. Shaped so that no response
field can carry an entity value — leaking one would require adding a field, which
review would catch — and so that a refusal always yields a null artifact
reference.

``requested_action`` may only tighten. The policy ratchet stays inside the PII
agent; the platform cannot weaken it.
"""
