"""The general tool contract and registry.

Distinct from ``pii_agent.tools``, which is the security product's own six coarse
capabilities. Merging them would either force the agent's constraints onto every
platform tool or dilute them.

Arguments are validated against the declared schema before execution, and never by
the model that proposed them.
"""
