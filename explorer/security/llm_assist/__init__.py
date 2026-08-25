"""Opt-in LLM-assisted detection.

The riskiest capability in the platform, so it is contained structurally rather
than procedurally:

* It lives here, outside ``pii_agent.core``, so the core's no-LLM-import assertion
  keeps holding. The module boundary is the enforcement.
* Deterministic detection completes first, so a provider outage degrades to the
  deterministic baseline rather than to nothing.
* Candidates are add-only, labelled ``LLM_SUGGESTED``, and ranked below both
  calibrated and heuristic sources. A suggestion can never displace a
  validator-backed finding.
* Nothing here reaches the policy engine as an action. The ratchet is untouched.
"""
