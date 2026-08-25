"""Risk classification and approval gating.

Tool actions are validated independently of the model text that proposed them.
Approved parameters are the parameters executed; any difference refuses execution
rather than substituting values.
"""
