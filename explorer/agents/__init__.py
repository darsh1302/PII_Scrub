"""Agent runtime. Deferred beyond the MVP.

Budgets are scoped to a turn rather than accumulated across a session — the
reviewed design counted tool calls across the whole history, so a long conversation
silently stopped using tools.
"""
