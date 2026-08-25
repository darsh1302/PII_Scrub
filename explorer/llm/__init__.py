"""Model adapters and the versioned price table.

No business logic outside this package references a specific provider. Token counts
carry an ``estimated`` flag: where a provider does not report usage we estimate and
say so, because presenting an approximation as a measurement is worse than
presenting nothing.
"""
