"""Trace events, redaction middleware, completion reasons.

Redaction sits on the *write* path, not the render path. Redacting at render time
leaves the raw value in the store, which is where a breach reads from.

Every run terminates with an explicit completion reason, including runs that failed
or were blocked; the column is NOT NULL so a missing one is a loud failure rather
than a blank field.
"""
