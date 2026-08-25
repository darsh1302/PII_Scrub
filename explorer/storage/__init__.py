"""Persistence adapters: Postgres, object store, migrations, retention sweeper.

Every repository method takes ``workspace_id`` explicitly. No ambient context, no
thread-local, no current-workspace global — a parameter that must be passed is a
parameter a reviewer sees, and isolation that depends on remembering is not
isolation.
"""
