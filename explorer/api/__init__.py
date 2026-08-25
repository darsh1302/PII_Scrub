"""FastAPI application: authentication, workspace scoping, run and experiment services.

Every request is authenticated before any data access, and the workspace predicate
belongs in the query rather than in a filter over results — a post-filter means the
other workspace's rows were already read.
"""
