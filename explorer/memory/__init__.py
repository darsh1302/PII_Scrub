"""Memory types and lifecycle. Deferred beyond the MVP.

Built directly rather than on a third-party memory layer, for two reasons. The lab
exists to make provenance, relevance and lifecycle observable, and a library that
does extraction internally hides exactly that. And layers such as mem0 send
conversation content to a model to extract facts, which would disclose content as a
side effect of *writing* a memory — the same disclosure the platform otherwise
constrains explicitly.

Third-party layers arrive later as comparison adapters.
"""
