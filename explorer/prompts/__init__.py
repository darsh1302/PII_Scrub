"""Prompt templates, versioning, and context assembly.

The assembled prompt keeps its sections distinguishable — system, application,
user, retrieved context, memory, tool result — because untrusted sections must be
structurally separated rather than merely ordered.
"""
