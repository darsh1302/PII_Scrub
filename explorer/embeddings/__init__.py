"""Embedding providers.

An embedding is treated as sensitive to the same degree as the text it encodes:
inversion recovers substantial source content, so a stored vector is closer to a
copy of the input than to a hash of it.
"""
