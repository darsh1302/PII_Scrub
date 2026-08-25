"""Presentation. A leaf: nothing imports this package (rule D7).

Split as in the PII agent — presentation logic with no Streamlit import, and a thin
drawing layer over it. That split is what makes the framework replaceable rather
than merely declared replaceable.

Two conventions carried over because they measurably changed how people read
output: a refusal is rendered with the same visual weight as a success and states
what would change it; and anything estimated, heuristic, redacted or degraded is
labelled at the point of display.
"""
