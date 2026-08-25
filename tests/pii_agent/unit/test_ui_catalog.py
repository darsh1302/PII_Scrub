"""Capability catalogue and prompt examples shown in the UI.

The catalogue is read from resolved profiles rather than written out, because a
hardcoded list would drift the first time a profile changed — and a capability
list that overstates what is detected is worse than none, since someone would
rely on it.
"""

from __future__ import annotations

import pytest

from pii_agent.ui.presenters import (
    DESTINATION_NOTES,
    PROMPT_EXAMPLES,
    available_profile_names,
    build_profile_catalog,
)


def test_available_profiles_include_the_built_ones():
    names = available_profile_names()
    for expected in (
        "BASE_SECURITY",
        "DEFAULT_PII",
        "FINANCIAL",
        "PAYMENT_PCI",
        "AI_SAAS",
    ):
        assert expected in names


@pytest.mark.parametrize(
    "profile", ["DEFAULT_PII", "PAYMENT_PCI", "FINANCIAL", "AI_SAAS"]
)
def test_catalog_is_populated_and_well_formed(profile):
    catalog = build_profile_catalog(profile)
    assert catalog, f"{profile} produced an empty catalogue"

    for row in catalog:
        assert row.entity_type
        assert row.action
        assert row.severity_icon
        assert row.severity_label


def test_catalog_includes_inherited_rules():
    """An industry profile shows what it inherits, not only its own additions."""
    catalog = {row.entity_type for row in build_profile_catalog("PAYMENT_PCI")}
    assert "TRACK_DATA" in catalog          # its own
    assert "PASSWORD" in catalog            # from BASE_SECURITY
    assert "EMAIL_ADDRESS" in catalog       # from DEFAULT_PII


def test_destination_sensitive_rules_are_flagged_not_shown_as_final():
    """Showing the base action alone would misstate what happens."""
    rows = {r.entity_type: r.action for r in build_profile_catalog("DEFAULT_PII")}
    assert "varies by destination" in rows["IP_ADDRESS"]


def test_payment_pci_shows_tokenize_where_default_masks():
    """The catalogue has to make a real difference between profiles visible."""
    default = {r.entity_type: r.action for r in build_profile_catalog("DEFAULT_PII")}
    pci = {r.entity_type: r.action for r in build_profile_catalog("PAYMENT_PCI")}

    assert default["CREDIT_CARD"] == "MASK"
    assert pci["CREDIT_CARD"] == "TOKENIZE"


def test_unknown_profile_returns_empty_rather_than_raising():
    """A display concern must not be able to take the page down."""
    assert build_profile_catalog("NOT_A_PROFILE") == []


def test_prompt_examples_reference_only_built_profiles():
    """A broken example is worse than no example."""
    names = set(available_profile_names())
    for _, example in PROMPT_EXAMPLES:
        for token in example.split():
            if token.isupper() and "_" in token and token not in {
                "INTERNAL_SIEM",
                "EXTERNAL_LLM",
                "EXTERNAL_ANALYTICS",
            }:
                assert token in names, f"example references unbuilt {token}"


def test_prompt_examples_and_destination_notes_are_non_empty():
    assert len(PROMPT_EXAMPLES) >= 5
    assert all(label and example for label, example in PROMPT_EXAMPLES)

    destinations = {name for name, _ in DESTINATION_NOTES}
    assert {"INTERNAL_SIEM", "EXTERNAL_LLM", "FILE", "S3"} <= destinations
    assert all(note for _, note in DESTINATION_NOTES)
