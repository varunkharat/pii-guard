"""Layer 1c: organization names found by their legal or sector suffix."""

from __future__ import annotations

import pytest

from piiguard.detectors.orgs import OrgSuffixDetector
from piiguard.pipeline import Pipeline

detector = OrgSuffixDetector()


def found(text: str) -> list[str]:
    return [s.text for s in detector.detect(text)]


# -- what it must catch -------------------------------------------------


@pytest.mark.parametrize(
    "text,expected",
    [
        ("Copperline Mutual", "Copperline Mutual"),
        ("Harborlight Insurance - Auto Claim Intake", "Harborlight Insurance"),
        ("at Valley Health Partners.", "Valley Health Partners"),
        ("Calverton State University - Enrollment Record", "Calverton State University"),
        ("Bill to: Coastal Data Systems", "Coastal Data Systems"),
        ("Sisters of Mercy Hospital", "Sisters of Mercy Hospital"),
    ],
)
def test_finds_invented_organizations(text, expected):
    """These are exactly the names spaCy has never seen and returns nothing for."""
    assert found(text) == [expected]


def test_boundary_beats_ner_on_overlap():
    """Layer 2 returns "Harborlight Insurance - Auto"; the tighter span must win."""
    text = "Harborlight Insurance - Auto Claim Intake\nSSN: 205-19-6647\n"
    spans = Pipeline().scan(text)
    orgs = [s.text for s in spans if s.label == "ORG"]
    assert orgs == ["Harborlight Insurance"]


# -- what it must not catch ---------------------------------------------


def test_never_crosses_a_newline():
    """A letterhead puts the addressee directly above the company.

    With `\\s+` as the separator this matched "Tobias Renner\\nMeridian Freight"
    as a single organization -- swallowing a person into an ORG span and losing
    both labels.
    """
    assert found("Tobias Renner\nMeridian Freight") == ["Meridian Freight"]


def test_requires_a_capitalized_suffix():
    """"Insurance group 3141-5926" is a policy reference, not an organization."""
    assert found("Insurance group 3141-5926 (not an SSN).") == []
    assert found("Prior clinic fax line is closed.") == []


def test_requires_a_name_before_the_suffix():
    assert found("The Company will respond.") == []
    assert found("Insurance is required.") == []


def test_ignores_a_street_that_ends_in_a_suffix_word():
    """"North University Ave" is an address; the address layers own it."""
    assert found("640 North University Ave, Providence") == []


# -- boundary details ---------------------------------------------------


def test_strips_an_introducing_label():
    """The organization is Brightwave Analytics, not "Company Brightwave Analytics"."""
    assert found("Company Brightwave Analytics.") == ["Brightwave Analytics"]


def test_keeps_a_period_that_abbreviates_the_suffix():
    assert found("Cascadia Timber Co. filed") == ["Cascadia Timber Co."]
    assert found("Acme Corp. filed") == ["Acme Corp."]


def test_drops_a_sentence_period():
    assert found("Renewal with Brightwave Analytics.") == ["Brightwave Analytics"]


def test_offsets_point_at_the_matched_text():
    text = "Spoke with Deltaform Labs today."
    (span,) = detector.detect(text)
    assert text[span.start : span.end] == span.text == "Deltaform Labs"
    assert span.label == "ORG"


def test_runs_in_the_base_detector_set():
    """No spaCy, no network -- the suffix layer ships in the zero-install tool."""
    result = Pipeline().redact("Claim handled by Harborlight Insurance today.")
    assert "Harborlight" not in result.redacted
    assert result.clean
