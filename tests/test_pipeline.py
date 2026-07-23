from __future__ import annotations

import json
from pathlib import Path

import pytest

from piiguard.detectors.regex_detectors import iban_valid, luhn_valid, ssn_valid
from piiguard.merge import merge_spans
from piiguard.pipeline import Pipeline
from piiguard.policy import Policy
from piiguard.types import Span
from piiguard.verify import LeakError, verify

FIXTURES = Path(__file__).parent / "fixtures"


# -- validators ---------------------------------------------------------


def test_luhn_accepts_real_card_and_rejects_lookalike():
    assert luhn_valid("4111111111111111")
    assert not luhn_valid("4111111111111112")


@pytest.mark.parametrize("bad", ["000-12-3456", "666-12-3456", "900-12-3456", "078-00-1120"])
def test_ssn_rejects_unallocated_ranges(bad):
    assert not ssn_valid(bad)


def test_ssn_accepts_valid():
    assert ssn_valid("078-05-1120")


def test_iban_checksum():
    assert iban_valid("GB82WEST12345698765432")
    assert not iban_valid("GB82WEST12345698765433")


# -- merge --------------------------------------------------------------


def test_higher_score_wins_overlap():
    low = Span(0, 10, "PERSON", "x", score=0.6, detector="ner")
    high = Span(2, 8, "PHONE_US", "y", score=1.0, detector="regex")
    assert merge_spans([low, high]) == [high]


def test_non_overlapping_spans_all_kept():
    a = Span(0, 5, "EMAIL", "a", detector="regex")
    b = Span(6, 9, "IPV4", "b", detector="regex")
    assert len(merge_spans([a, b])) == 2


# -- policy -------------------------------------------------------------


def test_pseudonyms_are_stable_within_a_run():
    text = "Mail alice@a.example then mail alice@a.example again."
    result = Pipeline(policy=Policy(default="pseudonymize")).redact(text)
    surrogates = {
        line for line in result.redacted.split() if "@" in line
    }
    assert len(surrogates) == 1, "same input value must map to one surrogate"


def test_mask_preserves_shape():
    result = Pipeline(policy=Policy(default="mask")).redact("SSN 078-05-1120 ok")
    assert "***-**-****" in result.redacted


def test_per_label_override():
    policy = Policy(default="label", per_label={"IPV4": "keep"})
    text = "host 73.140.22.9 mail a@b.example"
    result = Pipeline(policy=policy).redact(text)
    assert "73.140.22.9" in result.redacted
    assert "a@b.example" not in result.redacted


# -- verify -------------------------------------------------------------


def test_verify_raises_on_leak():
    from piiguard.detectors import RegexDetector

    with pytest.raises(LeakError):
        verify("still here: a@b.example", [RegexDetector()])


def test_redact_output_is_clean_for_all_fixtures():
    for path in FIXTURES.glob("*.json"):
        doc = json.loads(path.read_text())
        result = Pipeline(policy=Policy(default="label")).redact(doc["text"])
        assert result.clean, f"{path.name} leaked: {result.leaks}"


# -- end to end ---------------------------------------------------------


def test_fixture_offsets_are_self_consistent():
    for path in FIXTURES.glob("*.json"):
        doc = json.loads(path.read_text())
        for span in doc["spans"]:
            assert doc["text"][span["start"] : span["end"]].strip(), (
                f"{path.name} has an empty gold span at {span['start']}"
            )
