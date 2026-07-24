"""Layer 3 tests that need no running model.

The network round-trip cannot be exercised without an Ollama server, but the
parts that keep a fallible model safe -- verbatim offset mapping, dropping
hallucinations, failing closed to a no-op, and never leaving loopback -- are
pure or observable here, and those are the parts that matter for trust.
"""

from __future__ import annotations

import json

from piiguard.detectors.llm import LlmDetector


def _resp(findings):
    return json.dumps({"findings": findings})


def test_locate_maps_verbatim_substrings_to_real_offsets():
    text = "Contact Jane Roe at Acme Corp about the invoice."
    spans = LlmDetector()._locate(
        text,
        _resp([
            {"text": "Jane Roe", "label": "PERSON"},
            {"text": "Acme Corp", "label": "ORG"},
        ]),
    )
    by_label = {s.label: s for s in spans}
    assert text[by_label["PERSON"].start : by_label["PERSON"].end] == "Jane Roe"
    assert text[by_label["ORG"].start : by_label["ORG"].end] == "Acme Corp"
    assert all(s.detector == "llm" for s in spans)


def test_locate_drops_hallucinated_text():
    text = "Contact Jane Roe about the invoice."
    # The model invents a name that is not in the source.
    spans = LlmDetector()._locate(
        text, _resp([{"text": "John Smith", "label": "PERSON"}])
    )
    assert spans == []


def test_locate_drops_unknown_labels():
    text = "Contact Jane Roe about the invoice."
    spans = LlmDetector()._locate(
        text, _resp([{"text": "Jane Roe", "label": "WIZARD"}])
    )
    assert spans == []


def test_locate_finds_every_occurrence():
    text = "Roe called Roe."
    spans = LlmDetector()._locate(text, _resp([{"text": "Roe", "label": "PERSON"}]))
    assert [s.start for s in spans] == [0, 11]


def test_locate_survives_malformed_output():
    text = "anything"
    assert LlmDetector()._locate(text, "not json at all") == []
    assert LlmDetector()._locate(text, None) == []
    assert LlmDetector()._locate(text, _resp("not-a-list")) == []


def test_detect_is_a_noop_when_server_is_down():
    # No Ollama here: detect must return [] and never raise.
    assert LlmDetector().detect("Contact Jane Roe at Acme Corp.") == []


def test_available_is_false_without_a_server():
    assert LlmDetector().available() is False


def test_never_connects_off_loopback():
    # A non-loopback host must never be contacted: the egress guard trips,
    # detect() swallows it to a no-op, and available() reports down.
    d = LlmDetector(host="example.com")
    assert d.available() is False
    assert d.detect("Contact Jane Roe.") == []
