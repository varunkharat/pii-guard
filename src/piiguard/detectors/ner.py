"""Layer 2: named-entity detection via spaCy.

Catches what regex fundamentally cannot -- people, organizations, places.
The model loads from disk; no network access at runtime.

Presidio was the obvious choice here and was tried first. It turned out to be
a wrapper we weren't using: its regex recognizers are disabled because layer 1
beats them on every shared label, and it drops ORGANIZATION from its default
entity set. Calling spaCy directly removes a dependency and gives us control
over span boundaries, which is the main open problem in this layer.
"""

from __future__ import annotations

from ..types import Span

# spaCy entity types -> our labels.
# GPE (geopolitical), LOC and FAC all contribute to addresses. spaCy returns
# them as separate fragments -- "900 Harbor Blvd", "Oakland" -- so downstream
# merging of adjacent same-label spans is still needed to reconstruct a full
# address. That is deliberate and tracked separately.
LABEL_MAP = {
    "PERSON": "PERSON",
    "ORG": "ORG",
    "GPE": "ADDRESS",
    "LOC": "ADDRESS",
    "FAC": "ADDRESS",
}

# spaCy's NER head does not expose calibrated confidences, so every span gets
# a fixed score below the regex layer's 1.0. That ordering matters: when the
# two layers overlap, the validated regex match wins.
NER_SCORE = 0.85

# spaCy tags bare uppercase acronyms as organizations. In documents full of
# field labels and log levels -- SSN, IBAN, INFO, HRIS -- that is almost always
# wrong, and a real org name in a document nearly always appears with at least
# one lowercase letter or multiple tokens.
def _plausible_org(value: str) -> bool:
    if value.isupper() and len(value) <= 5:
        return False
    if len(value.split()) == 1 and value.isupper():
        return False
    return True

class NerDetector:
    name = "ner"

    def __init__(self, model: str = "en_core_web_lg") -> None:
        import spacy

        self._nlp = spacy.load(model, disable=["lemmatizer", "textcat"])

    def detect(self, text: str) -> list[Span]:
        doc = self._nlp(text)
        spans = []
        for ent in doc.ents:
            label = LABEL_MAP.get(ent.label_)
            if label is None:
                continue
            # spaCy spans routinely swallow trailing whitespace and newlines,
            # which produced errors like "Alice Chen\nEmail". Trim to the
            # actual entity text before recording offsets.
            start, end = ent.start_char, ent.end_char
            newline = text.find("\n", start, end)
            if newline != -1:
                end = newline
            while end > start and text[end - 1].isspace():
                end -= 1
            while start < end and text[start].isspace():
                start += 1
            if start >= end:
                continue
            spans.append(
                Span(
                    start=start,
                    end=end,
                    label=label,
                    text=text[start:end],
                    score=NER_SCORE,
                    detector=self.name,
                )
            )
        return spans
    