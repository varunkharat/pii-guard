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


def _plausible_org(value: str) -> bool:
    """Reject bare uppercase acronyms tagged as organizations.

    spaCy labels SSN, IBAN, INFO, HRIS and similar field labels and log levels
    as ORG. In forms, logs and config files those are pervasive and always
    wrong. A real organization name in a document almost always carries a
    lowercase letter or spans multiple tokens.
    """
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
        spans: list[Span] = []

        for ent in doc.ents:
            label = LABEL_MAP.get(ent.label_)
            if label is None:
                continue

            start, end = ent.start_char, ent.end_char

            # spaCy entities routinely run past the value into the next line's
            # field label, producing spans like "Alice Chen\nEmail". In forms,
            # logs and CSVs a single PII value never spans lines, so cut there.
            newline = text.find("\n", start, end)
            if newline != -1:
                end = newline

            while end > start and text[end - 1].isspace():
                end -= 1
            while start < end and text[start].isspace():
                start += 1
            if start >= end:
                continue

            value = text[start:end]

            # Checked after trimming so it sees the cleaned span, not spaCy's.
            if label == "ORG" and not _plausible_org(value):
                continue

            spans.append(
                Span(
                    start=start,
                    end=end,
                    label=label,
                    text=value,
                    score=NER_SCORE,
                    detector=self.name,
                )
            )

        return spans