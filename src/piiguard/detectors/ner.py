"""Layer 2: named-entity detection via Presidio + spaCy.

Catches what regex fundamentally cannot -- people, organizations, places.
The model runs locally from disk; no network access at runtime.

Presidio ships its own regex recognizers for emails, phones, SSNs and cards.
Those are deliberately disabled here: layer 1 already handles them with real
validators and scores 1.000, and running both would mean two systems
disagreeing about the same span for no benefit.
"""

from __future__ import annotations

from ..types import Span

# Presidio's entity names -> our label set.
# This mapping is lossy on purpose and worth revisiting: LOCATION is broader
# than ADDRESS, and DATE_TIME is much broader than DOB. Expect precision to
# drop on those two labels before it improves.
LABEL_MAP = {
    "PERSON": "PERSON",
    "ORGANIZATION": "ORG",
    "LOCATION": "ADDRESS",
}


class NerDetector:
    name = "ner"

    def __init__(self, min_score: float = 0.4) -> None:
        from presidio_analyzer import AnalyzerEngine

        self._engine = AnalyzerEngine()
        self.min_score = min_score

    def detect(self, text: str) -> list[Span]:
        results = self._engine.analyze(
            text=text,
            entities=list(LABEL_MAP),
            language="en",
            score_threshold=self.min_score,
        )
        spans = []
        for r in results:
            label = LABEL_MAP.get(r.entity_type)
            if label is None:
                continue
            spans.append(
                Span(
                    start=r.start,
                    end=r.end,
                    label=label,
                    text=text[r.start : r.end],
                    score=r.score,
                    detector=self.name,
                )
            )
        return spans