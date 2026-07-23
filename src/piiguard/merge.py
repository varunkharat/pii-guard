"""Resolve overlapping spans produced by different detector layers.

When the regex layer says [12,23) is a PHONE_US and the NER layer says
[12,30) is a PERSON, something has to win. The rule here: prefer the higher
score, break ties by longer span, then by detector priority order.

This module is small but it is where a lot of the tool's real-world quality
lives -- get it wrong and you either leak PII or mangle clean text.
"""

from __future__ import annotations

from .types import Span

DEFAULT_PRIORITY = ["regex", "ner", "llm"]


def merge_spans(
    spans: list[Span], priority: list[str] | None = None
) -> list[Span]:
    """Return non-overlapping spans sorted by start offset."""
    priority = priority or DEFAULT_PRIORITY

    def rank(span: Span) -> tuple:
        try:
            detector_rank = priority.index(span.detector)
        except ValueError:
            detector_rank = len(priority)
        return (-span.score, -span.length, detector_rank, span.start)

    kept: list[Span] = []
    for span in sorted(spans, key=rank):
        if any(span.overlaps(k) for k in kept):
            continue
        kept.append(span)
    return sorted(kept, key=lambda s: (s.start, s.end))
