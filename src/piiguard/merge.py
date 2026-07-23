"""Resolve overlapping spans, then reassemble fragmented ones.

Two passes, and they do opposite things:

1. merge_spans   -- when two detectors claim overlapping text, pick one.
2. join_adjacent -- when one real-world value arrives as several spans,
                    glue them back together.

Pass 2 exists because NER returns addresses in pieces. spaCy sees
"900 Harbor Blvd, Suite 210, Oakland, CA 94607" as a FAC, a couple of GPEs,
and sometimes an ORG -- never one address. Redacting the pieces leaves the
connective tissue behind, and "Suite 210" plus a ZIP is still identifying.

The joining rule is deliberately biased toward over-redaction. For a scrubber,
destroying an extra comma costs nothing and leaking a house number costs
everything.
"""

from __future__ import annotations

import re

from .types import Span

DEFAULT_PRIORITY = ["regex", "ner", "llm"]

# Labels that can be fused into a single address. ORG is here because spaCy
# routinely mislabels address tails ("CA 94607", "Redwood Ct") as
# organizations; when such a span sits directly beside a confirmed address
# fragment, treating it as part of the address is the better reading.
ADDRESS_LIKE = {"ADDRESS", "ORG"}

# ...but only when the ORG span actually looks like part of an address: a
# state + ZIP, or a street or unit designator. Absorbing any adjacent ORG
# fused "B.S. Computer Science" and "UC Santa Cruz" into one bogus address,
# and lost a real organization in the process.
ADDRESS_TAIL = re.compile(
    r"^(?:[A-Z]{2}\s*\d{5}(?:-\d{4})?"
    r"|.*\b(?:St|Ave|Blvd|Rd|Ln|Dr|Ct|Way|Pkwy|Hwy|Ste|Suite|Apt|Unit)\.?)$",
    re.IGNORECASE,
)

# Text permitted between two fragments of one address: separators plus short
# unit designators. Anything longer or containing a newline ends the address.
CONNECTOR = re.compile(r"^[\s,.#-]*(?:[A-Za-z]{1,6}\.?\s*[\w-]{1,6}[\s,.#-]*)?$")
MAX_GAP = 20

# A street number immediately preceding the first fragment. spaCy leaves it
# out of the entity, so "1847 Fillmore St" arrives as "Fillmore St".
LEADING_NUMBER = re.compile(r"(\d{1,6}(?:-\d{1,4})?)\s+$")


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


def _joinable(text: str, left: Span, right: Span) -> bool:
    if left.label not in ADDRESS_LIKE or right.label not in ADDRESS_LIKE:
        return False
    for side in (left, right):
        if side.label == "ORG" and not ADDRESS_TAIL.match(side.text.strip()):
            return False
    if "ADDRESS" not in (left.label, right.label):
        return False  # two ORGs side by side are two organizations
    gap = text[left.end : right.start]
    if len(gap) > MAX_GAP or "\n" in gap:
        return False
    return bool(CONNECTOR.match(gap))


def join_adjacent(text: str, spans: list[Span]) -> list[Span]:
    """Fuse address fragments separated only by connective text.

    Never crosses a newline: in forms, logs and CSVs a value stays on its line,
    and crossing rows would glue unrelated records together.
    """
    if not spans:
        return spans

    out: list[Span] = []
    current = spans[0]

    for nxt in spans[1:]:
        if _joinable(text, current, nxt):
            current = Span(
                start=current.start,
                end=nxt.end,
                label="ADDRESS",
                text=text[current.start : nxt.end],
                score=min(current.score, nxt.score),
                detector="merge",
            )
        else:
            out.append(current)
            current = nxt
    out.append(current)

    return [_extend_left(text, s) for s in out]


def _extend_left(text: str, span: Span) -> Span:
    """Pull a street number into an address span.

    spaCy tags "Fillmore St" but not the "1847" in front of it, so the house
    number survives redaction -- which is exactly the digit an address is
    most identified by.
    """
    if span.label != "ADDRESS":
        return span
    line_start = text.rfind("\n", 0, span.start) + 1
    prefix = text[line_start : span.start]
    m = LEADING_NUMBER.search(prefix)
    if not m:
        return span
    new_start = span.start - (len(prefix) - m.start(1))
    return Span(
        start=new_start,
        end=span.end,
        label="ADDRESS",
        text=text[new_start : span.end],
        score=span.score,
        detector=span.detector,
    )
