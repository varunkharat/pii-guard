"""Organization names identified by their legal or sector suffix.

Layer 2 misses invented organization names outright. spaCy has never seen
"Copperline Mutual" or "Valley Health Partners", and unlike a person's name
there is no morphology to fall back on -- so it returns nothing, and the name
survives redaction. ORG was the weakest label in the corpus and the whole of
the residual character leak.

But an organization usually announces itself. English names them with a closed
set of tails: a legal form (Inc, LLC, Holdings), or the sector itself
(Insurance, Analytics, University, Pharmacy). A capitalized run ending in one
of those is an organization essentially always, whether or not any model has
heard of it. That is a lexical fact, not a statistical one, so it needs no
model to exploit -- this layer is stdlib and runs in the base tool.

The rule is deliberately narrow in one direction and loose in the other: the
suffix list only holds tails that are unambiguous when capitalized, but the
name preceding a suffix is taken greedily. Over-reaching left costs a redacted
word; stopping short leaks the distinctive part of the name.
"""

from __future__ import annotations

import re

from ..types import Span

# Tails that mark an organization when capitalized. Every entry is a word that
# is either a legal form or a sector noun -- deliberately excluding softer
# tails (Center, Park, Services, Office) that routinely end non-organizations.
ORG_SUFFIXES = [
    # legal forms
    "Inc", "LLC", "LLP", "PLC", "Ltd", "Limited", "GmbH", "Corp", "Corporation",
    "Co", "Company", "Holdings", "Group", "Partners", "Associates", "Ventures",
    # finance
    "Insurance", "Assurance", "Mutual", "Bancorp", "Bank", "Capital",
    "Financial", "Investments",
    # technology / industry
    "Analytics", "Systems", "Technologies", "Networks", "Labs", "Laboratories",
    "Industries", "Enterprises", "Consulting", "Logistics", "Freight",
    "Realty", "Properties",
    # health
    "Health", "Healthcare", "Clinic", "Hospital", "Pharmacy", "Physicians",
    # education / nonprofit
    "University", "College", "Institute", "Academy", "Foundation", "Trust",
    "Society", "Association",
]

# Words that introduce an organization without being part of its name:
# "Company Brightwave Analytics" is one organization, and it is not called
# "Company Brightwave Analytics".
INTRODUCERS = frozenset({
    "company", "employer", "vendor", "business", "organization", "organisation",
    "client", "firm", "account", "customer", "provider", "insurer", "school",
})

# An article carries no more of a name than an introducer does. Stripping both
# is what separates "The Company" -- which names nobody -- from a real name.
ARTICLES = frozenset({"the", "a", "an", "our", "your", "their", "this", "that"})

# A street type right after the suffix means this is an address, not an
# organization -- "North University Ave". The address layers own that text.
_STREET_AFTER = r"(?!\s+(?:St|Ave|Blvd|Rd|Ln|Dr|Ct|Way|Pkwy|Hwy)\b\.?)"

# One to four capitalized name words, then the suffix. Internal lowercase
# function words ("of", "and", "for", "the") are allowed to keep multi-word
# names whole -- "Sisters of Mercy Hospital".
#
# The word separator is spaces and tabs, never a newline. A letterhead puts the
# addressee directly above the company, and `\s+` reached back across the line
# break to redact "Tobias Renner\nMeridian Freight" as one organization. Same
# rule the address join follows: a value stays on its line.
# Both apostrophes are deliberate: documents pasted from word processors carry
# the typographic U+2019 rather than ASCII U+0027, and a possessive company
# name has to match either form.
_NAME_WORD = r"[A-Z][\w&'’.-]*"  # noqa: RUF001
_FUNCTION_WORD = r"(?:of|and|for|the|&)"
_SEP = r"[ \t]+"

ORG_PATTERN = re.compile(
    r"\b(?:" + _NAME_WORD + _SEP + r"(?:" + _FUNCTION_WORD + _SEP + r")?){1,4}"
    r"(?:" + "|".join(ORG_SUFFIXES) + r")\b\.?" + _STREET_AFTER
)

# A suffix match is lexical evidence, not a model's guess, so it carries the
# same weight as a validated regex or a table column. That is what lets it
# correct layer 2's boundaries: where spaCy returns "Harborlight Insurance -
# Auto", this returns "Harborlight Insurance" and the merge keeps the
# higher-scoring span.
ORG_SCORE = 1.0


class OrgSuffixDetector:
    """Find organization names by their legal or sector suffix.

    stdlib only, no model, no network -- part of the base detector set.
    """

    name = "orgsuffix"

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for m in ORG_PATTERN.finditer(text):
            start, end = m.start(), m.end()
            # A trailing period belongs to the sentence unless it abbreviates
            # the suffix itself ("Acme Corp." keeps it, "...Analytics." does not).
            if text[end - 1] == "." and not _abbreviated(text[start:end]):
                end -= 1
            start = _strip_introducer(text, start, end)
            if start is None:
                continue
            spans.append(
                Span(
                    start=start,
                    end=end,
                    label="ORG",
                    text=text[start:end],
                    score=ORG_SCORE,
                    detector=self.name,
                )
            )
        return spans


def _abbreviated(matched: str) -> bool:
    """True when the final period abbreviates the suffix, as in "Corp."."""
    word = matched[:-1].split()[-1]
    return word in {"Inc", "Corp", "Ltd", "Co"}

def _strip_introducer(text: str, start: int, end: int) -> int | None:
    """Drop leading article and label words, or return None to skip the match.

    A match must keep a distinctive word alongside its suffix to be worth
    redacting. "The Company" and "Our Group" name nobody -- once the article
    and the label are gone there is no name left, and redacting them would
    destroy ordinary prose for nothing.
    """
    cursor = start
    for word in text[start:end].split():
        if word.lower().strip(".,") not in ARTICLES | INTRODUCERS:
            break
        cursor += len(word)
        while cursor < end and text[cursor].isspace():
            cursor += 1
    else:  # every word was an article or a label
        return None
    return cursor if len(text[cursor:end].split()) > 1 else None
