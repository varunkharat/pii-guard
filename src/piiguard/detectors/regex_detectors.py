"""High-precision structured-PII detection using regex plus real validators.

This is deliberately the first layer: no models, no dependencies, microsecond
latency, and very few false positives. It establishes the baseline that later
NER and LLM layers have to beat.

Two kinds of rule live here:

  * Format rules -- a value is PII because of its shape, and a validator
    confirms the shape is real (Luhn, SSA allocation, IBAN mod-97).
  * Context rules -- a value is PII because of what sits next to it. A bare
    ISO date is not sensitive; the same date after "DOB:" is. These use
    CONTEXT_REQUIRED and look backward on the same line for a cue.

The second kind matters more than it first appears. Mapping every date to a
birth date produced seventeen false positives on a ten-document corpus. The
cue is what makes the value sensitive, so the cue has to be part of the rule.
"""

from __future__ import annotations

import re

from ..types import Span

# --------------------------------------------------------------------------
# Validators
# --------------------------------------------------------------------------


def luhn_valid(digits: str) -> bool:
    """Luhn checksum. Rejects most 16-digit numbers that aren't card numbers."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 12:
        return False
    total = 0
    for i, n in enumerate(reversed(nums)):
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def ssn_valid(value: str) -> bool:
    """SSA allocation rules. Kills a large class of look-alike false positives."""
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in {"000", "666"} or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def iban_valid(value: str) -> bool:
    """ISO 13616 mod-97 check."""
    v = re.sub(r"\s", "", value).upper()
    if len(v) < 15 or len(v) > 34:
        return False
    rearranged = v[4:] + v[:4]
    converted = "".join(
        str(ord(c) - 55) if c.isalpha() else c for c in rearranged
    )
    if not converted.isdigit():
        return False
    return int(converted) % 97 == 1


# RFC 2606 / RFC 6761 reserve these; they can never resolve to a real mailbox.
# ".example" is deliberately absent: it is the canonical domain for synthetic
# data and documentation, so rejecting it would discard most of a test corpus.
RESERVED_TLDS = (".invalid", ".test", ".localhost")


def email_valid(value: str) -> bool:
    """Reject addresses that are structurally incapable of being real."""
    domain = value.rsplit("@", 1)[-1].lower()
    return not domain.endswith(RESERVED_TLDS)


def phone_valid(value: str) -> bool:
    """Reject placeholder and test numbers."""
    digits = re.sub(r"\D", "", value)
    digits = digits[1:] if len(digits) == 11 and digits[0] == "1" else digits
    if len(digits) != 10:
        return False
    if len(set(digits)) == 1:  # 0000000000, 1111111111
        return False
    if digits[0] in "01" or digits[3] in "01":  # invalid NANP area/exchange
        return False
    return True


def ipv4_valid(value: str) -> bool:
    """Reject addresses that cannot identify a person."""
    octets = [int(o) for o in value.split(".")]
    if octets[0] == 0 or octets[0] >= 224:  # unspecified, multicast, reserved
        return False
    if octets == [255, 255, 255, 255]:
        return False
    if octets[3] == 0:  # network base, e.g. 192.168.0.0
        return False
    return True


US_STATES = {
    "AL", "AK", "AZ", "AR", "CA", "CO", "CT", "DE", "FL", "GA", "HI", "ID",
    "IL", "IN", "IA", "KS", "KY", "LA", "ME", "MD", "MA", "MI", "MN", "MS",
    "MO", "MT", "NE", "NV", "NH", "NJ", "NM", "NY", "NC", "ND", "OH", "OK",
    "OR", "PA", "RI", "SC", "SD", "TN", "TX", "UT", "VT", "VA", "WA", "WV",
    "WI", "WY", "DC", "PR", "VI", "GU", "AS", "MP",
}


def state_zip_valid(value: str) -> bool:
    """Require a real postal abbreviation.

    Without this, "IN 12345" and "OR 90210" match in ordinary prose. Emitted
    as ADDRESS rather than its own label so the merge pass can fuse it onto
    the street fragment NER found -- the ZIP is the part that most reliably
    identifies a household, and it was leaking.
    """
    return value.split()[0].upper() in US_STATES


# --------------------------------------------------------------------------
# Patterns
# --------------------------------------------------------------------------

PATTERNS: dict[str, tuple[re.Pattern[str], object]] = {
    "EMAIL": (
        re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
        email_valid,
    ),
    "SSN": (
        re.compile(r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"),
        ssn_valid,
    ),
    "CREDIT_CARD": (
        re.compile(r"\b(?:\d[ -]*?){13,19}\b"),
        luhn_valid,
    ),
    "PHONE_US": (
        re.compile(
            r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)"
        ),
        phone_valid,
    ),
    "IPV4": (
        re.compile(
            r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
        ),
        ipv4_valid,
    ),
    "IBAN": (
        re.compile(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b"),
        iban_valid,
    ),
    "ADDRESS": (
        re.compile(r"\b[A-Z]{2}\s+\d{5}(?:-\d{4})?\b"),
        state_zip_valid,
    ),
    "DOB": (
        re.compile(
            r"\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}[/-]\d{1,2}[/-]\d{2,4})\b"
        ),
        None,
    ),
}

# Labels whose matches are only PII when a cue appears earlier on the same
# line. The pattern is searched against the text between the line start and
# the match, so "DOB: 1987-03-14" fires and a bare log timestamp does not.
CONTEXT_REQUIRED: dict[str, re.Pattern[str]] = {
    "DOB": re.compile(
        r"(?:\bD\.?O\.?B\.?\b|date\s+of\s+birth|birth\s*day|\bborn\b)"
        r"[\s:=-]*$",
        re.IGNORECASE,
    ),
}


class RegexDetector:
    """Structured PII with format validation and, where needed, context."""

    name = "regex"

    def __init__(self, labels: list[str] | None = None) -> None:
        self.labels = labels or list(PATTERNS)

    def _has_context(self, text: str, label: str, start: int) -> bool:
        cue = CONTEXT_REQUIRED.get(label)
        if cue is None:
            return True
        line_start = text.rfind("\n", 0, start) + 1
        return bool(cue.search(text[line_start:start]))

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for label in self.labels:
            pattern, validator = PATTERNS[label]
            for match in pattern.finditer(text):
                value = match.group(0)
                if validator is not None and not validator(value):
                    continue
                if not self._has_context(text, label, match.start()):
                    continue
                spans.append(
                    Span(
                        start=match.start(),
                        end=match.end(),
                        label=label,
                        text=value,
                        score=1.0,
                        detector=self.name,
                    )
                )
        return spans