"""High-precision structured-PII detection using regex plus real validators.

This is deliberately the first layer: no models, no dependencies, microsecond
latency, and very few false positives. It establishes the baseline that later
NER and LLM layers have to beat.
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
RESERVED_TLDS = (".invalid", ".test", ".localhost")


def email_valid(value: str) -> bool:
    """Reject addresses that are structurally incapable of being real."""
    domain = value.rsplit("@", 1)[-1].lower()
    return not domain.endswith(RESERVED_TLDS)
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
        None,
    ),
    "IPV4": (
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
        None,
    ),
    "IBAN": (
        re.compile(r"\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b"),
        iban_valid,
    ),
}


class RegexDetector:
    """Structured PII with format validation."""

    name = "regex"

    def __init__(self, labels: list[str] | None = None) -> None:
        self.labels = labels or list(PATTERNS)

    def detect(self, text: str) -> list[Span]:
        spans: list[Span] = []
        for label in self.labels:
            pattern, validator = PATTERNS[label]
            for match in pattern.finditer(text):
                value = match.group(0)
                if validator is not None and not validator(value):
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
