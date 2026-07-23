"""Core data types shared across detectors, policies, and the pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, order=True)
class Span:
    """A detected span of PII in a source string.

    Offsets are character offsets into the original text, half-open [start, end).
    """

    start: int
    end: int
    label: str
    text: str = field(compare=False)
    score: float = field(default=1.0, compare=False)
    detector: str = field(default="", compare=False)

    def __post_init__(self) -> None:
        if self.start < 0 or self.end < self.start:
            raise ValueError(f"invalid span offsets: [{self.start}, {self.end})")

    @property
    def length(self) -> int:
        return self.end - self.start

    def overlaps(self, other: "Span") -> bool:
        return self.start < other.end and other.start < self.end


class Detector(Protocol):
    """Anything that can find PII in text.

    Every detector layer (regex, NER, optional local LLM) implements this.
    Detectors must be pure and must not perform network I/O.
    """

    name: str

    def detect(self, text: str) -> list[Span]:  # pragma: no cover - protocol
        ...
