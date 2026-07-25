"""The pipeline: detect -> merge -> policy -> transform -> verify.

Everything runs in-process on the local machine. No detector in this package
opens a socket, and tests/test_no_egress.py asserts that as a hard property.
"""

from __future__ import annotations

from dataclasses import dataclass

from .detectors import OrgSuffixDetector, RegexDetector
from .detectors.structured import StructuredDetector
from .merge import join_adjacent, merge_spans
from .policy import Policy, PolicyEngine
from .types import Span
from .verify import verify


@dataclass
class Result:
    original: str
    redacted: str
    spans: list[Span]
    leaks: list[Span]

    @property
    def clean(self) -> bool:
        return not self.leaks


class Pipeline:
    def __init__(
        self,
        detectors: list | None = None,
        policy: Policy | None = None,
        salt: bytes | None = None,
    ) -> None:
        self.detectors = (
            detectors
            if detectors is not None
            else [RegexDetector(), StructuredDetector(), OrgSuffixDetector()]
        )
        self.policy = policy or Policy()
        self.engine = PolicyEngine(self.policy, salt=salt)

    def scan(self, text: str) -> list[Span]:
        found: list[Span] = []
        for detector in self.detectors:
            found.extend(detector.detect(text))
        return join_adjacent(text, merge_spans(found))

    def redact(self, text: str, *, strict: bool = True) -> Result:
        spans = self.scan(text)
        redacted = self.engine.apply(text, spans)
        kept = frozenset(
            label
            for label in {s.label for s in spans}
            if self.policy.mode_for(label) == "keep"
        )
        leaks = verify(
            redacted,
            self.detectors,
            ignore_labels=kept,
            known_surrogates=self.engine.surrogates,
            strict=strict,
        )
        return Result(original=text, redacted=redacted, spans=spans, leaks=leaks)
