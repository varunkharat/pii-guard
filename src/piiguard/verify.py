"""Self-verification: re-scan our own output and fail loudly if PII survived.

A redaction tool that silently misses things is worse than no tool, because it
manufactures false confidence. This pass is cheap and it is the single highest
trust-per-line-of-code feature in the project.
"""

from __future__ import annotations

from .types import Span


class LeakError(RuntimeError):
    """Raised when redacted output still contains detectable PII."""

    def __init__(self, leaks: list[Span]):
        self.leaks = leaks
        summary = ", ".join(f"{s.label}@{s.start}" for s in leaks[:5])
        more = "" if len(leaks) <= 5 else f" (+{len(leaks) - 5} more)"
        super().__init__(f"redacted output still contains PII: {summary}{more}")


def verify(
    redacted: str,
    detectors,
    *,
    ignore_labels: frozenset[str] = frozenset(),
    known_surrogates: set[str] | None = None,
    strict: bool = True,
) -> list[Span]:
    """Re-run detection on redacted text. Returns surviving spans.

    With strict=True (the default) any survivor raises LeakError.
    ignore_labels exists for policies that intentionally keep a label.
    known_surrogates are values we generated ourselves; a pseudonymized email
    is supposed to look like an email, so it is not a leak.
    """
    known_surrogates = known_surrogates or set()
    leaks: list[Span] = []
    for detector in detectors:
        for span in detector.detect(redacted):
            if span.label in ignore_labels:
                continue
            if span.text in known_surrogates:
                continue
            leaks.append(span)

    if leaks and strict:
        raise LeakError(leaks)
    return leaks
