"""Transformation policies.

Detection decides *what* is PII. Policy decides *what to do about it*, which is
a separate and often per-label decision:

    mask          555-12-1234        -> ***-**-****
    label         Alice Chen         -> [PERSON_1]
    pseudonymize  Alice Chen         -> Dana Whitfield   (stable across a run)
    keep          leave it alone (useful for allowlisted values)

Pseudonymization is deterministic: the same input value maps to the same
surrogate everywhere in the run, so documents stay readable and coreference
survives redaction. The mapping is derived from a locally generated salt and is
never written to disk unless the caller asks for it.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass, field
from hashlib import sha256

from ..types import Span

FIRST_NAMES = [
    "Dana", "Rowan", "Sasha", "Emery", "Quinn", "Reese", "Blake", "Harper",
    "Marlow", "Teagan", "Ellis", "Nova", "Jules", "Arden", "Sloane", "Wren",
]
LAST_NAMES = [
    "Whitfield", "Alvarez", "Okafor", "Lindqvist", "Barros", "Nakamura",
    "Delacroix", "Vasquez", "Ferreira", "Osei", "Kowalski", "Bennett",
]

MODES = ("mask", "label", "pseudonymize", "keep")


@dataclass
class Policy:
    """Per-label handling with a default fallback."""

    default: str = "label"
    per_label: dict[str, str] = field(default_factory=dict)

    def mode_for(self, label: str) -> str:
        mode = self.per_label.get(label, self.default)
        if mode not in MODES:
            raise ValueError(f"unknown policy mode {mode!r} for label {label!r}")
        return mode


class PolicyEngine:
    def __init__(self, policy: Policy | None = None, salt: bytes | None = None):
        self.policy = policy or Policy()
        # Ephemeral by default: surrogates are not reversible across runs
        # unless the caller deliberately persists the salt.
        self.salt = salt or secrets.token_bytes(32)
        self._counters: dict[str, int] = {}
        self._assigned: dict[tuple[str, str], str] = {}

    # -- surrogate generation ------------------------------------------

    def _digest(self, label: str, value: str) -> int:
        mac = hmac.new(self.salt, f"{label}:{value}".encode(), sha256)
        return int.from_bytes(mac.digest()[:8], "big")

    def _pseudonym(self, label: str, value: str) -> str:
        key = (label, value.strip().lower())
        if key in self._assigned:
            return self._assigned[key]
        h = self._digest(label, key[1])
        if label == "PERSON":
            surrogate = (
                f"{FIRST_NAMES[h % len(FIRST_NAMES)]} "
                f"{LAST_NAMES[(h // 97) % len(LAST_NAMES)]}"
            )
        elif label == "EMAIL":
            surrogate = f"user{h % 10_000:04d}@example.invalid"
        else:
            surrogate = f"[{label}_{h % 1000:03d}]"
        self._assigned[key] = surrogate
        return surrogate

    def _label_token(self, label: str, value: str) -> str:
        key = (label, value.strip().lower())
        if key in self._assigned:
            return self._assigned[key]
        self._counters[label] = self._counters.get(label, 0) + 1
        token = f"[{label}_{self._counters[label]}]"
        self._assigned[key] = token
        return token

    @staticmethod
    def _mask(value: str) -> str:
        return "".join("*" if c.isalnum() else c for c in value)

    # -- application ----------------------------------------------------

    def replacement_for(self, span: Span) -> str:
        mode = self.policy.mode_for(span.label)
        if mode == "keep":
            return span.text
        if mode == "mask":
            return self._mask(span.text)
        if mode == "pseudonymize":
            return self._pseudonym(span.label, span.text)
        return self._label_token(span.label, span.text)

    def apply(self, text: str, spans: list[Span]) -> str:
        """Rewrite text right-to-left so offsets stay valid.

        Tokens are assigned in a left-to-right pre-pass first, otherwise
        [IPV4_1] ends up numbered from the bottom of the document upward.
        """
        for span in sorted(spans, key=lambda s: s.start):
            self.replacement_for(span)

        out = text
        for span in sorted(spans, key=lambda s: s.start, reverse=True):
            out = out[: span.start] + self.replacement_for(span) + out[span.end :]
        return out

    @property
    def mapping(self) -> dict[str, str]:
        """Original -> surrogate, for audit. Contains PII; handle with care."""
        return {value: surrogate for (_, value), surrogate in self._assigned.items()}

    @property
    def surrogates(self) -> set[str]:
        """Every replacement value this engine has emitted.

        Realistic surrogates are a double-edged sword: a fake email still looks
        like an email, so the verify pass will flag it as a leak unless it can
        tell the two apart. This set is how it tells them apart.
        """
        return set(self._assigned.values())
