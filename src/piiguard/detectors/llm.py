"""Layer 3: a local LLM (Ollama) for context-dependent PII the first two miss.

Layers 1 and 2 are strong on things with a shape or a name-entity signature. A
local model earns its place only on the residue -- an organization phrased
oddly, a person referred to obliquely, an address a parser fragments. It runs
entirely on this machine via Ollama, reached through localnet's loopback-only
guard; it never touches an external network.

Two design choices keep a fallible model from doing harm:

  * The model returns verbatim substrings and labels, never character offsets.
    Models are unreliable at arithmetic on positions but reliable at copying
    text. We find the offsets ourselves, and anything the model did not copy
    exactly is discarded -- a hallucinated span simply fails to match.
  * A missing or slow server is a no-op, not an error. If Ollama is not
    running, layer 3 contributes nothing and the pipeline proceeds on layers
    1 and 2. A redaction tool must never fail open because an optional model
    was unavailable.

Its spans score below every other layer, so on any overlap the validated
regex or the NER span wins.
"""

from __future__ import annotations

import json

from ..localnet import DEFAULT_TIMEOUT, EgressError, local_connection
from ..types import Span

# Labels we accept back from the model, mapped onto our own. Anything else is
# dropped rather than trusted.
KNOWN_LABELS = {
    "PERSON", "ORG", "ADDRESS", "EMAIL", "PHONE_US",
    "SSN", "CREDIT_CARD", "IPV4", "IBAN", "DOB",
}

LLM_SCORE = 0.6  # below regex (1.0), structured (0.95), NER (0.85)

PROMPT = (
    "You are a PII detector. Find every span of personally identifying "
    "information in the TEXT below. Return JSON of the form "
    '{{"findings": [{{"text": "<exact substring copied from TEXT>", '
    '"label": "<LABEL>"}}]}}. Allowed labels: PERSON, ORG, ADDRESS, EMAIL, '
    "PHONE_US, SSN, CREDIT_CARD, IPV4, IBAN, DOB. Copy each substring exactly "
    "as it appears, character for character. If there is no PII, return "
    '{{"findings": []}}. Do not explain.\n\nTEXT:\n{text}'
)


class LlmDetector:
    """Context-dependent PII via a local Ollama model. Loopback only."""

    name = "llm"

    def __init__(
        self,
        model: str = "llama3.2",
        host: str = "127.0.0.1",
        port: int = 11434,
        timeout: float = 60.0,
    ) -> None:
        self.model = model
        self.host = host
        self.port = port
        self.timeout = timeout

    # -- network -------------------------------------------------------

    def available(self) -> bool:
        """True if a server answers on the loopback endpoint."""
        try:
            conn = local_connection(self.host, self.port, timeout=DEFAULT_TIMEOUT)
            conn.request("GET", "/api/tags")
            resp = conn.getresponse()
            resp.read()
            return resp.status == 200
        except (OSError, EgressError):
            return False

    def _query(self, text: str) -> str | None:
        """Return the model's raw response string, or None on any failure."""
        body = json.dumps(
            {
                "model": self.model,
                "prompt": PROMPT.format(text=text),
                "stream": False,
                "format": "json",
            }
        )
        try:
            conn = local_connection(self.host, self.port, timeout=self.timeout)
            conn.request(
                "POST",
                "/api/generate",
                body=body,
                headers={"Content-Type": "application/json"},
            )
            resp = conn.getresponse()
            raw = resp.read()
            if resp.status != 200:
                return None
            return json.loads(raw).get("response")
        except (OSError, EgressError, ValueError):
            return None

    # -- parsing (pure; unit-tested without a server) ------------------

    def _locate(self, text: str, response: str | None) -> list[Span]:
        """Turn the model's {findings:[{text,label}]} into located spans.

        Only substrings that appear verbatim in the source become spans, at
        the real offsets. A finding the model paraphrased or invented is
        silently dropped.
        """
        if not response:
            return []
        try:
            findings = json.loads(response).get("findings", [])
        except (ValueError, AttributeError):
            return []
        if not isinstance(findings, list):
            return []

        spans: list[Span] = []
        for item in findings:
            if not isinstance(item, dict):
                continue
            value = item.get("text")
            label = item.get("label")
            if not isinstance(value, str) or not isinstance(label, str):
                continue
            value = value.strip()
            label = label.strip().upper()
            if len(value) < 2 or label not in KNOWN_LABELS:
                continue
            start = text.find(value)
            while start != -1:
                spans.append(
                    Span(
                        start=start,
                        end=start + len(value),
                        label=label,
                        text=value,
                        score=LLM_SCORE,
                        detector=self.name,
                    )
                )
                start = text.find(value, start + len(value))
        return spans

    # -- detector interface --------------------------------------------

    def detect(self, text: str) -> list[Span]:
        return self._locate(text, self._query(text))
