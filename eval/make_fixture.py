"""Turn inline-marked text into a labeled fixture, so you never hand-count offsets.

Write a .txt file with PII wrapped in markers:

    Contact {{EMAIL:alice@corp.example}} or call {{PHONE_US:415-555-0142}}.

Then:

    python eval/make_fixture.py raw/ticket01.txt --id support-ticket-01

Writes tests/fixtures/support-ticket-01.json with exact character offsets.
Include hard negatives (near-miss values with no marker) on purpose -- they are
what stop the detector from getting lazy.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

MARKER = re.compile(r"\{\{([A-Z0-9_]+):(.*?)\}\}", re.DOTALL)
FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"


def build(marked: str) -> tuple[str, list[dict]]:
    out: list[str] = []
    spans: list[dict] = []
    cursor = 0
    for m in MARKER.finditer(marked):
        out.append(marked[cursor : m.start()])
        start = sum(len(chunk) for chunk in out)
        value = m.group(2)
        out.append(value)
        spans.append({"start": start, "end": start + len(value), "label": m.group(1)})
        cursor = m.end()
    out.append(marked[cursor:])
    return "".join(out), spans


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--id", required=True)
    args = ap.parse_args()

    text, spans = build(Path(args.path).read_text(encoding="utf-8"))
    FIXTURES.mkdir(parents=True, exist_ok=True)
    dest = FIXTURES / f"{args.id}.json"
    dest.write_text(
        json.dumps({"id": args.id, "text": text, "spans": spans}, indent=2) + "\n"
    )
    print(f"wrote {dest} ({len(spans)} labeled span(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
