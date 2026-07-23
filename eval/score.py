"""Score the detector against the labeled corpus.

Usage:
    python eval/score.py                 # all fixtures
    python eval/score.py --partial       # count overlap as a hit, not exact match

Fixture format (tests/fixtures/*.json):

    {
      "id": "support-ticket-01",
      "text": "...",
      "spans": [{"start": 12, "end": 24, "label": "EMAIL"}]
    }

Run this before and after every detector change. If you cannot say what the
numbers did, you do not know whether the change helped.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from piiguard.pipeline import Pipeline  # noqa: E402
from piiguard.detectors import RegexDetector  # noqa: E402
from piiguard.detectors.ner import NerDetector  # noqa: E402

FIXTURES = Path(__file__).resolve().parents[1] / "tests" / "fixtures"


def load_fixtures() -> list[dict]:
    docs = []
    for path in sorted(FIXTURES.glob("*.json")):
        docs.append(json.loads(path.read_text()))
    return docs


def match(pred, gold, partial: bool) -> bool:
    if pred.label != gold["label"]:
        return False
    if partial:
        return pred.start < gold["end"] and gold["start"] < pred.end
    return pred.start == gold["start"] and pred.end == gold["end"]


def prf(tp: int, fp: int, fn: int) -> tuple[float, float, float]:
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    return precision, recall, f1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--partial", action="store_true")
    args = ap.parse_args()

    pipeline = Pipeline(detectors=[RegexDetector(), NerDetector()])
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0}
    )
    misses: list[tuple[str, str, str]] = []

    for doc in load_fixtures():
        predicted = pipeline.scan(doc["text"])
        gold = list(doc["spans"])
        used = set()

        for pred in predicted:
            hit = next(
                (
                    i
                    for i, g in enumerate(gold)
                    if i not in used and match(pred, g, args.partial)
                ),
                None,
            )
            if hit is None:
                counts[pred.label]["fp"] += 1
                misses.append((doc["id"], "FP", f"{pred.label} {pred.text!r}"))
            else:
                used.add(hit)
                counts[pred.label]["tp"] += 1

        for i, g in enumerate(gold):
            if i not in used:
                counts[g["label"]]["fn"] += 1
                snippet = doc["text"][g["start"] : g["end"]]
                misses.append((doc["id"], "FN", f"{g['label']} {snippet!r}"))

    print(f"{'LABEL':<16}{'P':>8}{'R':>8}{'F1':>8}{'TP':>6}{'FP':>6}{'FN':>6}")
    print("-" * 58)
    total = {"tp": 0, "fp": 0, "fn": 0}
    for label in sorted(counts):
        c = counts[label]
        for k in total:
            total[k] += c[k]
        p, r, f = prf(c["tp"], c["fp"], c["fn"])
        print(
            f"{label:<16}{p:>8.3f}{r:>8.3f}{f:>8.3f}"
            f"{c['tp']:>6}{c['fp']:>6}{c['fn']:>6}"
        )
    print("-" * 58)
    p, r, f = prf(total["tp"], total["fp"], total["fn"])
    print(
        f"{'OVERALL':<16}{p:>8.3f}{r:>8.3f}{f:>8.3f}"
        f"{total['tp']:>6}{total['fp']:>6}{total['fn']:>6}"
    )

    if misses:
        print("\nErrors:")
        for doc_id, kind, detail in misses:
            print(f"  [{kind}] {doc_id}: {detail}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
