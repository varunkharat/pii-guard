"""Score the detector against the labeled corpus.

Usage:
    python eval/score.py                 # all fixtures
    python eval/score.py --partial       # count overlap as a hit, not exact match
    python eval/score.py --no-ner        # layer 1 only, skips loading spaCy

Fixture format (tests/fixtures/*.json):

    {
      "id": "support-ticket-01",
      "text": "...",
      "spans": [{"start": 12, "end": 24, "label": "EMAIL"}]
    }

Run this before and after every detector change. If you cannot say what the
numbers did, you do not know whether the change helped.

TWO METRICS, AND THE SECOND ONE MATTERS MORE
--------------------------------------------
Span F1 asks "did we find the same spans a human would draw?" That is the
standard NER metric, and it is the wrong question for a redaction tool. It
scores a span that is one character short identically to one that missed
entirely, and it scores over-redaction identically to under-redaction.

Character coverage asks the question that actually matters: of the characters
a human marked as PII, how many survive into the output? That is the leak
rate, and it is the number to put in a README. Its counterpart, over-redaction,
measures how much clean text got destroyed along the way.

A tool with mediocre span F1 and a 0% leak rate is safe and blunt.
A tool with good span F1 and a 5% leak rate is dangerous.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from piiguard.detectors import RegexDetector  # noqa: E402
from piiguard.pipeline import Pipeline  # noqa: E402

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


def char_set(spans) -> set[int]:
    """Every character offset covered by a set of spans."""
    covered: set[int] = set()
    for s in spans:
        start = s.start if hasattr(s, "start") else s["start"]
        end = s.end if hasattr(s, "end") else s["end"]
        covered.update(range(start, end))
    return covered


def build_pipeline(use_ner: bool, use_llm: bool = False) -> Pipeline:
    from piiguard.detectors.structured import StructuredDetector

    detectors = [RegexDetector(), StructuredDetector()]
    if use_ner:
        from piiguard.detectors.ner import NerDetector

        detectors.append(NerDetector())
    if use_llm:
        from piiguard.detectors.llm import LlmDetector

        llm = LlmDetector()
        if not llm.available():
            print(
                f"note: --llm set but no Ollama server at {llm.host}:{llm.port}; "
                "layer 3 contributes nothing and these numbers are layers 1-2.",
                file=sys.stderr,
            )
        detectors.append(llm)
    return Pipeline(detectors=detectors)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--partial", action="store_true")
    ap.add_argument("--no-ner", action="store_true")
    ap.add_argument(
        "--llm",
        action="store_true",
        help="also run the local Ollama layer (needs a running server; no-op "
        "without one)",
    )
    ap.add_argument(
        "--fail-on-leak",
        metavar="LABELS",
        help="comma-separated labels that must not leak any span; exit 2 if any "
        "does. For the validator-backed labels (SSN, EMAIL, ...) this turns "
        "'these never survive redaction' into a CI-enforced property.",
    )
    ap.add_argument(
        "--max-leak-rate",
        type=float,
        metavar="PCT",
        help="exit 2 if the overall character leak rate exceeds this percent",
    )
    args = ap.parse_args()

    pipeline = build_pipeline(use_ner=not args.no_ner, use_llm=args.llm)
    counts: dict[str, dict[str, int]] = defaultdict(
        lambda: {"tp": 0, "fp": 0, "fn": 0}
    )
    misses: list[tuple[str, str, str]] = []

    # Character-level totals, accumulated across the corpus.
    gold_chars = covered_chars = pred_chars = extra_chars = 0
    worst: list[tuple[float, str, int]] = []

    for doc in load_fixtures():
        text = doc["text"]
        predicted = pipeline.scan(text)
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
                snippet = text[g["start"] : g["end"]]
                misses.append((doc["id"], "FN", f"{g['label']} {snippet!r}"))

        # -- character coverage, label-agnostic ---------------------------
        g_chars = char_set(gold)
        p_chars = char_set(predicted)
        leaked = g_chars - p_chars

        gold_chars += len(g_chars)
        covered_chars += len(g_chars & p_chars)
        pred_chars += len(p_chars)
        extra_chars += len(p_chars - g_chars)

        if g_chars:
            worst.append((len(leaked) / len(g_chars), doc["id"], len(leaked)))

    # -- span-level report ------------------------------------------------
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

    # -- character-level report -------------------------------------------
    leak_rate = 1 - (covered_chars / gold_chars) if gold_chars else 0.0
    over_rate = extra_chars / pred_chars if pred_chars else 0.0

    print()
    print("CHARACTER COVERAGE  (the number that actually matters)")
    print("-" * 58)
    print(f"  PII characters in corpus     {gold_chars:>8}")
    print(f"  covered by redaction         {covered_chars:>8}")
    print(f"  LEAKED                       {gold_chars - covered_chars:>8}"
          f"   ({leak_rate:.1%})")
    print(f"  clean text over-redacted     {extra_chars:>8}"
          f"   ({over_rate:.1%} of output spans)")

    worst.sort(reverse=True)
    leaky = [w for w in worst if w[0] > 0][:5]
    if leaky:
        print("\n  Leakiest documents:")
        for rate, doc_id, n in leaky:
            print(f"    {rate:>6.1%}  {doc_id}  ({n} chars)")

    if misses:
        print("\nErrors:")
        for doc_id, kind, detail in misses:
            print(f"  [{kind}] {doc_id}: {detail}")

    # -- gates: turn thresholds into a non-zero exit for CI ----------------
    failures: list[str] = []
    if args.fail_on_leak:
        for label in (l.strip().upper() for l in args.fail_on_leak.split(",")):
            if not label:
                continue
            fn = counts[label]["fn"]
            if fn:
                failures.append(f"{label} leaked {fn} span(s) (recall < 1.0)")
    if args.max_leak_rate is not None and leak_rate * 100 > args.max_leak_rate:
        failures.append(
            f"leak rate {leak_rate:.1%} exceeds budget {args.max_leak_rate:.1f}%"
        )

    if failures:
        print("\nGATE FAILED:")
        for f in failures:
            print(f"  {f}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())