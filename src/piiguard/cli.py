"""Command line interface.

    piiguard scan notes.txt
    piiguard redact notes.txt --policy pseudonymize -o clean.txt
    piiguard redact notes.txt --set SSN=mask --set PERSON=pseudonymize
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .pipeline import Pipeline
from .policy import Policy
from .verify import LeakError


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    return Path(path).read_text(encoding="utf-8", errors="replace")


def _build_policy(args) -> Policy:
    per_label = {}
    for item in args.set or []:
        if "=" not in item:
            raise SystemExit(f"--set expects LABEL=MODE, got {item!r}")
        label, mode = item.split("=", 1)
        per_label[label.upper()] = mode
    return Policy(default=args.policy, per_label=per_label)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="piiguard",
        description="Local-first PII detection and redaction. No network, ever.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="report PII without modifying anything")
    scan.add_argument("path", help="file to scan, or - for stdin")
    scan.add_argument("--json", action="store_true", help="machine-readable output")

    red = sub.add_parser("redact", help="rewrite PII according to a policy")
    red.add_argument("path", help="file to redact, or - for stdin")
    red.add_argument("-o", "--output", help="write here instead of stdout")
    red.add_argument(
        "--policy",
        default="label",
        choices=["mask", "label", "pseudonymize", "keep"],
        help="default handling for every label (default: label)",
    )
    red.add_argument(
        "--set",
        action="append",
        metavar="LABEL=MODE",
        help="override handling for one label; repeatable",
    )
    red.add_argument(
        "--no-verify",
        action="store_true",
        help="do not fail if PII survives redaction (not recommended)",
    )

    args = parser.parse_args(argv)
    text = _read(args.path)

    if args.command == "scan":
        spans = Pipeline().scan(text)
        if args.json:
            print(
                json.dumps(
                    [
                        {
                            "start": s.start,
                            "end": s.end,
                            "label": s.label,
                            "detector": s.detector,
                            "score": s.score,
                        }
                        for s in spans
                    ],
                    indent=2,
                )
            )
        else:
            for s in spans:
                print(f"{s.start:>7}  {s.label:<14} {s.detector:<8} {s.text}")
            print(f"\n{len(spans)} finding(s)", file=sys.stderr)
        return 0

    pipeline = Pipeline(policy=_build_policy(args))
    try:
        result = pipeline.redact(text, strict=not args.no_verify)
    except LeakError as exc:
        print(f"piiguard: {exc}", file=sys.stderr)
        return 2

    if args.output:
        Path(args.output).write_text(result.redacted, encoding="utf-8")
        print(
            f"redacted {len(result.spans)} span(s) -> {args.output}",
            file=sys.stderr,
        )
    else:
        sys.stdout.write(result.redacted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
