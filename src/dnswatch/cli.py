from __future__ import annotations

import argparse
import sys

from .analyzer import analyze, findings_as_json, findings_as_sarif, findings_as_table, read_zeek


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Offline, explainable heuristics for Zeek DNS logs")
    parser.add_argument("input", help="path to a Zeek dns.log TSV file")
    parser.add_argument("--format", choices=("table", "json", "sarif"), default="table")
    parser.add_argument("--max-queries", type=int, default=20)
    parser.add_argument("--entropy-threshold", type=float, default=3.5)
    parser.add_argument("--max-query-length", type=int, default=80)
    parser.add_argument("--max-file-bytes", type=int, default=5_000_000)
    parser.add_argument("--fail-on", choices=("none", "low", "medium", "high"), default="none")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        findings = analyze(
            read_zeek(args.input, max_bytes=args.max_file_bytes),
            max_queries=args.max_queries,
            entropy_threshold=args.entropy_threshold,
            max_query_length=args.max_query_length,
        )
    except (OSError, ValueError) as exc:
        print(f"dnswatch: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(findings_as_json(findings))
    elif args.format == "sarif":
        print(findings_as_sarif(findings))
    else:
        print(findings_as_table(findings))
    levels = {"none": 99, "low": 0, "medium": 1, "high": 2}
    return 1 if any(levels[f.severity] >= levels[args.fail_on] for f in findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())

