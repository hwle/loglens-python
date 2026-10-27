"""Command-line entry point for LogLens."""
import argparse
import json
from pathlib import Path
import sys

from .analyzer import create_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline authentication log triage")
    parser.add_argument("input", type=Path, help="Path to a JSONL event file")
    parser.add_argument("--output", type=Path, help="Optional JSON report destination")
    args = parser.parse_args()
    try:
        report = create_report(args.input)
        output = json.dumps(report, indent=2)
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
            print(f"Report written to {args.output}")
        else:
            print(output)
        return 0
    except (OSError, UnicodeError) as exc:
        print(f"Error reading input: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
