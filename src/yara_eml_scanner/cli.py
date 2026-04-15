"""Module description: Ye file CLI handle karti hai, yani user command de aur scanner pipeline run ho."""

from __future__ import annotations

import argparse
import json
import sys

from .logging_utils import configure_logging
from .pipeline import run_pipeline
from .reporting import format_summary


def build_parser() -> argparse.ArgumentParser:
    """Ye function command-line options define karta hai, jaise EML path aur output mode."""

    parser = argparse.ArgumentParser(description="Scan decoded EML attachments with YARA.")
    parser.add_argument("--eml", required=True, help="Path to the input .eml file.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser


def main() -> int:
    """Ye main CLI flow hai: args lo, logging set karo, pipeline chalao, aur output print karo."""

    parser = build_parser()
    args = parser.parse_args()

    configure_logging(verbose=args.verbose)
    report = run_pipeline(args.eml)

    # Agar user detailed output maange to JSON do, warna short summary dikhao.
    if args.json or args.pretty:
        json_kwargs = {"indent": 2} if args.pretty else {}
        print(json.dumps(report.to_dict(), **json_kwargs))
    else:
        print(format_summary(report.scan_results))

    return 0 if not report.pipeline_errors else 1


if __name__ == "__main__":
    sys.exit(main())
