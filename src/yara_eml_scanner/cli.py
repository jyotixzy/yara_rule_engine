"""Module description: Ye file CLI handle karti hai, yani user command de aur scanner pipeline run ho."""

from __future__ import annotations

import argparse
import json
import sys

from .logging_utils import configure_logging
from .models import FileScanResult
from .pipeline import run_pipeline


def build_parser() -> argparse.ArgumentParser:
    """Ye function command-line options define karta hai, jaise EML path aur output mode."""

    parser = argparse.ArgumentParser(description="Scan decoded EML attachments with YARA.")
    parser.add_argument("--eml", required=True, help="Path to the input .eml file.")
    parser.add_argument("--json", action="store_true", help="Print the full JSON report.")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON output.")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser


def format_summary(scan_results: list[FileScanResult]) -> str:
    """Ye function final results ko short human-readable summary me convert karta hai."""

    lines: list[str] = []

    # Yahan hum results ko do groups me baant rahe hain: malicious aur clean.
    malicious_results = [result for result in scan_results if result.is_malicious]
    clean_results = [result for result in scan_results if not result.is_malicious]

    lines.append("Malicious files:")
    if malicious_results:
        for result in malicious_results:
            # Ek hi file par multiple same rule names aa sakte hain, isliye unique rule list bana rahe hain.
            rule_names = ", ".join(sorted({match.rule for match in result.matches}))
            lines.append(f"- {result.file.source_name} | rules: {rule_names}")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("Clean files:")
    if clean_results:
        for result in clean_results:
            lines.append(f"- {result.file.source_name}")
    else:
        lines.append("- None")

    return "\n".join(lines)


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
