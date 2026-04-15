"""Helpers for rendering scan reports in a human-readable format."""

from __future__ import annotations

from .models import FileScanResult, RuleMatch


def format_summary(scan_results: list[FileScanResult]) -> str:
    """Render scan results in the short summary style used by the CLI."""

    lines: list[str] = []
    malicious_results = [result for result in scan_results if result.is_malicious]
    clean_results = [result for result in scan_results if not result.is_malicious]

    lines.append("Malicious files:")
    if malicious_results:
        for result in malicious_results:
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


def format_summary_from_dict(scan_results: list[dict]) -> str:
    """Render the same summary format from JSON-friendly scan result dictionaries."""

    lines: list[str] = []
    malicious_results = [result for result in scan_results if result.get("is_malicious")]
    clean_results = [result for result in scan_results if not result.get("is_malicious")]

    lines.append("Malicious files:")
    if malicious_results:
        for result in malicious_results:
            rule_names = ", ".join(sorted({match["rule"] for match in result.get("matches", [])}))
            lines.append(f"- {result['file']['source_name']} | rules: {rule_names}")
    else:
        lines.append("- None")

    lines.append("")
    lines.append("Clean files:")
    if clean_results:
        for result in clean_results:
            lines.append(f"- {result['file']['source_name']}")
    else:
        lines.append("- None")

    return "\n".join(lines)
