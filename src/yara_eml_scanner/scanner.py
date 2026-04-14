"""Module description: Ye file actual YARA matching chalati hai aur results ko normalize karti hai."""

from __future__ import annotations

import logging
from pathlib import Path
import warnings

from .models import ExtractedFile, FileScanResult, RuleMatch
from .rule_loader import CompiledRuleFile

LOGGER = logging.getLogger(__name__)


def _normalize_match(match, namespace: str) -> RuleMatch:
    """Ye raw yara-python match object ko hamare RuleMatch model me convert karta hai."""

    return RuleMatch(
        rule=match.rule,
        namespace=namespace,
        tags=list(getattr(match, "tags", [])),
        meta=dict(getattr(match, "meta", {})),
    )


def scan_file(file_info: ExtractedFile, compiled_rules: list[CompiledRuleFile]) -> FileScanResult:
    """Ye ek file ko saare compiled rule files ke against scan karta hai."""

    matches: list[RuleMatch] = []
    errors: list[str] = []
    file_path = Path(file_info.path)

    # Kuch rules file-related externals use karte hain, isliye per-file values pass ki ja rahi hain.
    externals = {
        "filename": file_path.name,
        "filepath": str(file_path),
        "extension": file_path.suffix.lstrip("."),
        "filetype": file_info.detected_type,
        "owner": "",
    }

    for rule_file in compiled_rules:
        try:
            # Noisy 'too many matches' warnings ko hide kiya gaya hai taaki output clean rahe.
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", message="too many matches for string.*", category=RuntimeWarning)
                raw_matches = rule_file.rules.match(str(file_info.path), externals=externals)
        except Exception as error:  # noqa: BLE001 - third-party rules should not crash the pipeline.
            errors.append(f"{rule_file.path}: {error}")
            LOGGER.debug("Failed matching %s with %s: %s", file_info.path, rule_file.path, error)
            continue

        for match in raw_matches:
            matches.append(_normalize_match(match, namespace=rule_file.source))

    return FileScanResult(file=file_info, is_malicious=bool(matches), matches=matches, errors=errors)


def scan_files(files: list[ExtractedFile], compiled_rules: list[CompiledRuleFile]) -> list[FileScanResult]:
    """Ye sab final files ko scan karke per-file results return karta hai."""

    results = [scan_file(file_info, compiled_rules) for file_info in files]
    # Logging yahan summary level par hoti hai, taaki verbose mode me per-file visibility mile.
    for result in results:
        if result.is_malicious:
            LOGGER.warning(
                "Malicious file detected: %s triggered %s rules.",
                result.file.path,
                len(result.matches),
            )
        else:
            LOGGER.info("Clean file: %s", result.file.path)
    return results
