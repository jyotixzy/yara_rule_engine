"""Module description: Ye file shared data models rakhti hai jo pipeline ke har stage me pass hote hain."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ExtractedFile:
    """Ye model ek extracted ya unpacked file ko represent karta hai."""

    path: Path
    source_name: str
    media_type: str | None
    detected_type: str
    depth: int
    parent: str | None = None
    from_container: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Ye model ko JSON-friendly dict me convert karta hai."""

        data = asdict(self)
        data["path"] = str(self.path)
        return data


@dataclass(slots=True)
class RuleLoadError:
    """Ye model un YARA rule files ke liye hai jo compile nahi ho paayin."""

    path: str
    source: str
    error: str

    def to_dict(self) -> dict[str, Any]:
        """Ye error model ko JSON-friendly dict me convert karta hai."""

        return asdict(self)


@dataclass(slots=True)
class RuleMatch:
    """Ye model ek single YARA match ko represent karta hai."""

    rule: str
    namespace: str
    tags: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Ye rule match ko JSON-friendly dict me convert karta hai."""

        return asdict(self)


@dataclass(slots=True)
class FileScanResult:
    """Ye model batata hai ek file malicious nikli ya clean, aur kaunse rules lage."""

    file: ExtractedFile
    is_malicious: bool
    matches: list[RuleMatch] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Ye file scan result ko JSON output ke liye dict me convert karta hai."""

        return {
            "file": self.file.to_dict(),
            "is_malicious": self.is_malicious,
            "matches": [match.to_dict() for match in self.matches],
            "errors": list(self.errors),
        }


@dataclass(slots=True)
class PipelineReport:
    """Ye final top-level report hai jisme poora scan summary store hota hai."""

    eml_path: str
    extracted_files: list[ExtractedFile] = field(default_factory=list)
    scan_results: list[FileScanResult] = field(default_factory=list)
    rule_errors: list[RuleLoadError] = field(default_factory=list)
    pipeline_errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Ye poori report ko JSON output ke liye dict me convert karta hai."""

        return {
            "eml_path": self.eml_path,
            "extracted_files": [item.to_dict() for item in self.extracted_files],
            "scan_results": [item.to_dict() for item in self.scan_results],
            "rule_errors": [item.to_dict() for item in self.rule_errors],
            "pipeline_errors": list(self.pipeline_errors),
        }
