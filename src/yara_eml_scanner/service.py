"""Generic YARA file scanning service helpers."""

from __future__ import annotations

import logging
import shutil
import uuid
from functools import lru_cache
from pathlib import Path

from .config import RUNTIME_TEMP_ROOT
from .container_unpacker import expand_containers
from .file_types import detect_file_type
from .models import ExtractedFile
from .rule_loader import CompiledRuleFile, compile_rule_files
from .scanner import scan_files

LOGGER = logging.getLogger(__name__)


@lru_cache(maxsize=1)
def get_compiled_rules() -> tuple[list[CompiledRuleFile], list[dict[str, str]]]:
    """Compile YARA rules once and reuse them across API requests."""

    compiled_rules, rule_errors = compile_rule_files()
    return compiled_rules, [error.to_dict() for error in rule_errors]


def scan_path(path: str | Path) -> dict:
    """Scan a regular file path and return a JSON-friendly report."""

    input_path = Path(path).resolve()
    RUNTIME_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    workspace = RUNTIME_TEMP_ROOT / f"yara_file_scan_{uuid.uuid4().hex}"
    workspace.mkdir(parents=True, exist_ok=True)

    try:
        file_info = ExtractedFile(
            path=input_path,
            source_name=input_path.name,
            media_type=None,
            detected_type=detect_file_type(input_path),
            depth=0,
        )
        expanded_files = expand_containers([file_info], workspace)
        compiled_rules, rule_errors = get_compiled_rules()
        scan_results = scan_files(expanded_files, compiled_rules)
        return {
            "input_file": str(input_path),
            "extracted_files": [item.to_dict() for item in expanded_files],
            "scan_results": [item.to_dict() for item in scan_results],
            "rule_errors": rule_errors,
            "pipeline_errors": [],
        }
    except Exception as error:  # noqa: BLE001 - service should return clean failures.
        LOGGER.exception("File scan failed for %s", input_path)
        return {
            "input_file": str(input_path),
            "extracted_files": [],
            "scan_results": [],
            "rule_errors": [],
            "pipeline_errors": [str(error)],
        }
    finally:
        try:
            shutil.rmtree(workspace, ignore_errors=True)
        except Exception as cleanup_error:  # noqa: BLE001 - cleanup is best effort.
            LOGGER.debug("Workspace cleanup failed for %s: %s", workspace, cleanup_error)
