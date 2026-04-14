"""Module description: Ye orchestrator file hai jo poore EML-to-YARA workflow ko ek jagah se chalati hai."""

from __future__ import annotations

import logging
import shutil
import uuid
from pathlib import Path

from .config import RUNTIME_TEMP_ROOT
from .container_unpacker import expand_containers
from .eml_parser import extract_attachments, parse_eml
from .models import PipelineReport
from .rule_loader import compile_rule_files
from .scanner import scan_files

LOGGER = logging.getLogger(__name__)


def run_pipeline(eml_path: str | Path) -> PipelineReport:
    """Ye end-to-end pipeline run karta hai aur final structured report return karta hai."""

    eml_path = Path(eml_path).resolve()
    report = PipelineReport(eml_path=str(eml_path))
    RUNTIME_TEMP_ROOT.mkdir(parents=True, exist_ok=True)
    workspace = RUNTIME_TEMP_ROOT / f"yara_eml_scan_{uuid.uuid4().hex}"
    workspace.mkdir(parents=True, exist_ok=True)
    attachments_dir = workspace / "attachments"

    try:
        # Step 1: mail parse karo.
        message = parse_eml(eml_path)
        # Step 2: attachments decode karke nikalo.
        attachments = extract_attachments(message, attachments_dir)
        # Step 3: agar archive/container mile to andar tak expand karo.
        expanded_files = expand_containers(attachments, workspace)
        # Step 4: YARA rules compile/load karo.
        compiled_rules, rule_errors = compile_rule_files()
        # Step 5: final files par YARA scan chalao.
        scan_results = scan_files(expanded_files, compiled_rules)
    except Exception as error:  # noqa: BLE001 - pipeline should return failure details cleanly.
        LOGGER.exception("Pipeline execution failed for %s", eml_path)
        report.pipeline_errors.append(str(error))
        return report
    finally:
        # Temp workspace ko best-effort basis par cleanup kiya jata hai.
        try:
            shutil.rmtree(workspace, ignore_errors=True)
        except Exception as cleanup_error:  # noqa: BLE001 - cleanup must stay best effort.
            LOGGER.debug("Workspace cleanup failed for %s: %s", workspace, cleanup_error)

    report.extracted_files.extend(expanded_files)
    report.scan_results.extend(scan_results)
    report.rule_errors.extend(rule_errors)
    return report
