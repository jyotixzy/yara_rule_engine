"""FastAPI app exposing YARA scan endpoints."""

from __future__ import annotations

import logging
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.responses import PlainTextResponse

from .config import MAX_FILE_BYTES, RUNTIME_TEMP_ROOT
from .pipeline import run_pipeline
from .reporting import format_summary, format_summary_from_dict
from .service import get_compiled_rules, scan_path

LOGGER = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    """Warm up the YARA rules cache on startup."""

    get_compiled_rules()
    yield


app = FastAPI(
    title="YARA Scanning API Service",
    version="0.1.0",
    description="Upload a file and get YARA scan results from this server.",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, str]:
    """Simple health endpoint for uptime checks."""

    return {"status": "ok"}


@app.post("/scan/file")
async def scan_file(
    file: UploadFile = File(...),
    response_format: str = Query(default="text", pattern="^(text|json)$"),
):
    """Accept a file upload, scan it with YARA, and return matches."""

    if not file.filename:
        raise HTTPException(status_code=400, detail="Uploaded file must have a filename.")

    upload_root = RUNTIME_TEMP_ROOT / "api_uploads"
    upload_root.mkdir(parents=True, exist_ok=True)
    request_dir = upload_root / uuid.uuid4().hex
    request_dir.mkdir(parents=True, exist_ok=True)
    target_path = request_dir / Path(file.filename).name

    try:
        total_bytes = 0
        with target_path.open("wb") as handle:
            while chunk := await file.read(1024 * 1024):
                total_bytes += len(chunk)
                if total_bytes > MAX_FILE_BYTES:
                    raise HTTPException(
                        status_code=413,
                        detail=f"Uploaded file exceeds the {MAX_FILE_BYTES // (1024 * 1024)}MB limit.",
                    )
                handle.write(chunk)
    except Exception as error:  # noqa: BLE001 - upload failures should be returned as 500.
        if isinstance(error, HTTPException):
            raise
        LOGGER.exception("Failed to persist upload %s", file.filename)
        raise HTTPException(status_code=500, detail=f"Failed to save upload: {error}") from error
    finally:
        await file.close()

    try:
        if target_path.suffix.lower() == ".eml":
            report = run_pipeline(target_path)
            if response_format == "json":
                return report.to_dict()

            summary = format_summary(report.scan_results)
            if report.pipeline_errors:
                summary = f"{summary}\n\nPipeline errors:\n- " + "\n- ".join(report.pipeline_errors)
            return PlainTextResponse(summary)

        report = scan_path(target_path)
        if response_format == "json":
            return report

        summary = format_summary_from_dict(report.get("scan_results", []))
        if report.get("pipeline_errors"):
            summary = f"{summary}\n\nPipeline errors:\n- " + "\n- ".join(report["pipeline_errors"])
        return PlainTextResponse(summary)
    finally:
        shutil.rmtree(request_dir, ignore_errors=True)


def main() -> None:
    """Run the FastAPI app with uvicorn."""

    uvicorn.run("yara_eml_scanner.api:app", host="0.0.0.0", port=8000, reload=False)
