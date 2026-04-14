"""Module description: Ye file container/archive files ko recursively unpack karti hai taaki actual inner files scan ho sakein."""

from __future__ import annotations

import bz2
import gzip
import logging
import lzma
import shutil
import tarfile
import zipfile
from pathlib import Path

from .config import MAX_RECURSION_DEPTH, MAX_UNPACKED_BYTES, SUPPORTED_CONTAINER_TYPES
from .file_types import detect_file_type
from .models import ExtractedFile

LOGGER = logging.getLogger(__name__)

try:
    import py7zr
except ImportError:  # pragma: no cover - optional dependency in development.
    py7zr = None

try:
    import rarfile
except ImportError:  # pragma: no cover - optional dependency in development.
    rarfile = None


def is_container_type(detected_type: str) -> bool:
    """Ye batata hai ki detected type archive/container hai ya nahi."""

    return detected_type in SUPPORTED_CONTAINER_TYPES


def _enforce_size_limit(path: Path) -> None:
    """Ye guard hai jo oversized file ko process hone se rokta hai."""

    if path.stat().st_size > MAX_UNPACKED_BYTES:
        raise ValueError(f"Refusing to process oversized file: {path}")


def _extract_single_stream(reader, destination: Path) -> None:
    """Ye helper single compressed stream ko ek output file me likhta hai."""

    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as handle:
        shutil.copyfileobj(reader, handle)


def _safe_destination(root: Path, member_name: str) -> Path:
    """Ye ensure karta hai ki archive ke andar ka path workspace ke bahar escape na kare."""

    candidate = (root / member_name).resolve()
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError(f"Unsafe archive member path detected: {member_name}")
    return candidate


def unpack_zip(source: Path, destination: Path) -> list[Path]:
    """Ye zip archive kholkar uske actual child files disk par nikalta hai."""

    written: list[Path] = []
    with zipfile.ZipFile(source) as archive:
        for member in archive.infolist():
            if member.is_dir():
                continue
            # Har member ko safe path par resolve karna zaroori hai, warna zip-slip risk hota hai.
            target = _safe_destination(destination, member.filename)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as reader, target.open("wb") as writer:
                shutil.copyfileobj(reader, writer)
            written.append(target)
    return written


def unpack_tar(source: Path, destination: Path) -> list[Path]:
    """Ye tar archive ke andar ki real files ko safe tarike se extract karta hai."""

    written: list[Path] = []
    with tarfile.open(source) as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            target = _safe_destination(destination, member.name)
            target.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is None:
                continue
            with extracted, target.open("wb") as writer:
                shutil.copyfileobj(extracted, writer)
            written.append(target)
    return written


def unpack_gzip(source: Path, destination: Path) -> list[Path]:
    """Ye gzip stream ko ek single decompressed file me convert karta hai."""

    output = destination / source.stem
    with gzip.open(source, "rb") as reader:
        _extract_single_stream(reader, output)
    return [output]


def unpack_bzip2(source: Path, destination: Path) -> list[Path]:
    """Ye bzip2 compressed file ko single decompressed output me badalta hai."""

    output = destination / source.stem
    with bz2.open(source, "rb") as reader:
        _extract_single_stream(reader, output)
    return [output]


def unpack_xz(source: Path, destination: Path) -> list[Path]:
    """Ye xz compressed file ko single decompressed output me badalta hai."""

    output = destination / source.stem
    with lzma.open(source, "rb") as reader:
        _extract_single_stream(reader, output)
    return [output]


def unpack_7z(source: Path, destination: Path) -> list[Path]:
    """Ye 7z archive extract karta hai, bas tab jab py7zr installed ho."""

    if py7zr is None:
        raise RuntimeError("py7zr is not installed, so 7z extraction is unavailable.")
    with py7zr.SevenZipFile(source, mode="r") as archive:
        archive.extractall(path=destination)
    return [path for path in destination.rglob("*") if path.is_file()]


def unpack_rar(source: Path, destination: Path) -> list[Path]:
    """Ye RAR archive extract karta hai, bas tab jab rarfile dependency available ho."""

    if rarfile is None:
        raise RuntimeError("rarfile is not installed, so RAR extraction is unavailable.")
    with rarfile.RarFile(source) as archive:
        archive.extractall(path=destination)
    return [path for path in destination.rglob("*") if path.is_file()]


def unpack_container(source: Path, detected_type: str, destination: Path) -> list[Path]:
    """Ye router function hai jo detected type ke hisaab se sahi unpacker choose karta hai."""

    if detected_type == "zip":
        return unpack_zip(source, destination)
    if detected_type == "tar":
        return unpack_tar(source, destination)
    if detected_type == "gzip":
        return unpack_gzip(source, destination)
    if detected_type == "bzip2":
        return unpack_bzip2(source, destination)
    if detected_type == "xz":
        return unpack_xz(source, destination)
    if detected_type == "7z":
        return unpack_7z(source, destination)
    if detected_type == "rar":
        return unpack_rar(source, destination)
    raise ValueError(f"Unsupported container type: {detected_type}")


def expand_containers(files: list[ExtractedFile], workspace: Path) -> list[ExtractedFile]:
    """Ye main recursive expansion function hai jo nested archives ke andar tak jaakar files collect karta hai."""

    expanded: list[ExtractedFile] = []
    queue = list(files)

    # Queue-based traversal use ki gayi hai taaki nested containers level by level handle ho sakein.
    while queue:
        current = queue.pop(0)
        _enforce_size_limit(current.path)
        current.detected_type = detect_file_type(current.path)
        expanded.append(current)

        # Agar ye container nahi hai ya recursion limit hit ho gayi hai, to isi file ko final scan list me rehne do.
        if current.depth >= MAX_RECURSION_DEPTH or not is_container_type(current.detected_type):
            continue

        container_root = workspace / f"unpacked_depth_{current.depth + 1}" / current.path.stem
        container_root.mkdir(parents=True, exist_ok=True)
        LOGGER.info("Unpacking %s as %s", current.path, current.detected_type)

        try:
            unpacked_paths = unpack_container(current.path, current.detected_type, container_root)
        except Exception as error:  # noqa: BLE001 - we want resilient container handling.
            LOGGER.exception("Failed to unpack %s: %s", current.path, error)
            continue

        # Unpacked child files ko queue me daal diya jata hai taaki un par bhi same logic lage.
        for child_path in unpacked_paths:
            queue.append(
                ExtractedFile(
                    path=child_path,
                    source_name=child_path.name,
                    media_type=None,
                    detected_type="unknown",
                    depth=current.depth + 1,
                    parent=str(current.path),
                    from_container=True,
                )
            )

    return expanded
