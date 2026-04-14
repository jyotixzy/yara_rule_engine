"""Module description: Ye file content-based file type detect karti hai, taaki extension par blindly bharosa na karna pade."""

from __future__ import annotations

import bz2
import gzip
import lzma
import tarfile
import zipfile
from pathlib import Path

MAGIC_SIGNATURES: list[tuple[bytes, str]] = [
    (b"MZ", "pe"),
    (b"%PDF", "pdf"),
    (b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1", "ole"),
    (b"\x50\x4B\x03\x04", "zip"),
    (b"\x37\x7A\xBC\xAF\x27\x1C", "7z"),
    (b"\x52\x61\x72\x21\x1A\x07\x00", "rar"),
    (b"\x52\x61\x72\x21\x1A\x07\x01\x00", "rar"),
    (b"\x1F\x8B\x08", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xFD\x37\x7A\x58\x5A\x00", "xz"),
    (b"\x7FELF", "elf"),
    (b"\xCA\xFE\xBA\xBE", "java"),
    (b"\xFE\xED\xFA", "mach-o"),
    (b"Rar!", "rar"),
]


def read_magic_bytes(path: Path, size: int = 32) -> bytes:
    """Ye file ke starting bytes padhta hai, jisse magic signature detect ho sake."""

    with path.open("rb") as handle:
        return handle.read(size)


def looks_like_tar(path: Path) -> bool:
    """Ye check karta hai ki file actual tar archive lag rahi hai ya nahi."""

    return tarfile.is_tarfile(path)


def looks_like_zip(path: Path) -> bool:
    """Ye check karta hai ki file actual zip archive lag rahi hai ya nahi."""

    return zipfile.is_zipfile(path)


def looks_like_gzip(path: Path) -> bool:
    """Ye check karta hai ki file actual gzip compressed content hai ya nahi."""

    try:
        with gzip.open(path, "rb") as handle:
            handle.read(1)
        return True
    except OSError:
        return False


def looks_like_bzip2(path: Path) -> bool:
    """Ye check karta hai ki file actual bzip2 compressed content hai ya nahi."""

    try:
        with bz2.open(path, "rb") as handle:
            handle.read(1)
        return True
    except OSError:
        return False


def looks_like_xz(path: Path) -> bool:
    """Ye check karta hai ki file actual xz compressed content hai ya nahi."""

    try:
        with lzma.open(path, "rb") as handle:
            handle.read(1)
        return True
    except (OSError, lzma.LZMAError):
        return False


def detect_file_type(path: Path) -> str:
    """Ye final detector hai jo magic bytes aur fallback validators dono use karke real type nikalta hai."""

    # Pehle fast magic-byte detection hota hai.
    header = read_magic_bytes(path)
    for signature, detected_type in MAGIC_SIGNATURES:
        if header.startswith(signature):
            return detected_type

    # Agar header se clear nahi hua, to archive validators try karte hain.
    if looks_like_zip(path):
        return "zip"
    if looks_like_tar(path):
        return "tar"
    if looks_like_gzip(path):
        return "gzip"
    if looks_like_bzip2(path):
        return "bzip2"
    if looks_like_xz(path):
        return "xz"
    return "unknown"
