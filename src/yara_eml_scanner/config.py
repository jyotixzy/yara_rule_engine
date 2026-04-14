"""Module description: Ye central config file hai jahan paths, limits, aur supported types define hote hain."""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
THIRD_PARTY_ROOT = PROJECT_ROOT / "third_party"
RUNTIME_TEMP_ROOT = PROJECT_ROOT / ".tmp"
CACHE_ROOT = PROJECT_ROOT / ".cache"

# Yahan decide hota hai kaunse third-party rule folders se YARA rules uthaye jayenge.
RULE_SOURCE_PATHS: dict[str, list[Path]] = {
    "yara-rules": [
        THIRD_PARTY_ROOT / "yara-rules" / "email",
        THIRD_PARTY_ROOT / "yara-rules" / "maldocs",
        THIRD_PARTY_ROOT / "yara-rules" / "malware",
    ],
    "signature-base": [THIRD_PARTY_ROOT / "signature-base" / "yara"],
}

# Supported rule extensions aur container types yahin globally define kiye gaye hain.
SUPPORTED_RULE_SUFFIXES = {".yar", ".yara"}
SUPPORTED_CONTAINER_TYPES = {"zip", "tar", "gzip", "bzip2", "xz", "7z", "rar"}

# Safety limits taaki bahut deep ya bahut large file processing se system choke na ho.
MAX_RECURSION_DEPTH = 5
MAX_ATTACHMENT_BYTES = 100 * 1024 * 1024
MAX_UNPACKED_BYTES = 500 * 1024 * 1024
