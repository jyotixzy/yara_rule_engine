"""Module description: Ye file third-party folders se YARA rule files dhoondh kar compile karti hai."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from pathlib import Path

from .config import CACHE_ROOT, RULE_SOURCE_PATHS, SUPPORTED_RULE_SUFFIXES
from .models import RuleLoadError

LOGGER = logging.getLogger(__name__)

# Kuch community rules external vars expect karte hain, isliye default blank values di ja rahi hain.
DEFAULT_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
    "owner": "",
}


@dataclass(slots=True)
class CompiledRuleFile:
    """Ye model ek compiled YARA rule file aur uske source metadata ko hold karta hai."""

    source: str
    path: Path
    rules: object


def _rule_signature(path: Path) -> str:
    """Ye helper file path, size, aur modified time se ek stable cache signature banata hai."""

    stat = path.stat()
    raw = f"{path.resolve()}|{stat.st_size}|{stat.st_mtime_ns}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _cache_paths(path: Path) -> tuple[Path, Path]:
    """Ye cache file aur metadata file ke paths banata hai."""

    cache_dir = CACHE_ROOT / "compiled_rules"
    cache_dir.mkdir(parents=True, exist_ok=True)
    path_hash = hashlib.sha256(str(path.resolve()).encode("utf-8")).hexdigest()
    return cache_dir / f"{path_hash}.bin", cache_dir / f"{path_hash}.json"


def _load_cached_rules(yara_module, path: Path):
    """Ye dekhta hai valid compiled cache available hai ya nahi, aur ho to usse rule load karta hai."""

    cache_file, meta_file = _cache_paths(path)
    if not cache_file.exists() or not meta_file.exists():
        return None

    try:
        metadata = json.loads(meta_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if metadata.get("signature") != _rule_signature(path):
        return None

    try:
        return yara_module.load(str(cache_file))
    except Exception as error:  # noqa: BLE001 - broken cache should be ignored safely.
        LOGGER.debug("Cached rule load failed for %s: %s", path, error)
        return None


def _save_cached_rules(compiled_rules, path: Path) -> None:
    """Ye newly compiled rules ko cache me save karta hai taaki next run fast ho sake."""

    cache_file, meta_file = _cache_paths(path)
    compiled_rules.save(str(cache_file))
    metadata = {"signature": _rule_signature(path), "source_path": str(path.resolve())}
    meta_file.write_text(json.dumps(metadata), encoding="utf-8")


def iter_rule_files() -> list[tuple[str, Path]]:
    """Ye configured folders ko walk karke valid YARA rule files ki list banata hai."""

    discovered: list[tuple[str, Path]] = []
    for source_name, roots in RULE_SOURCE_PATHS.items():
        for root in roots:
            if not root.exists():
                LOGGER.warning("Rule root %s is missing and will be skipped.", root)
                continue
            # Sirf .yar aur .yara files ko candidate maana jata hai.
            for path in root.rglob("*"):
                if path.is_file() and path.suffix.lower() in SUPPORTED_RULE_SUFFIXES:
                    discovered.append((source_name, path))
    return discovered


def compile_rule_files() -> tuple[list[CompiledRuleFile], list[RuleLoadError]]:
    """Ye rules ko ek-ek karke compile karta hai taaki ek broken rule poora load fail na kare."""

    try:
        import yara
    except ImportError as error:  # pragma: no cover - depends on local runtime setup.
        raise RuntimeError("yara-python is required to compile rules.") from error

    compiled: list[CompiledRuleFile] = []
    failures: list[RuleLoadError] = []
    cache_hits = 0
    cache_misses = 0

    # Per-file compile strategy se broken upstream rules isolate ho jaate hain.
    for source_name, path in iter_rule_files():
        try:
            compiled_rules = _load_cached_rules(yara, path)
            if compiled_rules is not None:
                cache_hits += 1
            else:
                cache_misses += 1
                compiled_rules = yara.compile(filepath=str(path), externals=DEFAULT_EXTERNALS)
                _save_cached_rules(compiled_rules, path)
            compiled.append(CompiledRuleFile(source=source_name, path=path, rules=compiled_rules))
        except Exception as error:  # noqa: BLE001 - third-party rule failures must be isolated.
            failures.append(RuleLoadError(path=str(path), source=source_name, error=str(error)))
            LOGGER.debug("Skipping rule file %s because it failed to compile: %s", path, error)

    LOGGER.info(
        "Loaded %s rule files, skipped %s broken files, cache hits=%s, cache misses=%s.",
        len(compiled),
        len(failures),
        cache_hits,
        cache_misses,
    )
    return compiled, failures
