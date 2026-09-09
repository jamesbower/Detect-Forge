"""Priority list loading for the ``coverage`` subcommand.

Discovery order at resolution time (highest precedence first):

1. ``cli_path`` — operator passed ``--priority-list /path/to/custom.json``.
2. ``config_path`` — the ``[coverage] priority_list`` value from ``.detect-forge.toml``.
3. Built-in default — the file named by ``PRIORITY_DEFAULT_FILENAME``, packaged in
   ``priority_data/``.
"""

from __future__ import annotations

import importlib.resources as ir
import json
import logging
import re
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

PRIORITY_DEFAULT_FILENAME = "ctid_top_techniques_2024.json"
"""Currently-active built-in priority list. Update when refreshing annually."""

_TECHNIQUE_ID_PATTERN = re.compile(r"^T\d{4}(\.\d{3})?$")


def _validate_technique_ids(ids: list[str], source_hint: str) -> set[str]:
    """Validate a list of technique-ID strings. Raises ValueError on the first bad ID."""
    for tid in ids:
        if not isinstance(tid, str) or not _TECHNIQUE_ID_PATTERN.match(tid):
            raise ValueError(
                f"Invalid technique ID in {source_hint}: {tid!r}. "
                f"Expected pattern T#### or T####.###"
            )
    return set(ids)


def load_priority_techniques(path: Path) -> set[str]:
    """Load a priority list from a JSON file. Raises on missing/malformed input.

    A file that resolves to *zero* technique IDs (empty list, or a mistyped
    ``technique_ids`` key) raises ``ValueError`` rather than returning an empty
    set — an empty priority set silently disables CI gating, which is exactly
    the failure a custom priority list is meant to prevent.
    """
    if not path.is_file():
        raise FileNotFoundError(f"Priority list not found: {path}")
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError(
            f"Priority list at {path} must be a JSON object with a "
            f"'technique_ids' array (got {type(raw).__name__})"
        )
    tids = raw.get("technique_ids", [])
    if not isinstance(tids, list):
        raise ValueError(
            f"Priority list at {path} has malformed 'technique_ids' (expected list)"
        )
    ids = _validate_technique_ids(tids, source_hint=str(path))
    if not ids:
        raise ValueError(
            f"Priority list at {path} contains no valid technique IDs — check "
            f"that the top-level 'technique_ids' array is present and non-empty"
        )
    return ids


def load_builtin_priority_techniques() -> set[str]:
    """Load the packaged default priority list."""
    pkg = "detect_forge.coverage.priority_data"
    with ir.files(pkg).joinpath(PRIORITY_DEFAULT_FILENAME).open(
        "r", encoding="utf-8"
    ) as f:
        raw: dict[str, Any] = json.load(f)
    tids = raw.get("technique_ids", [])
    if not isinstance(tids, list):
        raise ValueError(
            f"Built-in priority list {PRIORITY_DEFAULT_FILENAME!r} has malformed 'technique_ids'"
        )
    return _validate_technique_ids(
        tids, source_hint=f"built-in {PRIORITY_DEFAULT_FILENAME}"
    )


def resolve_priority_techniques(
    *,
    cli_path: Path | None,
    config_path: Path | None = None,
    start_dir: Path | None = None,
) -> set[str]:
    """Resolve the priority list using the documented precedence.

    Args:
        cli_path: Path passed via ``--priority-list`` (highest precedence).
        config_path: Path from ``[coverage] priority_list`` in
            ``.detect-forge.toml``. ``None`` means "no override".
        start_dir: Directory to resolve relative ``config_path`` against. When
            ``None``, uses ``Path.cwd()``.
    """
    if cli_path is not None:
        log.debug("Priority list source: CLI --priority-list (%s)", cli_path)
        return load_priority_techniques(cli_path)
    if config_path is not None:
        base = start_dir if start_dir is not None else Path.cwd()
        resolved = (
            (base / config_path).resolve()
            if not config_path.is_absolute()
            else config_path
        )
        log.debug("Priority list source: .detect-forge.toml (%s)", resolved)
        return load_priority_techniques(resolved)
    log.debug("Priority list source: built-in default")
    return load_builtin_priority_techniques()
