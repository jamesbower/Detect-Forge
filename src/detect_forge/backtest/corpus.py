"""Mordor (Security-Datasets) corpus loader with on-demand fetch + cache.

Discovery order:
1. ``source_override`` (CLI ``--mordor-source PATH``) — local checkout; no fetch
2. ``index_override`` (test injection) — for fixtures
3. Bundled ``mordor_index.json`` shipped in the wheel

Datasets are fetched lazily per ``datasets_for(technique_id)`` call. Per-dataset
cache key: ``(technique_id, dataset_id)``. SHA256 in the index validates payloads
when populated; an empty SHA skips verification with a debug log.
"""

from __future__ import annotations

import hashlib
import importlib.resources as ir
import io
import json
import logging
import zipfile
from pathlib import Path
from typing import Any

import requests
from pydantic import BaseModel, Field

log = logging.getLogger(__name__)

INDEX_FILENAME = "mordor_index.json"

# Guards against zip-bombs / runaway payloads on network-fetched datasets.
MAX_DOWNLOAD_BYTES = 512 * 1024 * 1024
MAX_MEMBER_BYTES = 512 * 1024 * 1024


def _reject_unsafe_path(fragment: str) -> None:
    """Raise if a path fragment could escape its base dir (``..`` or absolute)."""
    p = Path(fragment)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(f"Refusing unsafe dataset path fragment: {fragment!r}")


def _parse_events_member(raw: str) -> tuple[list[dict[str, Any]], bool]:
    """Parse one ``.json`` ZIP member into a list of event dicts.

    Handles three shapes: a JSON array of events, a single JSON object, and
    **JSON Lines** (one JSON object per line) — the on-disk format used by the
    Security-Datasets (Mordor) corpus. Blank lines and unparseable lines are
    skipped. Returns ``(events, recognized)`` where ``recognized`` is False only
    for content that isn't event data at all (empty, or a bare scalar), so the
    caller can tell "no events here" from "this wasn't a dataset member".
    """
    raw = raw.strip()
    if not raw:
        return [], False
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # JSON Lines: parse each non-empty line independently.
        events: list[dict[str, Any]] = []
        recognized = False
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            recognized = True
            if isinstance(obj, dict):
                events.append(obj)
        return events, recognized
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)], True
    if isinstance(data, dict):
        return [data], True
    return [], False


class MordorDataset(BaseModel):
    """One Mordor dataset's metadata + parsed event list."""

    dataset_id: str
    technique_id: str
    platform: str
    events: list[dict[str, Any]] = Field(default_factory=list)


def load_builtin_index() -> dict[str, Any]:
    """Load the packaged Security-Datasets index snapshot."""
    pkg = "detect_forge.backtest.corpus_data"
    with ir.files(pkg).joinpath(INDEX_FILENAME).open("r", encoding="utf-8") as f:
        raw: dict[str, Any] = json.load(f)
    return raw


class MordorCorpus:
    """Lazy corpus loader. Datasets fetched + cached as requested."""

    def __init__(
        self,
        cache_dir: Path,
        *,
        platform_filter: set[str] | None = None,
        technique_filter: set[str] | None = None,
        source_override: Path | None = None,
        index_override: dict[str, Any] | None = None,
        no_cache: bool = False,
    ) -> None:
        self._cache_dir = cache_dir / "security-datasets"
        self._platform_filter = platform_filter
        self._technique_filter = technique_filter
        self._source_override = source_override
        self._no_cache = no_cache
        self._consulted: set[tuple[str, str]] = set()

        if index_override is not None:
            self._index = index_override
        elif source_override is not None:
            self._index = json.loads(
                (source_override / "index.json").read_text(encoding="utf-8")
            )
        else:
            self._index = load_builtin_index()

    def source_label(self) -> str:
        """Return a short string for the report's ``mordor_source`` field."""
        if self._source_override is not None:
            return str(self._source_override)
        return "fetched"

    def datasets_for(self, technique_id: str) -> list[MordorDataset]:
        """Return datasets for this technique after applying filters.

        Fetches + caches any dataset not already on disk. Returns [] when:
        - technique_id is excluded by ``technique_filter``
        - technique_id has no entries in the index
        - all entries are excluded by ``platform_filter``
        """
        if self._technique_filter and technique_id not in self._technique_filter:
            return []
        datasets_index = self._index.get("datasets", {})
        candidates = datasets_index.get(technique_id, [])
        if self._platform_filter:
            candidates = [
                c for c in candidates if c.get("platform") in self._platform_filter
            ]

        results: list[MordorDataset] = []
        for entry in candidates:
            try:
                ds = self._load_dataset(technique_id, entry)
            except Exception as exc:  # noqa: BLE001
                log.warning(
                    "Failed to load dataset %s for %s: %s",
                    entry.get("dataset_id"),
                    technique_id,
                    exc,
                )
                continue
            results.append(ds)
            self._consulted.add((technique_id, entry["dataset_id"]))
        return results

    def datasets_consulted(self) -> int:
        return len(self._consulted)

    # --- internal helpers ---

    def _cache_path(self, technique_id: str, dataset_id: str) -> Path:
        return self._cache_dir / "datasets" / technique_id / f"{dataset_id}.json"

    def _load_dataset(
        self, technique_id: str, entry: dict[str, Any]
    ) -> MordorDataset:
        if self._source_override is not None:
            events = self._load_from_local_override(entry)
        else:
            events = self._fetch_or_use_cache(technique_id, entry)
        return MordorDataset(
            dataset_id=entry["dataset_id"],
            technique_id=technique_id,
            platform=entry.get("platform", "unknown"),
            events=events,
        )

    def _fetch_or_use_cache(
        self, technique_id: str, entry: dict[str, Any]
    ) -> list[dict[str, Any]]:
        cache_path = self._cache_path(technique_id, entry["dataset_id"])
        if not self._no_cache and cache_path.is_file():
            cached: list[dict[str, Any]] = json.loads(
                cache_path.read_text(encoding="utf-8")
            )
            return cached
        url = entry["url"]
        log.debug("Fetching Mordor dataset: %s", url)
        response = requests.get(url, timeout=60)
        response.raise_for_status()
        content = response.content
        if len(content) > MAX_DOWNLOAD_BYTES:
            raise ValueError(
                f"Dataset {entry['dataset_id']} download exceeds "
                f"{MAX_DOWNLOAD_BYTES} bytes; refusing"
            )
        # Verify integrity BEFORE extracting or caching. A mismatch means the
        # payload is not what the index vouched for — drop it, don't use it.
        expected_sha = entry.get("sha256", "")
        if expected_sha:
            actual = hashlib.sha256(content).hexdigest()
            if actual != expected_sha:
                raise ValueError(
                    f"SHA256 mismatch for {entry['dataset_id']}: "
                    f"index={expected_sha} actual={actual}"
                )
        else:
            log.debug(
                "SHA256 not populated for %s; skipping verification",
                entry["dataset_id"],
            )
        events = self._extract_events_from_zip(content)
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_text(json.dumps(events), encoding="utf-8")
        return events

    def _load_from_local_override(self, entry: dict[str, Any]) -> list[dict[str, Any]]:
        """Locate ``entry``'s ZIP inside a local Security-Datasets checkout.

        Tries (in order):
        1. Flat layout: ``source_override/<dataset_id>.zip``
        2. URL-path-derived layout (strip ``scheme://host`` from URL)
        3. Recursive search for ``<dataset_id>.zip`` anywhere under override
        """
        assert self._source_override is not None  # noqa: S101
        base = self._source_override.resolve()
        dataset_id = entry["dataset_id"]
        _reject_unsafe_path(dataset_id)
        candidate = self._source_override / f"{dataset_id}.zip"
        if not candidate.is_file():
            # Fall back to URL-path-derived layout.
            url_path = entry["url"].split("//", 1)[-1].split("/", 1)[-1]
            _reject_unsafe_path(url_path)
            candidate = self._source_override / url_path
        if not candidate.is_file():
            # Last resort: recursive search by dataset_id, constrained to the
            # override dir.
            matches = [
                m
                for m in self._source_override.rglob(f"{dataset_id}.zip")
                if m.resolve().is_relative_to(base)
            ]
            if matches:
                candidate = matches[0]
        if not candidate.resolve().is_relative_to(base):
            raise ValueError(
                f"Refusing to read dataset outside override dir: {candidate}"
            )
        return self._extract_events_from_zip(candidate.read_bytes())

    def _extract_events_from_zip(self, blob: bytes) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        recognized_any = False
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            json_names = [n for n in zf.namelist() if n.endswith(".json")]
            if not json_names:
                raise ValueError("ZIP archive contains no .json file")
            for name in json_names:
                info = zf.getinfo(name)
                if info.file_size > MAX_MEMBER_BYTES:
                    raise ValueError(
                        f"ZIP member {name} decompresses to {info.file_size} bytes "
                        f"(> {MAX_MEMBER_BYTES}); refusing (possible zip bomb)"
                    )
                with zf.open(name) as f:
                    member_events, recognized = _parse_events_member(
                        f.read().decode("utf-8", "replace")
                    )
                if recognized:
                    recognized_any = True
                    events.extend(member_events)
        if not recognized_any:
            raise ValueError("Mordor dataset ZIP contained no parseable JSON events")
        return events
