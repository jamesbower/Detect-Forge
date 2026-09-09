"""Embedding model wrapper, cosine similarity, and on-disk embedding cache.

This module owns:
- The fastembed model id and a thin wrapper that returns plain-Python vectors.
- Cosine similarity (vectors are normalized by fastembed, so this is effectively
  a dot product, but we keep the formula for clarity).
- SHA256-based hashing helpers (rule text → key; STIX bundle → cache-version tag).
- JSON-backed cache load/save for both technique and rule embeddings, with
  atomic writes (tmp + rename) mirroring the existing ``cache.write_cache`` pattern.

It does NOT know about scoring, findings, or the rest of the staleness pipeline.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

import fastembed

from ..cache import default_cache_dir

MODEL_ID = "BAAI/bge-small-en-v1.5"
"""Canonical fastembed model identifier."""

MODEL_ID_SLUG = "bge-small-en-v1.5"
"""Filename-safe form of MODEL_ID (slash stripped). Used in cache filenames."""


class EmbeddingModel:
    """Thin wrapper around ``fastembed.TextEmbedding``.

    Returns plain Python lists of floats so vectors serialize cleanly through
    pydantic + JSON. Configures fastembed's model cache under
    ``default_cache_dir() / "fastembed_models"`` so model files live alongside
    our STIX cache.
    """

    def __init__(self, cache_dir: Path | None = None) -> None:
        resolved = cache_dir if cache_dir is not None else default_cache_dir()
        models_dir = resolved / "fastembed_models"
        models_dir.mkdir(parents=True, exist_ok=True)
        self._model = fastembed.TextEmbedding(
            model_name=MODEL_ID,
            cache_dir=str(models_dir),
        )

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        """Return one vector per input text. Vectors are normalized (||v|| ≈ 1)."""
        return [list(map(float, v)) for v in self._model.embed(texts)]


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two equal-length vectors.

    For fastembed's normalized output this collapses to a dot product, but the
    explicit formula keeps the math obvious for readers.
    """
    if len(a) != len(b):
        raise ValueError(f"vector length mismatch: {len(a)} vs {len(b)}")
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def rule_text_hash(text: str) -> str:
    """Stable hex digest of a rule text; used as the cache key for rule embeddings."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def stix_bundle_hash(cache_dir: Path, domain: str) -> str:
    """First 8 hex chars of SHA256(stix-bundle-file). Used in technique cache filenames.

    Returns the sentinel ``"nobundle"`` when the bundle is not on disk (e.g. a
    direct ``score_rules`` caller that passed a cache_dir without pre-fetching)
    so callers get a stable cache key instead of a FileNotFoundError.
    """
    bundle = cache_dir / f"{domain}.json"
    if not bundle.is_file():
        return "nobundle"
    h = hashlib.sha256(bundle.read_bytes()).hexdigest()
    return h[:8]


def _embeddings_dir(cache_dir: Path) -> Path:
    d = cache_dir / "embeddings"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _technique_cache_path(cache_dir: Path, model_id_slug: str, stix_hash: str) -> Path:
    return _embeddings_dir(cache_dir) / f"techniques.{model_id_slug}.{stix_hash}.json"


def _rule_cache_path(cache_dir: Path, model_id_slug: str) -> Path:
    return _embeddings_dir(cache_dir) / f"rules.{model_id_slug}.json"


def load_technique_cache(
    cache_dir: Path, model_id_slug: str, stix_hash: str
) -> dict[str, list[float]]:
    """Read the per-STIX-bundle technique embedding cache. Returns {} if missing."""
    path = _technique_cache_path(cache_dir, model_id_slug, stix_hash)
    if not path.exists():
        return {}
    return _decode_json(path)


def save_technique_cache(
    cache_dir: Path,
    model_id_slug: str,
    stix_hash: str,
    embeddings: dict[str, list[float]],
) -> None:
    """Atomically write the technique embedding cache (tmp + rename)."""
    path = _technique_cache_path(cache_dir, model_id_slug, stix_hash)
    _atomic_write(path, embeddings)


def load_rule_cache(cache_dir: Path, model_id_slug: str) -> dict[str, list[float]]:
    """Read the rule embedding cache (persistent across STIX updates)."""
    path = _rule_cache_path(cache_dir, model_id_slug)
    if not path.exists():
        return {}
    return _decode_json(path)


def save_rule_cache(
    cache_dir: Path, model_id_slug: str, embeddings: dict[str, list[float]]
) -> None:
    """Atomically write the rule embedding cache (tmp + rename)."""
    path = _rule_cache_path(cache_dir, model_id_slug)
    _atomic_write(path, embeddings)


def _decode_json(path: Path) -> dict[str, list[float]]:
    raw: Any = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        return {}
    return {str(k): list(map(float, v)) for k, v in raw.items()}


def _atomic_write(path: Path, data: dict[str, list[float]]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(path)
