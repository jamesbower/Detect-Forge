from __future__ import annotations

from pathlib import Path

import pytest
from pytest_mock import MockerFixture

from detect_forge.stale.embeddings import (
    MODEL_ID,
    MODEL_ID_SLUG,
    EmbeddingModel,
    cosine_similarity,
    load_rule_cache,
    load_technique_cache,
    rule_text_hash,
    save_rule_cache,
    save_technique_cache,
    stix_bundle_hash,
)


def test_model_id_constants() -> None:
    """Model id (canonical) and slug (filename-safe) must stay in sync."""
    assert MODEL_ID == "BAAI/bge-small-en-v1.5"
    assert MODEL_ID_SLUG == "bge-small-en-v1.5"
    assert "/" not in MODEL_ID_SLUG


def test_cosine_similarity_identical_vectors() -> None:
    assert cosine_similarity([1.0, 0.0, 0.0], [1.0, 0.0, 0.0]) == pytest.approx(1.0)


def test_cosine_similarity_orthogonal_vectors() -> None:
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == pytest.approx(0.0)


def test_cosine_similarity_opposite_vectors() -> None:
    assert cosine_similarity([1.0, 0.0], [-1.0, 0.0]) == pytest.approx(-1.0)


def test_cosine_similarity_near_identical() -> None:
    # Slight perturbation: similarity must be very close to 1 but less than 1.
    sim = cosine_similarity([1.0, 0.1], [1.0, 0.0])
    assert 0.99 < sim < 1.0


def test_rule_text_hash_is_deterministic() -> None:
    h1 = rule_text_hash("PowerShell Encoded Command")
    h2 = rule_text_hash("PowerShell Encoded Command")
    assert h1 == h2
    assert len(h1) == 64  # SHA256 hex


def test_rule_text_hash_differs_for_different_inputs() -> None:
    assert rule_text_hash("a") != rule_text_hash("b")


def test_stix_bundle_hash_returns_8_hex_chars(tmp_path: Path) -> None:
    bundle = tmp_path / "enterprise-attack.json"
    bundle.write_text('{"type": "bundle"}')
    h = stix_bundle_hash(tmp_path, "enterprise-attack")
    assert len(h) == 8
    assert all(c in "0123456789abcdef" for c in h)


def test_stix_bundle_hash_differs_when_content_changes(tmp_path: Path) -> None:
    bundle = tmp_path / "enterprise-attack.json"
    bundle.write_text('{"v": 1}')
    h1 = stix_bundle_hash(tmp_path, "enterprise-attack")
    bundle.write_text('{"v": 2}')
    h2 = stix_bundle_hash(tmp_path, "enterprise-attack")
    assert h1 != h2


def test_technique_cache_round_trip(tmp_path: Path) -> None:
    cache_dir = tmp_path
    embeddings = {"T1059": [0.1, 0.2, 0.3], "T1059.001": [0.4, 0.5, 0.6]}
    save_technique_cache(cache_dir, MODEL_ID_SLUG, "abc12345", embeddings)
    loaded = load_technique_cache(cache_dir, MODEL_ID_SLUG, "abc12345")
    assert loaded == embeddings


def test_technique_cache_returns_empty_dict_when_missing(tmp_path: Path) -> None:
    loaded = load_technique_cache(tmp_path, MODEL_ID_SLUG, "deadbeef")
    assert loaded == {}


def test_technique_cache_invalidated_by_different_stix_hash(tmp_path: Path) -> None:
    """A cache file written under one stix hash is invisible under a different hash."""
    save_technique_cache(tmp_path, MODEL_ID_SLUG, "aaaaaaaa", {"T1": [1.0]})
    assert load_technique_cache(tmp_path, MODEL_ID_SLUG, "aaaaaaaa") == {"T1": [1.0]}
    assert load_technique_cache(tmp_path, MODEL_ID_SLUG, "bbbbbbbb") == {}


def test_rule_cache_round_trip(tmp_path: Path) -> None:
    hashes = {"abc": [0.1, 0.2], "def": [0.3, 0.4]}
    save_rule_cache(tmp_path, MODEL_ID_SLUG, hashes)
    loaded = load_rule_cache(tmp_path, MODEL_ID_SLUG)
    assert loaded == hashes


def test_rule_cache_returns_empty_when_missing(tmp_path: Path) -> None:
    assert load_rule_cache(tmp_path, MODEL_ID_SLUG) == {}


def test_embedding_model_embed_batch_calls_fastembed(mocker: MockerFixture) -> None:
    """embed_batch must pass texts to fastembed and return vectors as plain lists."""
    import numpy as np

    fake_vectors = [np.array([0.1, 0.2, 0.3]), np.array([0.4, 0.5, 0.6])]
    mocker.patch(
        "detect_forge.stale.embeddings.fastembed.TextEmbedding.__init__",
        return_value=None,
    )
    mocker.patch(
        "detect_forge.stale.embeddings.fastembed.TextEmbedding.embed",
        return_value=iter(fake_vectors),
    )

    model = EmbeddingModel()
    result = model.embed_batch(["text one", "text two"])

    assert len(result) == 2
    assert result[0] == [0.1, 0.2, 0.3]
    assert result[1] == [0.4, 0.5, 0.6]
    # Vectors returned as plain Python lists (not numpy arrays), so they serialize
    # cleanly through pydantic + JSON.
    assert isinstance(result[0], list)
    assert isinstance(result[0][0], float)


def test_stix_bundle_hash_missing_bundle_does_not_raise(tmp_path: Path) -> None:
    """A direct caller with no cached bundle must not get a FileNotFoundError — T7."""
    from detect_forge.stale.embeddings import stix_bundle_hash

    h = stix_bundle_hash(tmp_path, "enterprise-attack")
    assert isinstance(h, str) and h
