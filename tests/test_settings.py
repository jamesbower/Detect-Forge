from __future__ import annotations

from pathlib import Path

import pytest

from detect_forge.settings import Settings


def test_defaults_match_spec(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    s = Settings()
    assert s.cache_dir == Path.home() / ".cache" / "detect-forge"
    assert s.cache_ttl_hours == 24
    assert s.attack_domain == "enterprise-attack"
    assert s.no_cache is False


def test_env_prefix_overrides_cache_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("DETECT_FORGE_CACHE_DIR", str(tmp_path / "alt"))
    s = Settings()
    assert s.cache_dir == tmp_path / "alt"


def test_env_prefix_overrides_no_cache(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DETECT_FORGE_NO_CACHE", "true")
    s = Settings()
    assert s.no_cache is True


def test_env_prefix_overrides_attack_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DETECT_FORGE_ATTACK_DOMAIN", "ics-attack")
    s = Settings()
    assert s.attack_domain == "ics-attack"


def test_semantic_threshold_out_of_range_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    """DETECT_FORGE_SEMANTIC_THRESHOLD outside the cosine range [-1, 1] is rejected."""
    from pydantic import ValidationError

    monkeypatch.setenv("DETECT_FORGE_SEMANTIC_THRESHOLD", "5")
    with pytest.raises(ValidationError):
        Settings()


def test_semantic_threshold_in_range_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DETECT_FORGE_SEMANTIC_THRESHOLD", "0.7")
    assert Settings().semantic_threshold == 0.7
