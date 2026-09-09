from __future__ import annotations

from pathlib import Path

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from .cache import default_cache_dir


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="DETECT_FORGE_", env_file=".env", extra="ignore")

    cache_dir: Path = Field(default_factory=default_cache_dir)
    cache_ttl_hours: int = 24
    attack_domain: str = "enterprise-attack"
    no_cache: bool = False
    semantic_threshold: float | None = None

    @field_validator("semantic_threshold")
    @classmethod
    def _threshold_in_range(cls, v: float | None) -> float | None:
        if v is not None and not -1.0 <= v <= 1.0:
            raise ValueError(
                f"semantic_threshold must be in [-1, 1] (cosine range); got {v}"
            )
        return v
