"""ATT&CK coverage gap analysis subcommand.

Public entry point: ``scan_coverage(rule_dir, *, domain, ..., priority_list)``.

Returns a fully-resolved ``CoverageReport`` ready to hand to ``reporter.render()``
or to inspect programmatically (``report.summary.priority_gap`` drives CI gating).
"""

from __future__ import annotations

from pathlib import Path

from ..stale.attack_client import build_index
from ..stale.rule_parser import parse_rule_dir
from .analyzer import analyze_coverage
from .models import (
    CoverageReport,
    CoverageState,
    CoverageSummary,
    MigrationItem,
    TacticRollup,
    TechniqueCoverage,
)
from .priority import resolve_priority_techniques

__all__ = [
    "CoverageReport",
    "CoverageState",
    "CoverageSummary",
    "MigrationItem",
    "TacticRollup",
    "TechniqueCoverage",
    "scan_coverage",
]


def scan_coverage(
    rule_dir: Path,
    *,
    domain: str = "enterprise-attack",
    cache_dir: Path | None = None,
    cache_ttl_hours: int = 24,
    no_cache: bool = False,
    priority_list: Path | None = None,
    config_priority_list: Path | None = None,
    config_dir: Path | None = None,
) -> CoverageReport:
    """Run a full coverage scan: parse rules, fetch ATT&CK, analyze.

    Args:
        rule_dir: Directory containing detection rules (Sigma .yml and/or
            Elastic .toml). Walked recursively.
        domain: ATT&CK domain — ``enterprise-attack``, ``ics-attack``,
            or ``mobile-attack``.
        cache_dir: Override for the cache directory (typically left as None
            so the XDG-aware default wins).
        cache_ttl_hours: Hours before the cached STIX bundle is considered
            stale. Ignored when ``no_cache`` is True.
        no_cache: When True, bypass the cache entirely and refetch the STIX
            bundle.
        priority_list: Path to a custom priority list JSON passed on the CLI
            (``--priority-list``). Highest precedence. When None, falls back to
            the config value then the built-in CTID default.
        config_priority_list: The ``[coverage] priority_list`` value from
            ``.detect-forge.toml`` (may be relative). Used only when
            ``priority_list`` is None.
        config_dir: Directory of the discovered ``.detect-forge.toml``, used to
            resolve a relative ``config_priority_list`` against the config
            location rather than the current working directory.
    """
    rules = parse_rule_dir(rule_dir)
    index = build_index(
        domain=domain,
        cache_dir=cache_dir,
        ttl_hours=0 if no_cache else cache_ttl_hours,
    )
    priority_ids = resolve_priority_techniques(
        cli_path=priority_list,
        config_path=config_priority_list,
        start_dir=config_dir,
    )
    return analyze_coverage(rules, index, priority_ids)
