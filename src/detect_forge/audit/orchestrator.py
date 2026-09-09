"""Audit orchestrator: composes stale + coverage + backtest into AuditReport.

Each subcommand runs sequentially in-process. Failure isolation: a
crashing subcommand becomes an AuditSubResult with status='errored';
the other two still run.

Gate composition per spec §5: strict-AND — audit_would_gate is True
only when ALL enabled subcommands' would_gate predicates are True.
gate_strategy='never' overrides to always-False.

The scoring/gate-predicate functions are imported from .scoring; this
module is purely composition + error handling + summary building.
"""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from ..backtest import scan_backtest
from ..coverage import scan_coverage
from ..stale import scan as scan_stale
from .models import AuditReport, AuditSubResult, AuditSummary, SubcommandName
from .scoring import (
    backtest_verification_rate,
    backtest_would_gate,
    coverage_completeness,
    coverage_would_gate,
    stale_health,
    stale_would_gate,
)

log = logging.getLogger(__name__)


def run_audit(
    rule_dir: Path,
    *,
    enabled: set[SubcommandName] | None = None,
    gate_strategy: Literal["all", "never"] = "all",
    domain: str = "enterprise-attack",
    cache_dir: Path | None = None,
    cache_ttl_hours: int = 24,
    no_cache: bool = False,
    priority_list: Path | None = None,
    platform: str = "all",
    technique_filter: set[str] | None = None,
    mordor_source: Path | None = None,
    semantic_threshold: float = 0.65,
    llm_model: str | None = None,
    max_proposals: int = 5,
    coverage_gate_on_priority_gaps: bool = True,
    backtest_gate_on_priority_silence: bool = True,
    backtest_gate_on_broken_rules: bool = True,
) -> AuditReport:
    """Compose all 3 subcommands into a single AuditReport.

    Each subcommand call is wrapped in try/except. A crashing subcommand
    becomes a sub_result with status='errored' and the rest continue.

    Args:
        rule_dir: Detection rule directory.
        enabled: Set of subcommands to run. Default: all 3.
        gate_strategy: 'all' for strict-AND composition; 'never' to disable.
        domain, cache_dir, cache_ttl_hours, no_cache, priority_list:
            forwarded to each subcommand.
        platform, technique_filter, mordor_source: backtest-only kwargs.
        semantic_threshold, llm_model, max_proposals: stale-only kwargs.
    """
    if enabled is None:
        enabled = {"stale", "coverage", "backtest"}

    started = time.monotonic()
    sub_results: list[AuditSubResult] = []
    rules_scanned: int = 0

    # ---- Stale ----
    if "stale" in enabled:
        try:
            stale_report = scan_stale(
                rule_dir,
                domain=domain,
                cache_dir=cache_dir,
                cache_ttl_hours=cache_ttl_hours,
                no_cache=no_cache,
                semantic_threshold=semantic_threshold,
                llm_model=llm_model,
                max_proposals=max_proposals,
            )
            rules_scanned = max(rules_scanned, stale_report.summary.total_rules)
            sub_results.append(AuditSubResult(
                subcommand="stale",
                status="ran",
                would_gate=stale_would_gate(stale_report),
                score=stale_health(stale_report),
                stale_report=stale_report,
            ))
        except Exception as exc:  # noqa: BLE001 — failure isolation per spec §11
            log.error("stale subcommand failed: %s", exc, exc_info=True)
            sub_results.append(AuditSubResult(
                subcommand="stale",
                status="errored",
                error=f"{type(exc).__name__}: {exc}",
            ))
    else:
        sub_results.append(AuditSubResult(subcommand="stale", status="skipped"))

    # ---- Coverage ----
    if "coverage" in enabled:
        try:
            cov_report = scan_coverage(
                rule_dir,
                domain=domain,
                cache_dir=cache_dir,
                cache_ttl_hours=cache_ttl_hours,
                no_cache=no_cache,
                priority_list=priority_list,
            )
            rules_scanned = max(rules_scanned, cov_report.summary.rules_parsed)
            sub_results.append(AuditSubResult(
                subcommand="coverage",
                status="ran",
                would_gate=coverage_would_gate(
                    cov_report, gate_on_priority_gaps=coverage_gate_on_priority_gaps
                ),
                score=coverage_completeness(cov_report),
                coverage_report=cov_report,
            ))
        except Exception as exc:  # noqa: BLE001
            log.error("coverage subcommand failed: %s", exc, exc_info=True)
            sub_results.append(AuditSubResult(
                subcommand="coverage",
                status="errored",
                error=f"{type(exc).__name__}: {exc}",
            ))
    else:
        sub_results.append(AuditSubResult(subcommand="coverage", status="skipped"))

    # ---- Backtest ----
    if "backtest" in enabled:
        try:
            bt_report = scan_backtest(
                rule_dir,
                domain=domain,
                cache_dir=cache_dir,
                cache_ttl_hours=cache_ttl_hours,
                no_cache=no_cache,
                priority_list=priority_list,
                platform=platform,
                technique_filter=technique_filter,
                mordor_source=mordor_source,
            )
            rules_scanned = max(rules_scanned, bt_report.summary.rules_parsed)
            sub_results.append(AuditSubResult(
                subcommand="backtest",
                status="ran",
                would_gate=backtest_would_gate(
                    bt_report,
                    gate_on_priority_silence=backtest_gate_on_priority_silence,
                    gate_on_broken_rules=backtest_gate_on_broken_rules,
                ),
                score=backtest_verification_rate(bt_report),
                backtest_report=bt_report,
            ))
        except Exception as exc:  # noqa: BLE001
            log.error("backtest subcommand failed: %s", exc, exc_info=True)
            sub_results.append(AuditSubResult(
                subcommand="backtest",
                status="errored",
                error=f"{type(exc).__name__}: {exc}",
            ))
    else:
        sub_results.append(AuditSubResult(subcommand="backtest", status="skipped"))

    # ---- Compose summary ----
    ran = [sr for sr in sub_results if sr.status == "ran"]
    skipped = [sr for sr in sub_results if sr.status == "skipped"]
    errored = [sr for sr in sub_results if sr.status == "errored"]

    audit_would_gate = (
        gate_strategy == "all"
        and len(ran) > 0
        and all(sr.would_gate for sr in ran)
        and len(ran) == len(enabled)  # All enabled subcommands actually ran
    )

    stale_sr = next((sr for sr in ran if sr.subcommand == "stale"), None)
    cov_sr = next((sr for sr in ran if sr.subcommand == "coverage"), None)
    bt_sr = next((sr for sr in ran if sr.subcommand == "backtest"), None)

    summary = AuditSummary(
        rules_scanned=rules_scanned,
        stale_health=stale_sr.score if stale_sr else None,
        coverage_completeness=cov_sr.score if cov_sr else None,
        backtest_verification_rate=bt_sr.score if bt_sr else None,
        subcommands_ran=len(ran),
        subcommands_skipped=len(skipped),
        subcommands_errored=len(errored),
        audit_would_gate=audit_would_gate,
        attack_domain=domain,
        generated_at=datetime.now(UTC),
        elapsed_seconds=time.monotonic() - started,
    )

    return AuditReport(summary=summary, sub_results=sub_results)
