"""Backtest orchestrator: rules × datasets → rollup → BacktestReport."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from .._tactics import TACTIC_DISPLAY_ORDER
from ..stale.models import AttackIndex, DetectionRule
from .corpus import MordorCorpus
from .matchers._base import select_matcher
from .models import (
    BacktestReport,
    BacktestSummary,
    FireRecord,
    FireStatus,
    RuleResult,
    RuleStatus,
    TechniqueResult,
    TechniqueRollup,
    TechniqueStatus,
)

log = logging.getLogger(__name__)


def run_backtest(
    rules: list[DetectionRule],
    index: AttackIndex,
    corpus: MordorCorpus,
    priority_ids: set[str],
) -> BacktestReport:
    """Run each rule against the Mordor datasets for its tagged techniques.

    Per spec §5: each (rule, technique) pair becomes a TechniqueResult; rules
    roll up to RuleResult via _derive_rule_status; techniques roll up to
    TechniqueRollup across all rules tagging them. Matcher exceptions on a
    single dataset are caught + logged DEBUG so one bad dataset can't crash
    the whole scan.
    """
    rule_results: list[RuleResult] = []
    pair_results_all: list[TechniqueResult] = []  # for technique rollup

    for rule in rules:
        matcher, rule_format = select_matcher(rule)
        if matcher is None:
            rule_results.append(
                RuleResult(
                    rule_id=rule.rule_id or rule.title,
                    rule_title=rule.title,
                    source_file=rule.source_file,
                    rule_format=rule_format,
                    status="unsupported",
                    unsupported_reason="unknown rule format",
                    technique_results=[],
                )
            )
            continue

        supports, reason = matcher.support_reason(rule)
        pair_results: list[TechniqueResult] = []

        for tid in rule.technique_ids:
            tech = index.techniques.get(tid)
            if tech is None or tech.deprecated or tech.revoked:
                continue
            datasets = corpus.datasets_for(tid)
            if not supports or not datasets:
                pair_results.append(
                    TechniqueResult(
                        rule_id=rule.rule_id or rule.title,
                        rule_title=rule.title,
                        technique_id=tid,
                        status="untested",
                        datasets_tested=len(datasets),
                        datasets_fired=0,
                    )
                )
                continue
            fires: list[FireRecord] = []
            datasets_fired = 0
            for ds in datasets:
                try:
                    ds_fires = matcher.match(rule, ds.events, ds.dataset_id, technique_id=tid)
                except Exception as exc:  # noqa: BLE001
                    # One bad dataset must not crash the scan, but surface it at
                    # WARNING so systematic matcher bugs don't hide as false silents.
                    log.warning(
                        "Matcher exception on %s/%s (%s): %s",
                        rule.source_file,
                        ds.dataset_id,
                        tid,
                        exc,
                    )
                    continue
                if ds_fires:
                    datasets_fired += 1
                    fires.extend(ds_fires)
            # UI display cap: keep at most 20 FireRecords per (rule, technique)
            # pair to bound terminal/HTML report size. The full datasets_fired
            # count is still accurate (incremented above) — only the per-pair
            # fires list is truncated.
            fires = fires[:20]
            status: FireStatus = "verified" if datasets_fired > 0 else "silent"
            pair_results.append(
                TechniqueResult(
                    rule_id=rule.rule_id or rule.title,
                    rule_title=rule.title,
                    technique_id=tid,
                    status=status,
                    datasets_tested=len(datasets),
                    datasets_fired=datasets_fired,
                    fires=fires,
                )
            )

        pair_results_all.extend(pair_results)
        rule_results.append(
            RuleResult(
                rule_id=rule.rule_id or rule.title,
                rule_title=rule.title,
                source_file=rule.source_file,
                rule_format=rule_format,
                status=_derive_rule_status(pair_results, supports),
                unsupported_reason=reason if not supports else None,
                technique_results=pair_results,
            )
        )

    technique_rollups = _build_technique_rollups(
        rules, pair_results_all, index, priority_ids,
    )
    summary = _build_summary(
        rule_results, technique_rollups, corpus, index,
        rules_parsed=len(rules),
    )

    return BacktestReport(
        summary=summary,
        rule_results=_sort_rules_for_display(rule_results),
        technique_rollups=_sort_techniques_for_display(technique_rollups),
    )


def _derive_rule_status(
    pairs: list[TechniqueResult], supports: bool,
) -> RuleStatus:
    if not supports:
        return "unsupported"
    tested = [p for p in pairs if p.datasets_tested > 0]
    if not tested:
        return "untested"
    fired = [p for p in tested if p.status == "verified"]
    if len(fired) == len(tested):
        return "fires"
    if not fired:
        return "silent_on_all"
    return "partial"


def _build_technique_rollups(
    rules: list[DetectionRule],
    pair_results: list[TechniqueResult],
    index: AttackIndex,
    priority_ids: set[str],
) -> list[TechniqueRollup]:
    # Build tid → rules_tagged_count once. O(rules) instead of O(rules × techniques).
    rules_tagged_by_tid: dict[str, int] = {}
    for r in rules:
        for tid in r.technique_ids:
            rules_tagged_by_tid[tid] = rules_tagged_by_tid.get(tid, 0) + 1

    # Aggregate by technique_id.
    by_tid: dict[str, list[TechniqueResult]] = {}
    for p in pair_results:
        by_tid.setdefault(p.technique_id, []).append(p)
    rollups: list[TechniqueRollup] = []
    for tid, prs in by_tid.items():
        tech = index.techniques.get(tid)
        if tech is None:
            continue
        rules_tagged = rules_tagged_by_tid.get(tid, 0)
        rules_fired = sum(1 for p in prs if p.status == "verified")
        # datasets_for(tid) is keyed by technique, so all rules tagging tid see
        # the same dataset set; max() is a safety net for any future case where
        # rules tag differently filtered subsets.
        datasets_available = max((p.datasets_tested for p in prs), default=0)
        rollups.append(TechniqueRollup(
            technique_id=tid,
            technique_name=tech.name,
            tactic_ids=tech.tactic_ids,
            status=_derive_technique_status(prs),
            is_priority=tid in priority_ids,
            rules_tagged=rules_tagged,
            rules_fired=rules_fired,
            datasets_available=datasets_available,
        ))
    return rollups


def _derive_technique_status(pairs: list[TechniqueResult]) -> TechniqueStatus:
    tested = [p for p in pairs if p.datasets_tested > 0]
    if not tested:
        return "untested"
    if any(p.status == "verified" for p in tested):
        return "verified"
    return "silent"


def _build_summary(
    rule_results: list[RuleResult],
    technique_rollups: list[TechniqueRollup],
    corpus: MordorCorpus,
    index: AttackIndex,
    rules_parsed: int,
) -> BacktestSummary:
    return BacktestSummary(
        rules_parsed=rules_parsed,
        rules_fires=sum(1 for r in rule_results if r.status == "fires"),
        rules_partial=sum(1 for r in rule_results if r.status == "partial"),
        rules_silent_on_all=sum(
            1 for r in rule_results if r.status == "silent_on_all"
        ),
        rules_untested=sum(1 for r in rule_results if r.status == "untested"),
        rules_unsupported=sum(
            1 for r in rule_results if r.status == "unsupported"
        ),
        techniques_in_scope=len(technique_rollups),
        techniques_verified=sum(
            1 for t in technique_rollups if t.status == "verified"
        ),
        techniques_silent=sum(
            1 for t in technique_rollups if t.status == "silent"
        ),
        techniques_untested=sum(
            1 for t in technique_rollups if t.status == "untested"
        ),
        priority_total=sum(1 for t in technique_rollups if t.is_priority),
        priority_verified=sum(
            1
            for t in technique_rollups
            if t.is_priority and t.status == "verified"
        ),
        priority_silent=sum(
            1
            for t in technique_rollups
            if t.is_priority and t.status == "silent"
        ),
        priority_untested=sum(
            1
            for t in technique_rollups
            if t.is_priority and t.status == "untested"
        ),
        datasets_consulted=corpus.datasets_consulted(),
        mordor_source=corpus.source_label(),
        attack_domain=index.source_domain,
        attack_fetched_at=index.fetched_at,
        generated_at=datetime.now(UTC),
    )


_RULE_STATUS_RANK = {
    "silent_on_all": 0,
    "partial": 1,
    "untested": 2,
    "unsupported": 3,
    "fires": 4,
}


def _sort_rules_for_display(rules: list[RuleResult]) -> list[RuleResult]:
    return sorted(rules, key=lambda r: (_RULE_STATUS_RANK.get(r.status, 999), r.rule_title))


def _sort_techniques_for_display(
    techs: list[TechniqueRollup],
) -> list[TechniqueRollup]:
    tactic_rank = {short: i for i, short in enumerate(TACTIC_DISPLAY_ORDER)}
    status_rank = {"silent": 0, "untested": 1, "verified": 2}

    def key(t: TechniqueRollup) -> tuple[int, int, int, str]:
        priority_silent = 0 if (t.is_priority and t.status == "silent") else 1
        primary_tactic = t.tactic_ids[0] if t.tactic_ids else ""
        return (
            priority_silent,
            tactic_rank.get(primary_tactic, 999),
            status_rank.get(t.status, 999),
            t.technique_id,
        )

    return sorted(techs, key=key)
