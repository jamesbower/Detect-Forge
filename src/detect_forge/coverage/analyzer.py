"""Coverage analyzer: classify each ATT&CK technique as full / shallow / gap.

This module has one public entry point, ``analyze_coverage``, and is pure: it
takes parsed rules + an ATT&CK index + a priority ID set and returns a
``CoverageReport``. No file IO, no network, no caching concerns.
"""

from __future__ import annotations

import logging
from collections import defaultdict
from datetime import UTC, datetime

from .._tactics import TACTIC_DISPLAY_ORDER, lookup_tactic
from ..stale.models import AttackIndex, DetectionRule
from .models import (
    CoverageReport,
    CoverageState,
    CoverageSummary,
    MigrationItem,
    TacticRollup,
    TechniqueCoverage,
)

log = logging.getLogger(__name__)


def analyze_coverage(
    rules: list[DetectionRule],
    index: AttackIndex,
    priority_ids: set[str],
) -> CoverageReport:
    """Compute coverage state for every non-deprecated/non-revoked technique."""

    # ---- Pass 1: build the rule-tag inverted index ----
    # technique_id → list[(rule, exact_match: bool)]
    tag_to_rules: dict[str, list[tuple[DetectionRule, bool]]] = defaultdict(list)
    migrations: list[MigrationItem] = []
    # Count distinct rules with >=1 unknown tag, not raw tag occurrences, so the
    # field can't exceed rules_parsed.
    rules_with_unknown: set[str] = set()

    for rule in rules:
        for tid in rule.technique_ids:
            tech = index.techniques.get(tid)

            if tech is None:
                rules_with_unknown.add(str(rule.source_file))
                continue

            if tech.deprecated or tech.revoked:
                migrations.append(MigrationItem(
                    rule_source=rule.source_file,
                    rule_title=rule.title,
                    deprecated_technique_id=tid,
                    reason="revoked" if tech.revoked else "deprecated",
                    replacement_id=tech.replacement_id,
                ))
                continue

            # Exact-match against the technique that's tagged.
            tag_to_rules[tid].append((rule, True))

            if not tech.is_subtechnique:
                # Propagate parent → sub-techniques as shallow coverage.
                for sub_tid in index.subtechniques_of(tid):
                    tag_to_rules[sub_tid].append((rule, False))  # shallow
            elif tech.parent_id:
                # Roll a covered sub-technique up to its parent as shallow
                # coverage so a covered parent isn't reported as a false gap.
                tag_to_rules[tech.parent_id].append((rule, False))  # shallow

    # ---- Pass 2: walk the in-scope universe, assign state ----
    techniques: list[TechniqueCoverage] = []
    for tid, tech in index.techniques.items():
        if tech.deprecated or tech.revoked:
            continue

        matches = tag_to_rules.get(tid, [])
        exact_rules = [r for r, is_exact in matches if is_exact]
        shallow_rules = [r for r, is_exact in matches if not is_exact]

        if exact_rules:
            state: CoverageState = "full"
            contributing = exact_rules
        elif shallow_rules:
            state = "shallow"
            contributing = shallow_rules
        else:
            state = "gap"
            contributing = []

        # rule_count and rule_sources reflect ONLY the rules that determined
        # the state — exact matches when full, shallow matches when shallow,
        # empty when gap.
        techniques.append(TechniqueCoverage(
            technique_id=tid,
            technique_name=tech.name,
            is_subtechnique=tech.is_subtechnique,
            parent_id=tech.parent_id,
            tactic_ids=tech.tactic_ids,
            state=state,
            rule_count=len(contributing),
            rule_sources=[r.source_file for r in contributing],
            is_priority=(tid in priority_ids),
        ))

    summary = _build_summary(
        techniques=techniques,
        migrations=migrations,
        unknown_count=len(rules_with_unknown),
        rules_parsed=len(rules),
        index=index,
    )
    tactic_rollups = _build_tactic_rollups(techniques)
    ordered = _sort_for_display(techniques, tactic_rollups)

    return CoverageReport(
        summary=summary,
        techniques=ordered,
        tactic_rollups=tactic_rollups,
        migrations=migrations,
    )


def _build_summary(
    *,
    techniques: list[TechniqueCoverage],
    migrations: list[MigrationItem],
    unknown_count: int,
    rules_parsed: int,
    index: AttackIndex,
) -> CoverageSummary:
    """Aggregate per-technique results into the report-level summary."""
    full = sum(1 for t in techniques if t.state == "full")
    shallow = sum(1 for t in techniques if t.state == "shallow")
    gap = sum(1 for t in techniques if t.state == "gap")
    priority_techs = [t for t in techniques if t.is_priority]
    return CoverageSummary(
        total_techniques=len(techniques),
        full=full,
        shallow=shallow,
        gap=gap,
        priority_total=len(priority_techs),
        priority_full=sum(1 for t in priority_techs if t.state == "full"),
        priority_shallow=sum(1 for t in priority_techs if t.state == "shallow"),
        priority_gap=sum(1 for t in priority_techs if t.state == "gap"),
        rules_parsed=rules_parsed,
        rules_with_unknown_tags=unknown_count,
        migrations_needed=len(migrations),
        attack_domain=index.source_domain,
        attack_fetched_at=index.fetched_at,
        generated_at=datetime.now(UTC),
    )


def _build_tactic_rollups(
    techniques: list[TechniqueCoverage],
) -> list[TacticRollup]:
    """Aggregate per-technique state into per-tactic rollups.

    A technique tagged to multiple tactics contributes to each rollup. Display
    order follows ``TACTIC_DISPLAY_ORDER``; tactics not present in the order
    list (unknown shortnames) trail at the end in shortname-sorted order.
    """
    by_shortname: dict[str, list[TechniqueCoverage]] = defaultdict(list)
    for t in techniques:
        for short in t.tactic_ids:
            by_shortname[short].append(t)

    rollups: list[TacticRollup] = []
    seen: set[str] = set()
    for short in TACTIC_DISPLAY_ORDER:
        if short not in by_shortname:
            continue
        seen.add(short)
        ta_id, name = lookup_tactic(short)
        techs = by_shortname[short]
        rollups.append(_make_rollup(ta_id, name, techs))

    for short in sorted(by_shortname.keys() - seen):
        ta_id, name = lookup_tactic(short)
        rollups.append(_make_rollup(ta_id, name, by_shortname[short]))

    return rollups


def _make_rollup(
    tactic_id: str,
    tactic_name: str,
    techs: list[TechniqueCoverage],
) -> TacticRollup:
    return TacticRollup(
        tactic_id=tactic_id,
        tactic_name=tactic_name,
        total_techniques=len(techs),
        full_count=sum(1 for t in techs if t.state == "full"),
        shallow_count=sum(1 for t in techs if t.state == "shallow"),
        gap_count=sum(1 for t in techs if t.state == "gap"),
        priority_gap_count=sum(
            1 for t in techs if t.is_priority and t.state == "gap"
        ),
    )


_STATE_DISPLAY_RANK: dict[CoverageState, int] = {
    "gap": 0,
    "shallow": 1,
    "full": 2,
}


def _sort_for_display(
    techniques: list[TechniqueCoverage],
    tactic_rollups: list[TacticRollup],
) -> list[TechniqueCoverage]:
    """Order techniques for display.

    Sort key: priority gaps first, then by tactic display order, then by
    state (gap → shallow → full), then by technique_id.
    """
    tactic_rank: dict[str, int] = {
        short: idx for idx, short in enumerate(TACTIC_DISPLAY_ORDER)
    }
    def key(t: TechniqueCoverage) -> tuple[int, int, int, str]:
        priority_gap = 0 if (t.is_priority and t.state == "gap") else 1
        primary_tactic = t.tactic_ids[0] if t.tactic_ids else ""
        tactic_idx = tactic_rank.get(primary_tactic, 999)
        return (priority_gap, tactic_idx, _STATE_DISPLAY_RANK[t.state], t.technique_id)
    return sorted(techniques, key=key)
