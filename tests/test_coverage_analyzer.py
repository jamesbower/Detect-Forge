from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from detect_forge.stale.models import AttackIndex, AttackTechnique, DetectionRule


# --------------------------------------------------------------------- helpers
def _now() -> datetime:
    return datetime.now(UTC)


def _make_index(*technique_specs) -> AttackIndex:  # type: ignore[no-untyped-def]
    """Build a synthetic AttackIndex from technique spec tuples.

    Each spec is (id, name, is_sub, tactic_ids, deprecated, revoked, replacement_id).
    """

    techs: dict[str, AttackTechnique] = {}
    now = _now()
    for spec in technique_specs:
        (
            tid,
            name,
            is_sub,
            tactic_ids,
            deprecated,
            revoked,
            replacement_id,
        ) = spec
        techs[tid] = AttackTechnique(
            technique_id=tid,
            name=name,
            modified=now,
            is_subtechnique=is_sub,
            deprecated=deprecated,
            revoked=revoked,
            tactic_ids=tactic_ids,
            stix_id=f"attack-pattern--{tid.replace('.', '-')}",
            parent_id=tid.split(".")[0] if is_sub else None,
            replacement_id=replacement_id,
        )
    return AttackIndex(techniques=techs, fetched_at=now)


def _make_rule(
    technique_ids: list[str],
    source_file: str = "/rules/r.yml",
) -> DetectionRule:
    return DetectionRule(
        title="Test Rule",
        technique_ids=technique_ids,
        source_file=Path(source_file),
        raw_tags=[f"attack.{t.lower()}" for t in technique_ids],
    )


# --------------------------------------------------------------------- tests
def test_analyze_empty_corpus_marks_all_techniques_as_gap() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059", "PowerShell Family", False, ["execution"], False, False, None),
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
    )
    report = analyze_coverage([], idx, priority_ids=set())
    assert {t.state for t in report.techniques} == {"gap"}
    assert report.summary.total_techniques == 2
    assert report.summary.gap == 2


def test_analyze_exact_subtechnique_match_marks_full() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059", "PowerShell Family", False, ["execution"], False, False, None),
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
    )
    rule = _make_rule(["T1059.001"])
    report = analyze_coverage([rule], idx, priority_ids=set())
    sub = next(t for t in report.techniques if t.technique_id == "T1059.001")
    assert sub.state == "full"
    assert sub.rule_count == 1
    parent = next(t for t in report.techniques if t.technique_id == "T1059")
    # Parent isn't tagged directly, but a covered sub-technique rolls it up to
    # shallow (covered-via-sub) rather than a false gap (C3).
    assert parent.state == "shallow"


def test_analyze_subtechnique_coverage_rolls_up_to_parent() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059", "PowerShell Family", False, ["execution"], False, False, None),
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
    )
    rule = _make_rule(["T1059.001"])
    report = analyze_coverage([rule], idx, priority_ids={"T1059"})
    parent = next(t for t in report.techniques if t.technique_id == "T1059")
    assert parent.state == "shallow"           # covered via sub, not a gap
    assert parent.rule_count == 1
    assert report.summary.priority_gap == 0     # priority parent no longer false-gaps


def test_analyze_parent_tag_marks_subtechniques_shallow() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059", "PowerShell Family", False, ["execution"], False, False, None),
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
        ("T1059.002", "AppleScript", True, ["execution"], False, False, None),
    )
    rule = _make_rule(["T1059"])
    report = analyze_coverage([rule], idx, priority_ids=set())
    parent = next(t for t in report.techniques if t.technique_id == "T1059")
    assert parent.state == "full"
    sub_001 = next(t for t in report.techniques if t.technique_id == "T1059.001")
    sub_002 = next(t for t in report.techniques if t.technique_id == "T1059.002")
    assert sub_001.state == "shallow"
    assert sub_002.state == "shallow"


def test_analyze_exact_match_wins_over_parent_propagation() -> None:
    """Rule tagged with BOTH T1059 and T1059.001 — the sub gets full, not shallow."""
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059", "PowerShell Family", False, ["execution"], False, False, None),
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
    )
    rule = _make_rule(["T1059", "T1059.001"])
    report = analyze_coverage([rule], idx, priority_ids=set())
    sub = next(t for t in report.techniques if t.technique_id == "T1059.001")
    assert sub.state == "full"
    assert sub.rule_count == 1


def test_analyze_multiple_rules_same_technique_increments_rule_count() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
    )
    rules = [
        _make_rule(["T1059.001"], "/rules/a.yml"),
        _make_rule(["T1059.001"], "/rules/b.yml"),
        _make_rule(["T1059.001"], "/rules/c.yml"),
    ]
    report = analyze_coverage(rules, idx, priority_ids=set())
    sub = next(t for t in report.techniques if t.technique_id == "T1059.001")
    assert sub.state == "full"
    assert sub.rule_count == 3
    assert {str(p) for p in sub.rule_sources} == {"/rules/a.yml", "/rules/b.yml", "/rules/c.yml"}


def test_analyze_unknown_tag_counted_but_no_state_changed() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059", "PowerShell Family", False, ["execution"], False, False, None),
    )
    rule = _make_rule(["T9999"])
    report = analyze_coverage([rule], idx, priority_ids=set())
    assert report.summary.rules_with_unknown_tags == 1
    # The single known technique is still gap.
    assert next(t for t in report.techniques if t.technique_id == "T1059").state == "gap"


def test_analyze_revoked_technique_routes_to_migration() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1086", "PowerShell (revoked)", False, ["execution"], False, True, "T1059.001"),
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
    )
    rule = _make_rule(["T1086"])
    report = analyze_coverage([rule], idx, priority_ids=set())
    assert report.summary.migrations_needed == 1
    assert len(report.migrations) == 1
    item = report.migrations[0]
    assert item.deprecated_technique_id == "T1086"
    assert item.reason == "revoked"
    assert item.replacement_id == "T1059.001"
    # The revoked technique is NOT in the coverage matrix; sub is still gap.
    assert all(t.technique_id != "T1086" for t in report.techniques)
    assert next(t for t in report.techniques if t.technique_id == "T1059.001").state == "gap"


def test_analyze_deprecated_technique_routes_to_migration() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1086", "Older technique", False, ["execution"], True, False, None),
    )
    rule = _make_rule(["T1086"])
    report = analyze_coverage([rule], idx, priority_ids=set())
    assert report.summary.migrations_needed == 1
    assert report.migrations[0].reason == "deprecated"
    assert report.migrations[0].replacement_id is None


def test_analyze_priority_flag_set_on_listed_techniques() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
        ("T1078", "Valid Accounts", False, ["initial-access"], False, False, None),
    )
    report = analyze_coverage([], idx, priority_ids={"T1078"})
    pri = next(t for t in report.techniques if t.technique_id == "T1078")
    other = next(t for t in report.techniques if t.technique_id == "T1059.001")
    assert pri.is_priority is True
    assert other.is_priority is False


def test_analyze_priority_gap_summary_counts_only_priority_gaps() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1078", "Valid Accounts", False, ["initial-access"], False, False, None),
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
    )
    rule = _make_rule(["T1059.001"])
    report = analyze_coverage([rule], idx, priority_ids={"T1078", "T1059.001"})
    assert report.summary.priority_total == 2
    assert report.summary.priority_full == 1  # T1059.001 covered
    assert report.summary.priority_gap == 1  # T1078 uncovered


def test_analyze_tactic_rollup_sums_per_tactic() -> None:
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059", "PowerShell Family", False, ["execution"], False, False, None),
        ("T1059.001", "PowerShell", True, ["execution"], False, False, None),
        ("T1078", "Valid Accounts", False, ["initial-access"], False, False, None),
    )
    rule = _make_rule(["T1059.001"])
    report = analyze_coverage([rule], idx, priority_ids=set())
    by_id = {r.tactic_id: r for r in report.tactic_rollups}
    assert "TA0002" in by_id  # execution maps to TA0002
    exec_rollup = by_id["TA0002"]
    assert exec_rollup.total_techniques == 2
    assert exec_rollup.full_count == 1
    # Parent T1059 rolls up to shallow via its covered sub-technique (C3).
    assert exec_rollup.shallow_count == 1
    assert exec_rollup.gap_count == 0


def test_analyze_excludes_deprecated_techniques_from_universe() -> None:
    """A deprecated technique must NOT appear in the coverage matrix."""
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1086", "Deprecated", False, ["execution"], True, False, None),
        ("T1059", "Alive", False, ["execution"], False, False, None),
    )
    report = analyze_coverage([], idx, priority_ids=set())
    assert {t.technique_id for t in report.techniques} == {"T1059"}
    assert report.summary.total_techniques == 1


def test_analyze_unknown_tags_counts_rules_not_occurrences() -> None:
    """A single rule with multiple unknown tags counts once (C6)."""
    from detect_forge.coverage.analyzer import analyze_coverage

    idx = _make_index(
        ("T1059", "PowerShell Family", False, ["execution"], False, False, None),
    )
    rule = _make_rule(["T9999", "T8888"])  # two unknown IDs, one rule
    report = analyze_coverage([rule], idx, priority_ids=set())
    assert report.summary.rules_with_unknown_tags == 1
