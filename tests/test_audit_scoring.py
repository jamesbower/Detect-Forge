from __future__ import annotations

from datetime import UTC, datetime


def _make_stale_report(*, total_rules: int, critical: int):  # type: ignore[no-untyped-def]
    from detect_forge.stale.models import ReportSummary, StalenessReport

    summary = ReportSummary(
        total_rules=total_rules,
        rules_with_findings=critical,
        critical=critical,
        high=0, medium=0, low=0,
        no_attack_tags=0, unknown_techniques=0,
        deprecated_techniques=0, revoked_techniques=0,
        generated_at=datetime.now(UTC),
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
    )
    return StalenessReport(summary=summary)


def _make_coverage_report(*, total: int, full: int, priority_gap: int):  # type: ignore[no-untyped-def]
    from detect_forge.coverage.models import CoverageReport, CoverageSummary

    summary = CoverageSummary(
        total_techniques=total, full=full, shallow=0, gap=total - full,
        priority_total=1, priority_full=0, priority_shallow=0,
        priority_gap=priority_gap,
        rules_parsed=0, rules_with_unknown_tags=0, migrations_needed=0,
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
        generated_at=datetime.now(UTC),
    )
    return CoverageReport(summary=summary)


def _make_backtest_report(  # type: ignore[no-untyped-def]
    *, parsed: int, unsupported: int, fires: int,
    priority_silent: int = 0, silent_on_all: int = 0,
):
    from detect_forge.backtest.models import BacktestReport, BacktestSummary

    summary = BacktestSummary(
        rules_parsed=parsed, rules_fires=fires, rules_partial=0,
        rules_silent_on_all=silent_on_all, rules_untested=0,
        rules_unsupported=unsupported,
        techniques_in_scope=0, techniques_verified=0,
        techniques_silent=0, techniques_untested=0,
        priority_total=0, priority_verified=0,
        priority_silent=priority_silent, priority_untested=0,
        datasets_consulted=0, mordor_source="fetched",
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
        generated_at=datetime.now(UTC),
    )
    return BacktestReport(summary=summary)


def test_stale_health_score_with_critical_findings() -> None:
    """100 * (total_rules - critical) / total_rules."""
    from detect_forge.audit.scoring import stale_health

    assert stale_health(_make_stale_report(total_rules=20, critical=4)) == 80


def test_stale_health_score_zero_rules_returns_none() -> None:
    """Empty rule corpus → score is undefined; return None rather than divide by zero."""
    from detect_forge.audit.scoring import stale_health

    assert stale_health(_make_stale_report(total_rules=0, critical=0)) is None


def test_coverage_completeness_score() -> None:
    """100 * full / total_techniques."""
    from detect_forge.audit.scoring import coverage_completeness

    r = _make_coverage_report(total=200, full=144, priority_gap=0)
    assert coverage_completeness(r) == 72  # 144/200 = 72%


def test_backtest_verification_rate_excludes_unsupported() -> None:
    """100 * rules_fires / (rules_parsed - rules_unsupported)."""
    from detect_forge.audit.scoring import backtest_verification_rate

    # 31 parsed, 16 unsupported → 15 supported; 8 fire → 53%
    r = _make_backtest_report(parsed=31, unsupported=16, fires=8)
    assert backtest_verification_rate(r) == 53


def test_backtest_verification_rate_all_unsupported_returns_none() -> None:
    """No supported rules → divide-by-zero guard."""
    from detect_forge.audit.scoring import backtest_verification_rate

    r = _make_backtest_report(parsed=5, unsupported=5, fires=0)
    assert backtest_verification_rate(r) is None


def test_stale_would_gate_fires_when_critical_present() -> None:
    """Stale gate predicate: any critical finding → True."""
    from detect_forge.audit.scoring import stale_would_gate

    assert stale_would_gate(_make_stale_report(total_rules=10, critical=1)) is True
    assert stale_would_gate(_make_stale_report(total_rules=10, critical=0)) is False


def test_coverage_would_gate_when_priority_gap_positive() -> None:
    """Coverage gate predicate: priority_gap > 0."""
    from detect_forge.audit.scoring import coverage_would_gate

    assert coverage_would_gate(_make_coverage_report(total=10, full=5, priority_gap=2)) is True
    assert coverage_would_gate(_make_coverage_report(total=10, full=5, priority_gap=0)) is False


def test_coverage_completeness_zero_techniques_returns_none() -> None:
    """No techniques in scope → score is undefined; return None."""
    from detect_forge.audit.scoring import coverage_completeness

    r = _make_coverage_report(total=0, full=0, priority_gap=0)
    assert coverage_completeness(r) is None


def test_backtest_would_gate_on_either_input() -> None:
    """Backtest gate predicate: priority_silent > 0 OR rules_silent_on_all > 0."""
    from detect_forge.audit.scoring import backtest_would_gate

    assert backtest_would_gate(_make_backtest_report(
        parsed=10, unsupported=0, fires=10, priority_silent=1,
    )) is True
    assert backtest_would_gate(_make_backtest_report(
        parsed=10, unsupported=0, fires=10, silent_on_all=1,
    )) is True
    assert backtest_would_gate(_make_backtest_report(
        parsed=10, unsupported=0, fires=10, priority_silent=0, silent_on_all=0,
    )) is False


def test_coverage_would_gate_respects_config_flag() -> None:
    """gate_on_priority_gaps=False disables the coverage gate (C5)."""
    from detect_forge.audit.scoring import coverage_would_gate

    r = _make_coverage_report(total=10, full=5, priority_gap=2)
    assert coverage_would_gate(r) is True
    assert coverage_would_gate(r, gate_on_priority_gaps=False) is False


def test_backtest_would_gate_respects_config_flags() -> None:
    """gate_on_priority_silence / gate_on_broken_rules can each disable a gate (C5)."""
    from detect_forge.audit.scoring import backtest_would_gate

    r = _make_backtest_report(
        parsed=5, unsupported=0, fires=1, priority_silent=1, silent_on_all=1
    )
    assert backtest_would_gate(r) is True
    assert (
        backtest_would_gate(
            r, gate_on_priority_silence=False, gate_on_broken_rules=False
        )
        is False
    )
    # Broken-rules alone still gates when only that flag is on.
    assert backtest_would_gate(r, gate_on_priority_silence=False) is True
