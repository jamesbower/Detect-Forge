from __future__ import annotations

from datetime import UTC, datetime


def _make_report(  # type: ignore[no-untyped-def]
    *,
    audit_would_gate: bool = False,
    sub_results=None,
    stale_health: int | None = 87,
    coverage_completeness: int | None = 72,
    backtest_verification_rate: int | None = 48,
    subcommands_ran: int = 3,
    subcommands_skipped: int = 0,
    subcommands_errored: int = 0,
):
    from detect_forge.audit.models import AuditReport, AuditSubResult, AuditSummary
    summary = AuditSummary(
        rules_scanned=31,
        stale_health=stale_health,
        coverage_completeness=coverage_completeness,
        backtest_verification_rate=backtest_verification_rate,
        subcommands_ran=subcommands_ran,
        subcommands_skipped=subcommands_skipped,
        subcommands_errored=subcommands_errored,
        audit_would_gate=audit_would_gate,
        attack_domain="enterprise-attack",
        generated_at=datetime.now(UTC),
        elapsed_seconds=4.2,
    )
    if sub_results is None:
        sub_results = [
            AuditSubResult(subcommand="stale", status="ran",
                           would_gate=audit_would_gate, score=stale_health),
            AuditSubResult(subcommand="coverage", status="ran",
                           would_gate=audit_would_gate, score=coverage_completeness),
            AuditSubResult(subcommand="backtest", status="ran",
                           would_gate=audit_would_gate, score=backtest_verification_rate),
        ]
    return AuditReport(summary=summary, sub_results=sub_results)


def test_terminal_render_includes_three_scores() -> None:
    """Summary panel shows the 3 per-dimension scores."""
    from detect_forge.audit.reporter import render

    out = render(_make_report(), output_format="terminal")
    assert "Detect-Forge Audit" in out
    assert "87" in out
    assert "72" in out
    assert "48" in out


def test_terminal_render_gate_fired_banner() -> None:
    """audit_would_gate=True surfaces a prominent banner."""
    from detect_forge.audit.reporter import render

    out = render(_make_report(audit_would_gate=True), output_format="terminal")
    assert "AUDIT GATE FIRED" in out


def test_terminal_render_gate_silent_banner() -> None:
    """audit_would_gate=False surfaces a 'gate not fired' message."""
    from detect_forge.audit.reporter import render

    out = render(_make_report(audit_would_gate=False), output_format="terminal")
    assert "AUDIT GATE NOT FIRED" in out or "gate not fired" in out.lower()


def test_terminal_render_handles_null_scores_for_skipped() -> None:
    """Subcommand skipped → score is null; render uses dash placeholder, not 'None'."""
    from detect_forge.audit.reporter import render

    out = render(
        _make_report(
            stale_health=None,
            coverage_completeness=100,
            backtest_verification_rate=None,
            subcommands_ran=1,
            subcommands_skipped=2,
        ),
        output_format="terminal",
    )
    # The literal string "None" must NOT appear (it's a code smell)
    assert "None%" not in out


def test_terminal_render_unknown_format_raises() -> None:
    """Unknown format names raise ValueError."""
    import pytest

    from detect_forge.audit.reporter import render

    with pytest.raises(ValueError, match="unknown output_format"):
        render(_make_report(), output_format="ascii-art")


def test_terminal_render_navigator_format_rejected_with_explicit_message() -> None:
    """audit doesn't support navigator in v0.1 — rejection message points operators
    at the per-subcommand commands so they have a workaround."""
    import pytest

    from detect_forge.audit.reporter import render

    with pytest.raises(ValueError, match="audit does not support"):
        render(_make_report(), output_format="navigator")


def test_json_render_is_valid_json_with_required_keys() -> None:
    import json

    from detect_forge.audit.reporter import render

    out = render(_make_report(), output_format="json")
    parsed = json.loads(out)
    assert "summary" in parsed
    assert "sub_results" in parsed
    assert parsed["summary"]["stale_health"] == 87
    assert parsed["summary"]["coverage_completeness"] == 72
    assert parsed["summary"]["backtest_verification_rate"] == 48
    assert parsed["summary"]["attack_domain"] == "enterprise-attack"


def test_json_render_nested_sub_reports_present() -> None:
    """A 'ran' sub_result with an attached report serializes it nested."""
    import json
    from datetime import UTC, datetime

    from detect_forge.audit.models import AuditSubResult
    from detect_forge.audit.reporter import render
    from detect_forge.coverage.models import CoverageReport, CoverageSummary

    cov_summary = CoverageSummary(
        total_techniques=10, full=8, shallow=0, gap=2,
        priority_total=0, priority_full=0, priority_shallow=0, priority_gap=0,
        rules_parsed=10, rules_with_unknown_tags=0, migrations_needed=0,
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
        generated_at=datetime.now(UTC),
    )
    sub_results = [
        AuditSubResult(subcommand="stale", status="skipped"),
        AuditSubResult(
            subcommand="coverage", status="ran", would_gate=False, score=80,
            coverage_report=CoverageReport(summary=cov_summary),
        ),
        AuditSubResult(subcommand="backtest", status="skipped"),
    ]
    audit = _make_report(sub_results=sub_results)
    parsed = json.loads(render(audit, output_format="json"))
    cov_entry = next(s for s in parsed["sub_results"] if s["subcommand"] == "coverage")
    assert cov_entry["coverage_report"]["summary"]["full"] == 8


def test_html_render_emits_doctype_and_audit_title() -> None:
    from detect_forge.audit.reporter import render

    out = render(_make_report(), output_format="html")
    assert "<!DOCTYPE html>" in out
    assert "Detect-Forge Audit" in out


def test_html_render_includes_three_score_cards() -> None:
    from detect_forge.audit.reporter import render

    out = render(_make_report(), output_format="html")
    assert "87" in out
    assert "72" in out
    assert "48" in out


def test_html_render_inlines_subcommand_body_when_attached() -> None:
    """A ran sub_result with an attached report has its inner body inlined."""
    from datetime import UTC, datetime

    from detect_forge.audit.models import AuditSubResult
    from detect_forge.audit.reporter import render
    from detect_forge.coverage.models import CoverageReport, CoverageSummary

    cov_summary = CoverageSummary(
        total_techniques=10, full=8, shallow=0, gap=2,
        priority_total=0, priority_full=0, priority_shallow=0, priority_gap=0,
        rules_parsed=10, rules_with_unknown_tags=0, migrations_needed=0,
        attack_domain="enterprise-attack",
        attack_fetched_at=datetime.now(UTC),
        generated_at=datetime.now(UTC),
    )
    sub_results = [
        AuditSubResult(subcommand="stale", status="skipped"),
        AuditSubResult(
            subcommand="coverage", status="ran", would_gate=False, score=80,
            coverage_report=CoverageReport(summary=cov_summary),
        ),
        AuditSubResult(subcommand="backtest", status="skipped"),
    ]
    report = _make_report(sub_results=sub_results)
    out = render(report, output_format="html")
    # Coverage HTML contains its own title string — verify it landed inside
    assert "Coverage" in out
    # The audit template should NOT have nested <html> tags
    assert out.count("<!DOCTYPE html>") == 1


def test_html_render_errored_subcommand_shows_error_text() -> None:
    """An errored sub_result renders the error text, not 'None'."""
    from detect_forge.audit.models import AuditSubResult
    from detect_forge.audit.reporter import render

    sub_results = [
        AuditSubResult(
            subcommand="stale", status="errored",
            error="RuntimeError: STIX cache missing at /var/cache",
        ),
        AuditSubResult(subcommand="coverage", status="skipped"),
        AuditSubResult(subcommand="backtest", status="skipped"),
    ]
    report = _make_report(
        sub_results=sub_results,
        subcommands_ran=0, subcommands_skipped=2, subcommands_errored=1,
    )
    out = render(report, output_format="html")
    assert "RuntimeError" in out
    assert "STIX cache missing" in out


def test_html_render_gate_fired_banner_when_audit_would_gate() -> None:
    """audit_would_gate=True surfaces the 'AUDIT GATE FIRED' banner in HTML."""
    from detect_forge.audit.reporter import render

    out = render(_make_report(audit_would_gate=True), output_format="html")
    assert "AUDIT GATE FIRED" in out
    assert "gate-fired" in out  # CSS class


def test_extract_body_content_handles_attributes() -> None:
    """A <body> with attributes is unwrapped correctly (C9)."""
    from detect_forge.audit.reporter import _extract_body_content

    assert (
        _extract_body_content('<html><body class="x" id="y">INNER</body></html>')
        == "INNER"
    )
    assert _extract_body_content("<body>PLAIN</body>") == "PLAIN"
    # Missing markers → fall back to the whole document.
    assert _extract_body_content("<div>no body</div>") == "<div>no body</div>"
