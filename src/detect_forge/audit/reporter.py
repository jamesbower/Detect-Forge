"""Format dispatcher for audit reports.

One function per format. Terminal uses Rich. JSON is trivial pydantic
serialization (Task 7). HTML composes each subcommand's full HTML render
and splices the body content into the audit template (Task 8).

Navigator is explicitly UNSUPPORTED — per spec §3 and §9, audit defers
that merge-or-split decision to v0.2. Callers get a clear error.
"""

from __future__ import annotations

import re
from io import StringIO

from jinja2 import Environment, PackageLoader
from rich import box
from rich.console import Console
from rich.panel import Panel

from ..console import theme
from .models import AuditReport, AuditSubResult


def render(report: AuditReport, output_format: str = "terminal") -> str:
    if output_format == "terminal":
        return _render_terminal(report)
    if output_format == "json":
        return report.model_dump_json(indent=2)
    if output_format == "html":
        return _render_html(report)
    if output_format == "navigator":
        raise ValueError(
            "audit does not support --format navigator in v0.1. "
            "Run `detect-forge coverage --format navigator` and/or "
            "`detect-forge backtest --format navigator` separately."
        )
    raise ValueError(
        f"unknown output_format: {output_format!r}. "
        "Valid values: terminal, json, html."
    )


def _fmt_score(score: int | None) -> str:
    """Format a per-dimension score: '87%' or '—' for null."""
    return f"{score}%" if score is not None else "—"


def _render_terminal(report: AuditReport) -> str:
    buf = StringIO()
    console = Console(
        file=buf, force_terminal=True, highlight=False, width=130, theme=theme,
    )
    s = report.summary

    # ---- Header panel ----
    enabled_count = s.subcommands_ran + s.subcommands_errored
    summary_lines = [
        f"Rules scanned: {s.rules_scanned}   Elapsed: {s.elapsed_seconds:.1f}s",
        "",
        f"Stale health:               {_fmt_score(s.stale_health)}",
        f"Coverage completeness:      {_fmt_score(s.coverage_completeness)}",
        f"Backtest verification rate: {_fmt_score(s.backtest_verification_rate)}",
        "",
    ]
    for sr in report.sub_results:
        if sr.status == "ran":
            cue = "  [critical](would gate)[/critical]" if sr.would_gate else ""
            summary_lines.append(f"  [low]✓[/low] {sr.subcommand:8s}  ran{cue}")
        elif sr.status == "skipped":
            summary_lines.append(f"  [info]·[/info] {sr.subcommand:8s}  skipped")
        else:  # errored
            err_preview = (sr.error or "unknown error")[:60]
            summary_lines.append(
                f"  [critical]✗[/critical] {sr.subcommand:8s}  errored: {err_preview}"
            )
    summary_lines.append("")

    if s.audit_would_gate:
        gate_msg = (
            f"[critical]AUDIT GATE FIRED[/critical] "
            f"(all {enabled_count} enabled subcommand(s) would gate)"
        )
    else:
        gate_msg = (
            "[info]AUDIT GATE NOT FIRED[/info] "
            f"({sum(1 for sr in report.sub_results if sr.would_gate)} "
            f"of {enabled_count} would gate; strategy=all)"
        )
    summary_lines.append(gate_msg)

    console.print(Panel(
        "\n".join(summary_lines),
        title="Detect-Forge Audit",
        expand=False,
        box=box.ROUNDED,
    ))

    # ---- Per-subcommand sections ----
    for sr in report.sub_results:
        console.print()
        console.print("─" * 100)
        console.print(f"  {sr.subcommand.upper()}")
        console.print("─" * 100)
        if sr.status == "errored":
            console.print(f"[critical]Errored:[/critical] {sr.error}")
            continue
        if sr.status == "skipped":
            console.print("[info]Skipped[/info] (not in enabled subcommands list)")
            continue
        section_render = _render_subcommand_section(sr)
        console.print(section_render, end="")

    return buf.getvalue()


def _render_subcommand_section(sr: AuditSubResult) -> str:
    """Delegate to the matching subcommand's render('terminal') and inline the result.

    Returns an empty string if the matching ``*_report`` field is None — happens
    when status == 'ran' but the report was somehow not attached, or in test
    fixtures that omit it. Callers should rely on the section header being
    rendered separately by ``_render_terminal``; this helper only emits the
    body content.
    """
    if sr.subcommand == "stale" and sr.stale_report is not None:
        from ..stale.reporter import render as stale_render
        return stale_render(sr.stale_report, output_format="terminal")
    if sr.subcommand == "coverage" and sr.coverage_report is not None:
        from ..coverage.reporter import render as coverage_render
        return coverage_render(sr.coverage_report, output_format="terminal")
    if sr.subcommand == "backtest" and sr.backtest_report is not None:
        from ..backtest.reporter import render as backtest_render
        return backtest_render(sr.backtest_report, output_format="terminal")
    return ""


def _extract_body_content(full_html: str) -> str:
    """Extract the inner <body>...</body> content for embedding.

    Handles a ``<body>`` opening tag with attributes (e.g. ``<body class="x">``)
    and falls back to returning the full document if the markers are missing —
    keeps the audit render robust against template drift in the subcommand
    reporters.
    """
    open_match = re.search(r"<body[^>]*>", full_html, re.IGNORECASE)
    end = full_html.lower().find("</body>")
    if open_match is None or end == -1:
        return full_html
    return full_html[open_match.end():end].strip()


def _render_html(report: AuditReport) -> str:
    env = Environment(
        loader=PackageLoader("detect_forge.audit", "templates"),
        autoescape=True,
    )
    template = env.get_template("report.html.j2")

    # Render each ran subcommand's HTML to a body fragment.
    sub_bodies: dict[str, str] = {}
    for sr in report.sub_results:
        if sr.status != "ran":
            continue
        if sr.subcommand == "stale" and sr.stale_report is not None:
            from ..stale.reporter import render as stale_render
            sub_bodies["stale"] = _extract_body_content(
                stale_render(sr.stale_report, output_format="html")
            )
        elif sr.subcommand == "coverage" and sr.coverage_report is not None:
            from ..coverage.reporter import render as coverage_render
            sub_bodies["coverage"] = _extract_body_content(
                coverage_render(sr.coverage_report, output_format="html")
            )
        elif sr.subcommand == "backtest" and sr.backtest_report is not None:
            from ..backtest.reporter import render as backtest_render
            sub_bodies["backtest"] = _extract_body_content(
                backtest_render(sr.backtest_report, output_format="html")
            )

    return template.render(
        summary=report.summary,
        sub_results=report.sub_results,
        sub_bodies=sub_bodies,
    )
