from __future__ import annotations

from pathlib import Path

import click
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..config import find_config_file, load_coverage_config_or_defaults
from ..console import err_console
from ..exit_codes import GATED
from ..settings import Settings


@click.command(name="coverage")
@click.argument(
    "rule_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json", "html", "navigator"]),
    default="terminal",
    show_default=True,
    help="Output format",
)
@click.option(
    "--output",
    "-o",
    type=click.Path(path_type=Path),
    default=None,
    help="Write output to file instead of stdout",
)
@click.option(
    "--no-cache",
    is_flag=True,
    default=False,
    help="Bypass disk cache and fetch fresh ATT&CK bundle",
)
@click.option(
    "--domain",
    type=click.Choice(["enterprise-attack", "ics-attack", "mobile-attack"]),
    default=Settings().attack_domain,
    show_default=True,
    help="ATT&CK domain to fetch",
)
@click.option(
    "--no-gate",
    is_flag=True,
    default=False,
    help="Don't exit 2 on priority gaps (informational only)",
)
@click.option(
    "--priority-list",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    default=None,
    help="Path to custom priority list JSON (overrides .detect-forge.toml)",
)
@click.pass_context
def coverage_cmd(
    ctx: click.Context,
    rule_dir: Path,
    output_format: str,
    output: Path | None,
    no_cache: bool,
    domain: str,
    no_gate: bool,
    priority_list: Path | None,
) -> None:
    """Score detection rules against the ATT&CK matrix for coverage gaps."""
    from . import reporter, scan_coverage

    settings = Settings()
    cov_cfg = load_coverage_config_or_defaults()
    effective_no_cache = no_cache or settings.no_cache

    # Priority list precedence is applied in resolve_priority_techniques:
    # --priority-list (CLI, relative to CWD) > [coverage].priority_list (config,
    # relative to the config-file dir) > built-in. Keep the two sources
    # separate so a relative config path resolves against the config location.
    config_priority: Path | None = (
        Path(cov_cfg.priority_list) if cov_cfg.priority_list else None
    )
    config_file = find_config_file()
    config_dir: Path | None = config_file.parent if config_file is not None else None

    # Gating precedence: CLI --no-gate > [coverage].gate_on_priority_gaps > default True.
    effective_gate = cov_cfg.gate_on_priority_gaps
    if no_gate:
        effective_gate = False

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        t = progress.add_task("Scoring rules for ATT&CK coverage...", total=None)
        report = scan_coverage(
            rule_dir,
            domain=domain,
            cache_dir=settings.cache_dir,
            cache_ttl_hours=settings.cache_ttl_hours,
            no_cache=effective_no_cache,
            priority_list=priority_list,
            config_priority_list=config_priority,
            config_dir=config_dir,
        )
        progress.remove_task(t)

    rendered = reporter.render(report, output_format=output_format)

    if output:
        output.write_text(rendered, encoding="utf-8")
        err_console.print(f"[info]Report written to {output}[/info]")
    else:
        click.echo(rendered, nl=False, color=output_format == "terminal")

    if effective_gate and report.summary.priority_gap > 0:
        err_console.print(
            f"[critical]{report.summary.priority_gap} priority technique(s) "
            f"have no detection coverage. CI gate failed.[/critical]"
        )
        ctx.exit(GATED)


def register(group: click.Group) -> None:
    """Attach the `coverage` command to a parent click group."""
    group.add_command(coverage_cmd)
