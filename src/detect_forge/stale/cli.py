from __future__ import annotations

import os
from pathlib import Path

import click
from click.core import ParameterSource
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..common import common_output_options
from ..config import load_stale_config_or_defaults
from ..console import err_console
from ..exit_codes import GATED
from ..settings import Settings


@click.command(name="stale")
@click.argument(
    "rule_dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@common_output_options
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
    "--semantic-threshold",
    type=float,
    default=0.65,
    show_default=True,
    help="Cosine similarity threshold for the semantic alignment check; "
         "rule x technique pairs below this value are flagged.",
)
@click.pass_context
def stale_cmd(
    ctx: click.Context,
    rule_dir: Path,
    output_format: str,
    output: Path | None,
    min_severity: str,
    no_cache: bool,
    domain: str,
    semantic_threshold: float,
) -> None:
    """Score detection rules for ATT&CK technique staleness."""
    from . import reporter, scan

    cfg = Settings()
    stale_cfg = load_stale_config_or_defaults()
    effective_no_cache = no_cache or cfg.no_cache

    # Threshold precedence: env > CLI explicit > file > default.
    # The file value (or built-in default) is the starting point.
    effective_threshold = stale_cfg.semantic_threshold
    if ctx.get_parameter_source("semantic_threshold") == ParameterSource.COMMANDLINE:
        effective_threshold = semantic_threshold
    if cfg.semantic_threshold is not None:
        effective_threshold = cfg.semantic_threshold
    if not -1.0 <= effective_threshold <= 1.0:
        raise click.BadParameter(
            f"semantic threshold must be in [-1, 1] (cosine range); got {effective_threshold}",
            param_hint="--semantic-threshold",
        )

    with Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        console=err_console,
        transient=True,
    ) as progress:
        t = progress.add_task("Scoring rules against ATT&CK...", total=None)
        report = scan(
            rule_dir,
            domain=domain,
            cache_dir=cfg.cache_dir,
            cache_ttl_hours=cfg.cache_ttl_hours,
            no_cache=effective_no_cache,
            semantic_threshold=effective_threshold,
            llm_model=stale_cfg.llm_model,
            max_proposals=stale_cfg.max_proposals,
        )
        progress.remove_task(t)

    rendered = reporter.render(
        report,
        output_format=output_format,
        min_severity=min_severity,
    )

    if output:
        output.write_text(rendered, encoding="utf-8")
        err_console.print(f"[info]Report written to {output}[/info]")
    else:
        click.echo(rendered, nl=False, color=output_format == "terminal")

    # Skip-message banner: when OPENAI_API_KEY is unset AND any rule has a
    # semantic_drift finding, hint the user that proposals would have been
    # generated if a key were available.
    has_drift = any(
        f.kind == "semantic_drift"
        for s in report.scores
        for f in s.findings
    )
    if has_drift and not os.environ.get("OPENAI_API_KEY"):
        err_console.print(
            "💡 LLM diff proposals skipped — set OPENAI_API_KEY to enable "
            "automatic fix proposals for semantically drifted rules."
        )

    if report.has_severity("critical"):
        ctx.exit(GATED)


def register(group: click.Group) -> None:
    """Attach the `stale` command to a parent click group."""
    group.add_command(stale_cmd)
