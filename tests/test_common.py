from __future__ import annotations

from pathlib import Path

import click
from click.testing import CliRunner

from detect_forge.common import common_output_options


def test_common_output_options_adds_three_flags() -> None:
    @click.command()
    @common_output_options
    def cmd(output_format: str, output: str | None, min_severity: str) -> None:
        click.echo(f"{output_format}|{output}|{min_severity}")

    runner = CliRunner()
    result = runner.invoke(cmd, ["--help"])
    assert result.exit_code == 0
    assert "--format" in result.output
    assert "--output" in result.output
    assert "-o" in result.output
    assert "--min-severity" in result.output


def test_common_output_options_accepts_info_min_severity() -> None:
    # info findings (no_attack_tags / unknown_technique) must be selectable,
    # otherwise they can never be displayed.
    @click.command()
    @common_output_options
    def cmd(output_format: str, output: str | None, min_severity: str) -> None:
        click.echo(min_severity)

    runner = CliRunner()
    ok = runner.invoke(cmd, ["--min-severity", "info"])
    assert ok.exit_code == 0
    assert ok.output.strip() == "info"

    bad = runner.invoke(cmd, ["--min-severity", "bogus"])
    assert bad.exit_code != 0


def test_common_output_options_defaults() -> None:
    @click.command()
    @common_output_options
    def cmd(output_format: str, output: str | None, min_severity: str) -> None:
        click.echo(f"{output_format}|{output}|{min_severity}")

    runner = CliRunner()
    result = runner.invoke(cmd, [])
    assert result.exit_code == 0
    assert result.output.strip() == "terminal|None|low"


def test_common_output_options_accepts_values(tmp_path: Path) -> None:
    target = tmp_path / "out.json"

    @click.command()
    @common_output_options
    def cmd(output_format: str, output: Path | None, min_severity: str) -> None:
        click.echo(f"{output_format}|{output}|{min_severity}")

    runner = CliRunner()
    result = runner.invoke(
        cmd,
        ["--format", "json", "-o", str(target), "--min-severity", "high"],
    )
    assert result.exit_code == 0
    assert f"json|{target}|high" in result.output
