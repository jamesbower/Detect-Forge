from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from click.testing import CliRunner
from pytest_mock import MockerFixture

from detect_forge.cli import main

if TYPE_CHECKING:
    from detect_forge.coverage.models import CoverageReport


@pytest.fixture
def empty_rule_dir(tmp_path: Path) -> Path:
    d = tmp_path / "rules"
    d.mkdir()
    return d


def _fake_report(*, priority_gap: int = 0) -> CoverageReport:
    from detect_forge.coverage.models import CoverageReport, CoverageSummary

    now = datetime.now(UTC)
    summary = CoverageSummary(
        total_techniques=0,
        full=0,
        shallow=0,
        gap=0,
        priority_total=0,
        priority_full=0,
        priority_shallow=0,
        priority_gap=priority_gap,
        rules_parsed=0,
        rules_with_unknown_tags=0,
        migrations_needed=0,
        attack_domain="enterprise-attack",
        attack_fetched_at=now,
        generated_at=now,
    )
    return CoverageReport(summary=summary)


def test_cli_exits_zero_when_no_priority_gaps(
    empty_rule_dir: Path,
    mocker: MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.coverage.scan_coverage",
        return_value=_fake_report(priority_gap=0),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["coverage", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr


def test_cli_exits_two_when_priority_gaps_present(
    empty_rule_dir: Path,
    mocker: MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.coverage.scan_coverage",
        return_value=_fake_report(priority_gap=5),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["coverage", str(empty_rule_dir)])
    assert result.exit_code == 2, result.stderr
    assert "5" in result.stderr  # gap count surfaces in the banner


def test_cli_no_gate_flag_suppresses_exit_two(
    empty_rule_dir: Path,
    mocker: MockerFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.coverage.scan_coverage",
        return_value=_fake_report(priority_gap=5),
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["coverage", str(empty_rule_dir), "--no-gate"]
    )
    assert result.exit_code == 0, result.stderr


def test_cli_passes_priority_list_path_to_scan(
    empty_rule_dir: Path,
    mocker: MockerFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    cli_priority = tmp_path / "cli_priority.json"
    cli_priority.write_text('{"technique_ids": ["T1078"]}')
    scan_mock = mocker.patch(
        "detect_forge.coverage.scan_coverage",
        return_value=_fake_report(priority_gap=0),
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["coverage", str(empty_rule_dir), "--priority-list", str(cli_priority)]
    )
    assert result.exit_code == 0, result.stderr
    assert scan_mock.call_args.kwargs.get("priority_list") == cli_priority


def test_cli_writes_to_output_file_when_given(
    empty_rule_dir: Path,
    mocker: MockerFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.coverage.scan_coverage",
        return_value=_fake_report(priority_gap=0),
    )
    out_file = tmp_path / "cov.json"
    runner = CliRunner()
    result = runner.invoke(
        main, [
            "coverage", str(empty_rule_dir),
            "--format", "json",
            "--output", str(out_file),
        ]
    )
    assert result.exit_code == 0, result.stderr
    assert out_file.exists()
    assert "summary" in out_file.read_text()


def test_cli_config_file_gate_off_suppresses_exit_two(
    empty_rule_dir: Path,
    mocker: MockerFixture,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    cfg = tmp_path / ".detect-forge.toml"
    cfg.write_text("[coverage]\ngate_on_priority_gaps = false\n")
    monkeypatch.chdir(tmp_path)
    mocker.patch(
        "detect_forge.coverage.scan_coverage",
        return_value=_fake_report(priority_gap=3),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["coverage", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr


def test_cli_passes_config_priority_relative_to_config_dir(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A relative [coverage] priority_list resolves against the config-file dir (C4)."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    cfgdir = tmp_path / "proj"
    cfgdir.mkdir()
    (cfgdir / ".detect-forge.toml").write_text('[coverage]\npriority_list = "ci/p.json"\n')
    rules = cfgdir / "rules"
    rules.mkdir()
    monkeypatch.chdir(cfgdir)
    spy = mocker.patch(
        "detect_forge.coverage.scan_coverage", return_value=_fake_report()
    )
    runner = CliRunner()
    result = runner.invoke(main, ["coverage", str(rules)])
    assert result.exit_code == 0, result.stderr
    kwargs = spy.call_args.kwargs
    assert kwargs["config_priority_list"] == Path("ci/p.json")
    assert kwargs["config_dir"] == cfgdir


def test_cli_priority_list_directory_rejected(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """--priority-list pointed at a directory is a clean usage error, not a traceback (C7)."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch("detect_forge.coverage.scan_coverage", return_value=_fake_report())
    a_dir = tmp_path / "adir"
    a_dir.mkdir()
    runner = CliRunner()
    result = runner.invoke(
        main, ["coverage", str(empty_rule_dir), "--priority-list", str(a_dir)]
    )
    assert result.exit_code == 2
    assert "directory" in result.output.lower()
