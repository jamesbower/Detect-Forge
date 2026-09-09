from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from click.testing import CliRunner
from pytest_mock import MockerFixture

from detect_forge.cli import main


@pytest.fixture
def empty_rule_dir(tmp_path: Path) -> Path:
    d = tmp_path / "rules"
    d.mkdir()
    return d


def _fake_audit_report(  # type: ignore[no-untyped-def]
    *, audit_would_gate: bool = False, subcommands_errored: int = 0,
    subcommands_ran: int = 3, subcommands_skipped: int = 0,
):
    from detect_forge.audit.models import AuditReport, AuditSubResult, AuditSummary

    summary = AuditSummary(
        rules_scanned=0,
        stale_health=100, coverage_completeness=100, backtest_verification_rate=100,
        subcommands_ran=subcommands_ran,
        subcommands_skipped=subcommands_skipped,
        subcommands_errored=subcommands_errored,
        audit_would_gate=audit_would_gate,
        attack_domain="enterprise-attack",
        generated_at=datetime.now(UTC),
        elapsed_seconds=0.1,
    )
    sub_results = [
        AuditSubResult(subcommand="stale", status="ran",
                       would_gate=audit_would_gate, score=100),
        AuditSubResult(subcommand="coverage", status="ran",
                       would_gate=audit_would_gate, score=100),
        AuditSubResult(subcommand="backtest", status="ran",
                       would_gate=audit_would_gate, score=100),
    ]
    return AuditReport(summary=summary, sub_results=sub_results)


def test_cli_exits_zero_when_gate_not_fired(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch("detect_forge.audit.scan_audit",
                 return_value=_fake_audit_report(audit_would_gate=False))
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(empty_rule_dir)])
    assert result.exit_code == 0, result.stderr


def test_cli_exits_two_when_audit_gate_fires(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch("detect_forge.audit.scan_audit",
                 return_value=_fake_audit_report(audit_would_gate=True))
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(empty_rule_dir)])
    assert result.exit_code == 2, result.stderr


def test_cli_exits_one_when_any_subcommand_errored_and_no_gate(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An errored subcommand → exit 1 (unless audit gate also fired = 2 wins)."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.audit.scan_audit",
        return_value=_fake_audit_report(
            audit_would_gate=False, subcommands_errored=1,
            subcommands_ran=2, subcommands_skipped=0,
        ),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(empty_rule_dir)])
    assert result.exit_code == 1


def test_cli_exit_two_takes_precedence_over_exit_one(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If gate fires AND a subcommand errored, exit 2 (gate fire wins per spec §11)."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch(
        "detect_forge.audit.scan_audit",
        return_value=_fake_audit_report(
            audit_would_gate=True, subcommands_errored=1,
            subcommands_ran=2, subcommands_skipped=0,
        ),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(empty_rule_dir)])
    assert result.exit_code == 2


def test_cli_no_gate_suppresses_exit_two(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch("detect_forge.audit.scan_audit",
                 return_value=_fake_audit_report(audit_would_gate=True))
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(empty_rule_dir), "--no-gate"])
    assert result.exit_code == 0


def test_cli_format_navigator_rejected(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--format navigator must be a click.Choice — invalid input rejected."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch("detect_forge.audit.scan_audit",
                 return_value=_fake_audit_report())
    runner = CliRunner()
    result = runner.invoke(
        main, ["audit", str(empty_rule_dir), "--format", "navigator"],
    )
    # click.Choice rejects this → exit 2 from click (usage error)
    assert result.exit_code != 0
    assert "navigator" in result.stderr.lower() or "navigator" in result.output.lower()


def test_cli_passes_skip_set_to_scan_audit(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--skip stale --skip coverage means enabled={'backtest'}."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    scan_mock = mocker.patch(
        "detect_forge.audit.scan_audit", return_value=_fake_audit_report(),
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["audit", str(empty_rule_dir), "--skip", "stale", "--skip", "coverage"],
    )
    assert result.exit_code == 0, result.stderr
    enabled = scan_mock.call_args.kwargs["enabled"]
    assert enabled == {"backtest"}


def test_cli_with_llm_proposals_passes_llm_model(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--with-llm-proposals → llm_model is set (not None)."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    scan_mock = mocker.patch(
        "detect_forge.audit.scan_audit", return_value=_fake_audit_report(),
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["audit", str(empty_rule_dir), "--with-llm-proposals"],
    )
    assert result.exit_code == 0
    assert scan_mock.call_args.kwargs["llm_model"] is not None


def test_cli_default_does_not_set_llm_model(
    empty_rule_dir: Path, mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Without --with-llm-proposals, llm_model is None (LLM disabled)."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    scan_mock = mocker.patch(
        "detect_forge.audit.scan_audit", return_value=_fake_audit_report(),
    )
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(empty_rule_dir)])
    assert result.exit_code == 0
    assert scan_mock.call_args.kwargs["llm_model"] is None


def test_cli_writes_output_file(
    empty_rule_dir: Path, mocker: MockerFixture, tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    mocker.patch("detect_forge.audit.scan_audit",
                 return_value=_fake_audit_report())
    out_file = tmp_path / "audit.json"
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["audit", str(empty_rule_dir), "--format", "json", "--output", str(out_file)],
    )
    assert result.exit_code == 0
    assert out_file.exists()
    text = out_file.read_text()
    assert "summary" in text


def test_cli_composes_per_subcommand_config(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """audit loads [stale]/[coverage]/[backtest] config and forwards it (C5)."""
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    monkeypatch.delenv("DETECT_FORGE_SEMANTIC_THRESHOLD", raising=False)
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / ".detect-forge.toml").write_text(
        '[stale]\nsemantic_threshold = 0.8\n'
        '[coverage]\ngate_on_priority_gaps = false\npriority_list = "p.json"\n'
        '[backtest]\ngate_on_priority_silence = false\nplatform = "windows"\n'
    )
    rules = proj / "rules"
    rules.mkdir()
    monkeypatch.chdir(proj)
    scan_mock = mocker.patch(
        "detect_forge.audit.scan_audit", return_value=_fake_audit_report()
    )
    runner = CliRunner()
    result = runner.invoke(main, ["audit", str(rules)])
    assert result.exit_code == 0, result.stderr
    kw = scan_mock.call_args.kwargs
    assert kw["semantic_threshold"] == 0.8
    assert kw["coverage_gate_on_priority_gaps"] is False
    assert kw["backtest_gate_on_priority_silence"] is False
    assert kw["platform"] == "windows"
    assert kw["priority_list"] == proj / "p.json"


def test_cli_mordor_source_forwarded(
    mocker: MockerFixture, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("XDG_CACHE_HOME", raising=False)
    rules = tmp_path / "rules"
    rules.mkdir()
    checkout = tmp_path / "sec-datasets"
    checkout.mkdir()
    scan_mock = mocker.patch(
        "detect_forge.audit.scan_audit", return_value=_fake_audit_report()
    )
    runner = CliRunner()
    result = runner.invoke(
        main, ["audit", str(rules), "--mordor-source", str(checkout)]
    )
    assert result.exit_code == 0, result.stderr
    assert scan_mock.call_args.kwargs["mordor_source"] == checkout
