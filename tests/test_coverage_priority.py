from __future__ import annotations

from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "coverage"


def test_load_priority_techniques_from_file() -> None:
    from detect_forge.coverage.priority import load_priority_techniques

    p = FIXTURE_DIR / "custom_priority.json"
    ids = load_priority_techniques(p)
    assert ids == {"T1059.001", "T1078", "T1190"}


def test_load_priority_techniques_rejects_malformed_ids() -> None:
    from detect_forge.coverage.priority import load_priority_techniques

    p = FIXTURE_DIR / "malformed_priority.json"
    with pytest.raises(ValueError):
        load_priority_techniques(p)


def test_load_priority_techniques_missing_file_raises() -> None:
    from detect_forge.coverage.priority import load_priority_techniques

    with pytest.raises(FileNotFoundError):
        load_priority_techniques(Path("/nonexistent/priority.json"))


def test_load_priority_techniques_wrong_key_raises(tmp_path: Path) -> None:
    """A mistyped key (e.g. 'techniques') must not silently disable gating (C1)."""
    from detect_forge.coverage.priority import load_priority_techniques

    p = tmp_path / "wrong_key.json"
    p.write_text('{"name": "oops", "techniques": ["T1078", "T1190"]}')
    with pytest.raises(ValueError, match="technique_ids|no valid"):
        load_priority_techniques(p)


def test_load_priority_techniques_empty_list_raises(tmp_path: Path) -> None:
    from detect_forge.coverage.priority import load_priority_techniques

    p = tmp_path / "empty.json"
    p.write_text('{"technique_ids": []}')
    with pytest.raises(ValueError):
        load_priority_techniques(p)


def test_load_priority_techniques_non_object_raises(tmp_path: Path) -> None:
    """A bare-array priority list is a clean ValueError, not AttributeError (C2)."""
    from detect_forge.coverage.priority import load_priority_techniques

    p = tmp_path / "array.json"
    p.write_text('["T1078", "T1190"]')
    with pytest.raises(ValueError):
        load_priority_techniques(p)


def test_load_builtin_priority_techniques_returns_set() -> None:
    """The built-in CTID list parses and returns a non-empty set of IDs."""
    from detect_forge.coverage.priority import load_builtin_priority_techniques

    ids = load_builtin_priority_techniques()
    assert len(ids) >= 20
    assert "T1059.001" in ids
    # All IDs match T#### or T####.### shape.
    import re
    pattern = re.compile(r"^T\d{4}(\.\d{3})?$")
    for tid in ids:
        assert pattern.match(tid), f"Invalid ID: {tid}"


def test_resolve_priority_techniques_cli_override(tmp_path: Path) -> None:
    """When --priority-list is provided, it wins over file and default."""
    from detect_forge.coverage.priority import resolve_priority_techniques

    cli_file = tmp_path / "cli.json"
    cli_file.write_text(
        '{"name": "cli", "technique_ids": ["T9999"]}'
    )
    ids = resolve_priority_techniques(cli_path=cli_file)
    assert ids == {"T9999"}


def test_resolve_priority_techniques_config_when_no_cli(tmp_path: Path) -> None:
    """When CLI is absent but config has a path, config wins."""
    from detect_forge.coverage.priority import resolve_priority_techniques

    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(
        '{"name": "cfg", "technique_ids": ["T8888"]}'
    )
    ids = resolve_priority_techniques(cli_path=None, config_path=cfg_file)
    assert ids == {"T8888"}


def test_resolve_priority_techniques_builtin_when_no_cli_or_config() -> None:
    """When neither CLI nor config provides a path, the built-in default is used."""
    from detect_forge.coverage.priority import resolve_priority_techniques

    ids = resolve_priority_techniques(cli_path=None)
    # Built-in has at least 20 IDs (see ctid_top_techniques_2024.json).
    assert len(ids) >= 20


def test_resolve_priority_techniques_config_path_resolves_relative_to_cwd_when_start_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A relative config_path resolves from CWD when start_dir is None."""
    from detect_forge.coverage.priority import resolve_priority_techniques

    monkeypatch.chdir(tmp_path)
    cfg_file = tmp_path / "rel.json"
    cfg_file.write_text(
        '{"name": "rel", "technique_ids": ["T7777"]}'
    )
    ids = resolve_priority_techniques(cli_path=None, config_path=Path("rel.json"))
    assert ids == {"T7777"}


def test_resolve_priority_techniques_explicit_none_returns_builtin() -> None:
    """Passing config_path=None explicitly returns the built-in priority list."""
    from detect_forge.coverage.priority import resolve_priority_techniques

    ids = resolve_priority_techniques(cli_path=None, config_path=None)
    assert isinstance(ids, set)
    # Built-in list is non-empty (ships with CTID top-25)
    assert len(ids) > 0
