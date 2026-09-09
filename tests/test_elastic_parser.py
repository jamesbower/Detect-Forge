from __future__ import annotations

from pathlib import Path

import pytest

from detect_forge.stale.elastic_parser import _extract_elastic_technique_ids, parse_rule_file

FIXTURES = Path(__file__).parent / "fixtures" / "elastic"


def test_parse_minimal_eql() -> None:
    rule = parse_rule_file(FIXTURES / "minimal_eql.toml")
    assert rule is not None
    assert rule.rule_id == "00000000-0000-0000-0000-000000000001"
    assert rule.title == "Minimal EQL Test Rule"
    assert rule.status == "production"
    assert rule.technique_ids == ["T1059"]
    assert rule.raw_tags == []
    assert rule.rule_date is not None
    assert rule.rule_date.year == 2024
    assert rule.rule_date.month == 3
    assert rule.modified_date is not None
    assert rule.modified_date.year == 2024
    assert rule.modified_date.month == 11


def test_parse_minimal_kql() -> None:
    rule = parse_rule_file(FIXTURES / "minimal_kql.toml")
    assert rule is not None
    assert rule.title == "Minimal KQL Test Rule"
    assert rule.technique_ids == ["T1086"]


def test_parse_with_subtechnique() -> None:
    rule = parse_rule_file(FIXTURES / "with_subtechnique.toml")
    assert rule is not None
    # Top-level technique first, then both subtechniques in source order.
    assert rule.technique_ids == ["T1003", "T1003.001", "T1003.002"]


def test_parse_no_techniques() -> None:
    rule = parse_rule_file(FIXTURES / "no_techniques.toml")
    assert rule is not None
    assert rule.technique_ids == []
    assert rule.title == "Rule Without ATT&CK Mapping"
    assert rule.status == "development"


def test_parse_malformed_returns_none(caplog: pytest.LogCaptureFixture) -> None:
    rule = parse_rule_file(FIXTURES / "malformed.toml")
    assert rule is None
    # The parser logs at WARNING with the path; don't pin the exact message.
    assert any("malformed.toml" in r.getMessage() for r in caplog.records)


def test_parse_missing_file_returns_none() -> None:
    rule = parse_rule_file(FIXTURES / "does_not_exist.toml")
    assert rule is None


def test_fallback_title_to_path_stem(tmp_path: Path) -> None:
    """When `rule.name` is missing, title falls back to path.stem."""
    p = tmp_path / "myrule.toml"
    p.write_text(
        '[metadata]\n'
        'creation_date = "2024/01/01"\n'
        '[rule]\n'
        'rule_id = "abc"\n'
    )
    rule = parse_rule_file(p)
    assert rule is not None
    assert rule.title == "myrule"


def test_non_dict_top_level_returns_none(tmp_path: Path) -> None:
    """TOML always produces a dict at top level, but pathological inputs
    can still trip the dict check. Empty file is a real corner case."""
    p = tmp_path / "empty.toml"
    p.write_text("")
    rule = parse_rule_file(p)
    # Empty TOML is a valid (empty) dict, so this should parse — title falls
    # back to path.stem and technique_ids stays empty.
    assert rule is not None
    assert rule.title == "empty"
    assert rule.technique_ids == []


def test_missing_metadata_block(tmp_path: Path) -> None:
    """[metadata] absent — parser should still produce a rule with None dates."""
    p = tmp_path / "no_metadata.toml"
    p.write_text(
        '[rule]\n'
        'name = "Has Rule But No Metadata"\n'
        'rule_id = "deadbeef"\n'
    )
    rule = parse_rule_file(p)
    assert rule is not None
    assert rule.title == "Has Rule But No Metadata"
    assert rule.rule_date is None
    assert rule.modified_date is None
    assert rule.status is None


def test_extract_handles_non_dict_threat_entries() -> None:
    """`rule.threat` items must be dicts; anything else is silently ignored."""
    assert _extract_elastic_technique_ids([{"technique": [{"id": "T1059"}]}]) == ["T1059"]
    assert _extract_elastic_technique_ids(["not a dict"]) == []  # type: ignore[list-item]
    assert _extract_elastic_technique_ids([]) == []


def test_extract_normalises_technique_ids_to_uppercase() -> None:
    ids = _extract_elastic_technique_ids([{"technique": [{"id": "t1059"}]}])
    assert ids == ["T1059"]


def test_extract_skips_non_T_ids() -> None:
    """Defensive: if some field accidentally holds a non-T identifier, skip it."""
    threats = [{"technique": [{"id": "G0016"}, {"id": "T1003"}]}]
    assert _extract_elastic_technique_ids(threats) == ["T1003"]


def test_extract_preserves_source_order() -> None:
    threats = [
        {"technique": [{"id": "T1003"}]},
        {"technique": [{"id": "T1059", "subtechnique": [{"id": "T1059.001"}]}]},
    ]
    assert _extract_elastic_technique_ids(threats) == ["T1003", "T1059", "T1059.001"]


def test_parse_extracts_description(tmp_path: Path) -> None:
    """Elastic rule descriptions live at rule.description; parser must extract."""
    p = tmp_path / "with_desc.toml"
    p.write_text(
        '[metadata]\n'
        'creation_date = "2024/01/01"\n'
        '[rule]\n'
        'name = "Has Description"\n'
        'rule_id = "abc123"\n'
        'description = "Detects suspicious inter-process communication via COM."\n'
        '[[rule.threat]]\n'
        '[[rule.threat.technique]]\n'
        'id = "T1559"\n'
    )
    rule = parse_rule_file(p)
    assert rule is not None
    assert rule.description == "Detects suspicious inter-process communication via COM."


def test_parse_no_description_yields_none(tmp_path: Path) -> None:
    p = tmp_path / "no_desc.toml"
    p.write_text(
        '[metadata]\n'
        '[rule]\n'
        'name = "No Description Here"\n'
        'rule_id = "def456"\n'
    )
    rule = parse_rule_file(p)
    assert rule is not None
    assert rule.description is None


def test_scalar_threat_does_not_crash(tmp_path: Path) -> None:
    """A scalar `threat` value must not abort the scan (T3)."""
    f = tmp_path / "bad.toml"
    f.write_text('[rule]\nname = "Bad threat"\nthreat = 5\nquery = \'x\'\n')
    rule = parse_rule_file(f)
    assert rule is not None
    assert rule.technique_ids == []


def test_elastic_rejects_non_technique_ids() -> None:
    """Only strict T#### / T####.### IDs are accepted (parity with Sigma) — T6."""
    assert _extract_elastic_technique_ids([{"technique": [{"id": "TA0001"}]}]) == []
    assert _extract_elastic_technique_ids([{"technique": [{"id": "TACOS"}]}]) == []
    assert _extract_elastic_technique_ids([{"technique": [{"id": "T1059"}]}]) == ["T1059"]
    assert _extract_elastic_technique_ids(
        [{"technique": [{"id": "T1059", "subtechnique": [{"id": "T1059.001"}]}]}]
    ) == ["T1059", "T1059.001"]
