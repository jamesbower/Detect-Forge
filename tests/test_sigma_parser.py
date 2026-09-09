from __future__ import annotations

from pathlib import Path

from detect_forge.stale.rule_parser import parse_rule_dir
from detect_forge.stale.sigma_parser import (
    _extract_technique_ids,
    parse_rule_file,
)

FIXTURES = Path(__file__).parent / "fixtures" / "sigma"


def test_extracts_subtechnique() -> None:
    assert _extract_technique_ids(["attack.t1059.001"]) == ["T1059.001"]


def test_extracts_parent_technique() -> None:
    assert _extract_technique_ids(["attack.t1059"]) == ["T1059"]


def test_skips_tactic() -> None:
    assert _extract_technique_ids(["attack.execution"]) == []


def test_skips_group_ref() -> None:
    assert _extract_technique_ids(["attack.g0016"]) == []


def test_skips_software_ref() -> None:
    assert _extract_technique_ids(["attack.s0002"]) == []


def test_skips_non_attack_namespace() -> None:
    assert _extract_technique_ids(["cve.2021-44228"]) == []


def test_normalises_to_uppercase() -> None:
    assert _extract_technique_ids(["attack.T1059.001"]) == ["T1059.001"]


def test_multiple_tags_mixed() -> None:
    tags = ["attack.execution", "attack.t1059", "attack.t1059.001", "cve.2020-1234"]
    assert _extract_technique_ids(tags) == ["T1059", "T1059.001"]


def test_parse_rule_with_subtechnique() -> None:
    rule = parse_rule_file(FIXTURES / "rule_with_subtechnique.yml")
    assert rule is not None
    assert rule.title == "PowerShell Encoded Command"
    assert "T1059.001" in rule.technique_ids


def test_parse_rule_no_attack_tags() -> None:
    rule = parse_rule_file(FIXTURES / "rule_no_attack_tags.yml")
    assert rule is not None
    assert rule.technique_ids == []
    assert "cve.2021-44228" in rule.raw_tags


def test_parse_rule_no_tags_field() -> None:
    rule = parse_rule_file(FIXTURES / "rule_no_tags.yml")
    assert rule is not None
    assert rule.technique_ids == []
    assert rule.raw_tags == []


def test_parse_rule_multiple_techniques() -> None:
    rule = parse_rule_file(FIXTURES / "rule_multiple_techniques.yml")
    assert rule is not None
    assert set(rule.technique_ids) == {"T1003", "T1003.001", "T1003.002"}


def test_parse_date_slash_format() -> None:
    rule = parse_rule_file(FIXTURES / "rule_with_subtechnique.yml")
    assert rule is not None
    assert rule.rule_date is not None
    assert rule.rule_date.year == 2024
    assert rule.rule_date.month == 3
    assert rule.modified_date is not None
    assert rule.modified_date.month == 11


def test_non_dict_yaml_returns_none() -> None:
    rule = parse_rule_file(FIXTURES / "not_a_sigma_rule.yml")
    assert rule is None


def test_parse_rule_dir_finds_all_valid_rules() -> None:
    rules = parse_rule_dir(FIXTURES)
    titles = {r.title for r in rules}
    assert "PowerShell Encoded Command" in titles
    assert "Suspicious PowerShell" in titles
    assert "Vendor Rule No ATT&CK" in titles
    assert "Bare Rule" in titles
    assert "Credential Dumping" in titles
    assert "Old Deprecated Rule" in titles
    assert "PowerShell Encoded Command Execution" in titles
    # not_a_sigma_rule.yml is a YAML list, correctly skipped
    assert len(rules) == 7


def test_parse_rule_dir_empty_dir(tmp_path: Path) -> None:
    rules = parse_rule_dir(tmp_path)
    assert rules == []


def test_parse_rule_date_none() -> None:
    from detect_forge.stale._dates import _parse_rule_date

    assert _parse_rule_date(None) is None


def test_parse_rule_date_date_instance() -> None:
    from datetime import date as _date

    from detect_forge.stale._dates import _parse_rule_date

    d = _date(2024, 3, 15)
    assert _parse_rule_date(d) is d


def test_parse_rule_date_datetime_instance_downconverts() -> None:
    from datetime import date as _date
    from datetime import datetime as _datetime

    from detect_forge.stale._dates import _parse_rule_date

    dt = _datetime(2024, 3, 15, 12, 0, 0)
    result = _parse_rule_date(dt)
    assert result == _date(2024, 3, 15)
    assert type(result) is _date


def test_parse_rule_date_slash_string() -> None:
    from datetime import date as _date

    from detect_forge.stale._dates import _parse_rule_date

    assert _parse_rule_date("2024/03/15") == _date(2024, 3, 15)


def test_parse_rule_date_dash_string() -> None:
    from datetime import date as _date

    from detect_forge.stale._dates import _parse_rule_date

    assert _parse_rule_date("2024-03-15") == _date(2024, 3, 15)


def test_parse_rule_date_unparseable_returns_none() -> None:
    from detect_forge.stale._dates import _parse_rule_date

    assert _parse_rule_date("not a date") is None
    assert _parse_rule_date("99-99-99") is None  # invalid month/day — can't parse


def test_extract_ignores_non_string_tags() -> None:
    # YAML can yield ints for malformed tags (e.g., `- 2021-44228` becomes int arithmetic).
    # Must not crash; must skip non-strings silently.
    assert _extract_technique_ids(["attack.t1059", -42223, None, True]) == ["T1059"]


def test_parse_rule_extracts_description() -> None:
    rule = parse_rule_file(FIXTURES / "rule_with_description.yml")
    assert rule is not None
    assert rule.description is not None
    assert "PowerShell" in rule.description
    assert "EncodedCommand" in rule.description


def test_parse_rule_no_description_yields_none() -> None:
    # rule_with_subtechnique.yml has no `description:` field.
    rule = parse_rule_file(FIXTURES / "rule_with_subtechnique.yml")
    assert rule is not None
    assert rule.description is None


# --------------------------------------------------------------------------
# Task 10: malformed tags must not crash the scan (T3, T4)
# --------------------------------------------------------------------------


def test_scalar_tags_does_not_crash(tmp_path: Path) -> None:
    f = tmp_path / "bad.yml"
    f.write_text(
        "title: Scalar tags\ntags: 42\n"
        "detection:\n  selection:\n    Image: x\n  condition: selection\n"
    )
    rule = parse_rule_file(f)
    assert rule is not None            # otherwise-valid rule is kept
    assert rule.technique_ids == []
    assert rule.raw_tags == []


def test_mixed_type_tags_keeps_valid_technique(tmp_path: Path) -> None:
    f = tmp_path / "mixed.yml"
    f.write_text(
        "title: Mixed tags\ntags:\n  - attack.t1059\n  - 5\n"
        "detection:\n  selection:\n    Image: x\n  condition: selection\n"
    )
    rule = parse_rule_file(f)
    assert rule is not None            # not dropped over a non-string tag
    assert rule.technique_ids == ["T1059"]


def test_one_bad_file_does_not_abort_dir_scan(tmp_path: Path) -> None:
    (tmp_path / "bad.yml").write_text("title: Bad\ntags: 42\n")
    (tmp_path / "good.yml").write_text(
        "title: Good\ntags:\n  - attack.t1059\n"
        "detection:\n  selection:\n    Image: x\n  condition: selection\n"
    )
    rules = parse_rule_dir(tmp_path)
    titles = {r.title for r in rules}
    assert "Good" in titles           # the good rule survives the bad one
