from __future__ import annotations

from pathlib import Path
from typing import Any

from detect_forge.stale.models import DetectionRule


def _rule_from_yaml(yaml_text: str, source: str = "/r.yml") -> DetectionRule:
    """Build a DetectionRule with raw YAML stashed for the matcher to re-read."""
    return DetectionRule(
        title="Test Rule",
        technique_ids=["T1059"],
        source_file=Path(source),
        raw_tags=[],
        raw_yaml=yaml_text,
    )


def test_sigma_supports_basic_detection_block() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: PS Encoded
detection:
    selection:
        Image|endswith: '\\\\powershell.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    m = SigmaMatcher()
    assert m.supports(rule) is True


def test_sigma_matches_simple_equality() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: Notepad
detection:
    selection:
        Image: 'notepad.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "notepad.exe"},
        {"Image": "calc.exe"},
        {"Image": "notepad.exe", "CommandLine": "x"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 2}


def test_sigma_matches_list_value_as_OR() -> None:
    """A list value in a selection means any-of."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: PS or CMD
detection:
    selection:
        Image:
            - 'powershell.exe'
            - 'cmd.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [{"Image": "powershell.exe"}, {"Image": "notepad.exe"}, {"Image": "cmd.exe"}]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 2}


def test_sigma_condition_all_of_selection_globs() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: both
detection:
    selection_a:
        Image: 'powershell.exe'
    selection_b:
        CommandLine|contains: '-EncodedCommand'
    condition: all of selection_*
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "powershell.exe", "CommandLine": "-EncodedCommand AABB"},
        {"Image": "powershell.exe", "CommandLine": "other"},
        {"Image": "notepad.exe", "CommandLine": "-EncodedCommand"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_sigma_condition_one_of_selection_globs() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: either
detection:
    selection_a:
        Image: 'powershell.exe'
    selection_b:
        CommandLine: 'whoami'
    condition: 1 of selection_*
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "powershell.exe"},
        {"Image": "cmd.exe", "CommandLine": "whoami"},
        {"Image": "notepad.exe"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 1}


def test_sigma_condition_and_or_not_parens() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: complex
detection:
    selection_a:
        Image: 'powershell.exe'
    selection_b:
        CommandLine: 'whoami'
    selection_c:
        Image: 'notepad.exe'
    condition: (selection_a and selection_b) or (selection_c and not selection_b)
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "powershell.exe", "CommandLine": "whoami"},
        {"Image": "notepad.exe"},
        {"Image": "notepad.exe", "CommandLine": "whoami"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 1}


def test_sigma_rejects_unknown_correlation_type() -> None:
    """Unknown correlation types remain unsupported even after Task 7."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: corr
correlation:
    type: not_a_real_type
    rules:
        - some_rule
    timespan: 5m
    condition:
        gt: 5
detection:
    selection: {}
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    m = SigmaMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "correlation" in (reason or "").lower()


def test_sigma_modifier_contains() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: contains
detection:
    selection:
        CommandLine|contains: 'EncodedCommand'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"CommandLine": "powershell -EncodedCommand AABB"},
        {"CommandLine": "cmd /c whoami"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_sigma_modifier_startswith() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: startswith
detection:
    selection:
        Image|startswith: 'C:\\Windows\\System32'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "C:\\Windows\\System32\\notepad.exe"},
        {"Image": "C:\\Temp\\evil.exe"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_sigma_modifier_endswith() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: endswith
detection:
    selection:
        Image|endswith: '\\powershell.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "C:\\Windows\\System32\\powershell.exe"},
        {"Image": "C:\\Windows\\System32\\notepad.exe"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_sigma_modifier_re() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: re
detection:
    selection:
        CommandLine|re: 'whoami.*.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"CommandLine": "whoami /all .exe"},
        {"CommandLine": "ls -la"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_sigma_modifier_endswith_with_list_value() -> None:
    """Modifier + list value still ORs across the list."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: any
detection:
    selection:
        Image|endswith:
            - '\\powershell.exe'
            - '\\cmd.exe'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"Image": "C:\\Windows\\System32\\cmd.exe"},
        {"Image": "C:\\Windows\\System32\\notepad.exe"},
        {"Image": "C:\\Windows\\System32\\powershell.exe"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 2}


def test_sigma_rejects_unknown_modifier() -> None:
    """Modifiers outside the supported allowlist must be rejected at supports()."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: unknown-modifier
detection:
    selection:
        CommandLine|base64: 'cG93ZXJzaGVsbA=='
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    m = SigmaMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "base64" in (reason or "").lower() or "unsupported" in (reason or "").lower()


def test_sigma_correlation_event_count_fires_above_threshold() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: 6+ failed logins per user
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 5m
    condition:
        gt: 5
detection:
    selection_failed_login:
        EventID: 4625
    condition: selection_failed_login
"""
    rule = _rule_from_yaml(rule_yaml)
    base = "2024-01-01T00:00:"
    events = [
        {"@timestamp": f"{base}{i:02}Z", "EventID": 4625, "User": "alice"}
        for i in range(6)
    ] + [
        {"@timestamp": f"{base}06Z", "EventID": 4625, "User": "bob"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    # alice trips on event 5 (6th occurrence in 5min). bob (only 1) doesn't.
    assert len(fires) >= 1
    assert all(f.event_index == 5 for f in fires)


def test_sigma_correlation_event_count_does_not_fire_below_threshold() -> None:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: gt-5
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 5m
    condition:
        gt: 5
detection:
    selection_failed_login:
        EventID: 4625
    condition: selection_failed_login
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"@timestamp": f"2024-01-01T00:00:0{i}Z", "EventID": 4625, "User": "alice"}
        for i in range(5)  # exactly 5; not > 5
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert fires == []


def test_sigma_correlation_value_count_distinct() -> None:
    """3+ distinct destination IPs from one source within 1 minute."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: port scan
correlation:
    type: value_count
    rules:
        - any_connection
    group-by:
        - SourceIP
    timespan: 1m
    condition:
        field: DestinationIP
        gte: 3
detection:
    selection_any_connection:
        EventID: 5156
    condition: selection_any_connection
"""
    rule = _rule_from_yaml(rule_yaml)
    base = "2024-01-01T00:00:"
    src = "10.0.0.1"
    events = [
        {"@timestamp": f"{base}00Z", "EventID": 5156, "SourceIP": src, "DestinationIP": "1.1.1.1"},
        {"@timestamp": f"{base}10Z", "EventID": 5156, "SourceIP": src, "DestinationIP": "2.2.2.2"},
        {"@timestamp": f"{base}20Z", "EventID": 5156, "SourceIP": src, "DestinationIP": "3.3.3.3"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert len(fires) >= 1


def test_sigma_correlation_temporal_any_order() -> None:
    """Both referenced selections fire within the window (any order)."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: download then execute
correlation:
    type: temporal
    rules:
        - file_download
        - process_exec
    timespan: 5m
detection:
    selection_file_download:
        EventID: 1003
    selection_process_exec:
        EventID: 1
    condition: 1 of selection_*
"""
    rule = _rule_from_yaml(rule_yaml)
    base = "2024-01-01T00:0"
    events = [
        {"@timestamp": f"{base}0:00Z", "EventID": 1},
        {"@timestamp": f"{base}0:30Z", "EventID": 1003},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert len(fires) >= 1


def test_sigma_correlation_temporal_ordered_respects_order() -> None:
    """Ordered: file_download must come BEFORE process_exec to fire."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: ordered chain
correlation:
    type: temporal_ordered
    rules:
        - file_download
        - process_exec
    timespan: 5m
detection:
    selection_file_download:
        EventID: 1003
    selection_process_exec:
        EventID: 1
    condition: 1 of selection_*
"""
    rule = _rule_from_yaml(rule_yaml)
    base = "2024-01-01T00:0"
    # Wrong order: process_exec first, then file_download.
    bad_events = [
        {"@timestamp": f"{base}0:00Z", "EventID": 1},
        {"@timestamp": f"{base}0:30Z", "EventID": 1003},
    ]
    # Right order:
    good_events = [
        {"@timestamp": f"{base}0:00Z", "EventID": 1003},
        {"@timestamp": f"{base}0:30Z", "EventID": 1},
    ]
    m = SigmaMatcher()
    assert m.match(rule, bad_events, "ds1") == []
    assert len(m.match(rule, good_events, "ds1")) >= 1


def test_sigma_correlation_respects_timespan_boundary() -> None:
    """Events outside the timespan don't count toward the threshold."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: 6+ in 1m
correlation:
    type: event_count
    rules:
        - any
    group-by:
        - User
    timespan: 1m
    condition:
        gt: 5
detection:
    selection_any:
        EventID: 4625
    condition: selection_any
"""
    rule = _rule_from_yaml(rule_yaml)
    # 6 events but spread over 2 minutes (only ~3 within any 1-min window).
    events = [
        {"@timestamp": f"2024-01-01T00:0{i//3}:0{(i%3)*20}Z", "EventID": 4625, "User": "alice"}
        for i in range(6)
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert fires == []


def test_sigma_correlation_timespan_accepts_uppercase() -> None:
    """timespan: 5M (uppercase) parses the same as 5m."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: 6+ in 5M (upper)
correlation:
    type: event_count
    rules:
        - failed_login
    group-by:
        - User
    timespan: 5M
    condition:
        gt: 5
detection:
    selection_failed_login:
        EventID: 4625
    condition: selection_failed_login
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"@timestamp": f"2024-01-01T00:00:{i:02}Z", "EventID": 4625, "User": "alice"}
        for i in range(6)
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert len(fires) >= 1  # 5M parsed as 300s, all 6 events fall in window


def test_sigma_correlation_warns_on_unresolved_rule_reference(
    caplog: Any,
) -> None:
    """Unresolved rule references log a warning and produce zero fires."""
    import logging

    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: bad ref
correlation:
    type: event_count
    rules:
        - nonexistent
    group-by:
        - User
    timespan: 5m
    condition:
        gt: 5
detection:
    selection_failed_login:
        EventID: 4625
    condition: selection_failed_login
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        {"@timestamp": f"2024-01-01T00:00:{i:02}Z", "EventID": 4625, "User": "alice"}
        for i in range(6)
    ]
    m = SigmaMatcher()
    with caplog.at_level(logging.WARNING):
        fires = m.match(rule, events, "ds1")
    assert fires == []
    assert any(
        "nonexistent" in record.message and "selection_nonexistent" in record.message
        for record in caplog.records
    )


def test_sigma_supports_contains_all_modifier() -> None:
    """Sigma rule using |contains|all must report supported."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: contains-all
detection:
    selection:
        CommandLine|contains|all:
            - 'EncodedCommand'
            - 'powershell'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    m = SigmaMatcher()
    assert m.supports(rule) is True


def test_sigma_contains_all_fires_when_all_values_match() -> None:
    """All values in the list must be present (AND, not OR)."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: contains-all
detection:
    selection:
        CommandLine|contains|all:
            - 'EncodedCommand'
            - 'powershell'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        # Has both strings → fires
        {"CommandLine": "powershell.exe -EncodedCommand AABB=="},
        # Has only one of the two → does NOT fire under |all
        {"CommandLine": "powershell.exe -Command Get-Process"},
        # Has neither → does not fire
        {"CommandLine": "cmd.exe /c whoami"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_sigma_contains_all_silent_when_one_value_missing() -> None:
    """Specifically pin down that missing-one-of-N suppresses the fire."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: contains-all-strict
detection:
    selection:
        Image|contains|all:
            - ':\\Program Files\\Microsoft Office'
            - '\\SkypeSrv\\'
    condition: selection
"""
    rule = _rule_from_yaml(rule_yaml)
    events = [
        # Has only the first substring → no fire
        {"Image": "C:\\Program Files\\Microsoft Office\\OUTLOOK.EXE"},
        # Has only the second substring → no fire
        {"Image": "C:\\OtherDir\\SkypeSrv\\SKYPESERVER.EXE"},
        # Has both substrings → fires
        {"Image": "C:\\Program Files\\Microsoft Office\\SkypeSrv\\SKYPESERVER.EXE"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {2}


def test_sigma_correlation_value_count_dedupes_duplicates() -> None:
    """3 events with only 2 distinct DestinationIPs don't trip gte: 3."""
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    rule_yaml = """
title: port scan
correlation:
    type: value_count
    rules:
        - any_connection
    group-by:
        - SourceIP
    timespan: 1m
    condition:
        field: DestinationIP
        gte: 3
detection:
    selection_any_connection:
        EventID: 5156
    condition: selection_any_connection
"""
    rule = _rule_from_yaml(rule_yaml)
    base = "2024-01-01T00:00:"
    src = "10.0.0.1"
    events = [
        {"@timestamp": f"{base}00Z", "EventID": 5156, "SourceIP": src, "DestinationIP": "1.1.1.1"},
        {"@timestamp": f"{base}10Z", "EventID": 5156, "SourceIP": src, "DestinationIP": "1.1.1.1"},
        {"@timestamp": f"{base}20Z", "EventID": 5156, "SourceIP": src, "DestinationIP": "2.2.2.2"},
    ]
    m = SigmaMatcher()
    fires = m.match(rule, events, "ds1")
    assert fires == []  # only 2 distinct DestinationIPs → below gte: 3


# --------------------------------------------------------------------------
# Task 1: plain-value wildcards, case-insensitivity, int/str coercion (M1,M4,M5)
# --------------------------------------------------------------------------


def _fires(yaml_text: str, events: list[dict[str, Any]]) -> bool:
    from detect_forge.backtest.matchers.sigma import SigmaMatcher

    return bool(SigmaMatcher().match(_rule_from_yaml(yaml_text), events, "ds"))


def test_sigma_plain_value_wildcard_matches() -> None:
    y = "detection:\n  selection:\n    CommandLine: '*-enc*'\n  condition: selection\n"
    assert _fires(y, [{"CommandLine": "powershell.exe -enc AAA"}])
    assert not _fires(y, [{"CommandLine": "powershell.exe -Command x"}])


def test_sigma_plain_value_question_mark_wildcard() -> None:
    y = "detection:\n  selection:\n    Image: 'cmd?.exe'\n  condition: selection\n"
    assert _fires(y, [{"Image": "cmd1.exe"}])
    assert not _fires(y, [{"Image": "cmd12.exe"}])


def test_sigma_plain_value_case_insensitive() -> None:
    y = "detection:\n  selection:\n    Image: 'CMD.EXE'\n  condition: selection\n"
    assert _fires(y, [{"Image": "cmd.exe"}])
    assert _fires(y, [{"Image": "CMD.EXE"}])


def test_sigma_contains_modifier_case_insensitive() -> None:
    y = "detection:\n  selection:\n    CommandLine|contains: '-ENC'\n  condition: selection\n"
    assert _fires(y, [{"CommandLine": "powershell -enc x"}])


def test_sigma_int_string_coercion() -> None:
    y = "detection:\n  selection:\n    EventID: 1\n  condition: selection\n"
    assert _fires(y, [{"EventID": "1"}])
    assert _fires(y, [{"EventID": 1}])
    assert not _fires(y, [{"EventID": "2"}])


# --------------------------------------------------------------------------
# Task 3: list-valued event fields (M6) and `field: null` (M7)
# --------------------------------------------------------------------------


def test_sigma_list_valued_event_field() -> None:
    y = "detection:\n  selection:\n    category: 'process'\n  condition: selection\n"
    assert _fires(y, [{"category": ["network", "process"]}])
    assert not _fires(y, [{"category": ["network", "file"]}])


def test_sigma_field_null_matches_absent() -> None:
    y = "detection:\n  selection:\n    Ghost: null\n  condition: selection\n"
    assert _fires(y, [{"Other": "x"}])            # Ghost absent -> matches null
    assert not _fires(y, [{"Ghost": "present"}])
