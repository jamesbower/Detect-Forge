from __future__ import annotations

from pathlib import Path

from detect_forge.stale.models import DetectionRule


def _eql_rule(query: str, source: str = "/r.toml") -> DetectionRule:
    """Build a DetectionRule with EQL query stashed in raw_toml."""
    toml = f"""
[rule]
name = "Test Rule"
type = "eql"
language = "eql"
query = '''
{query}
'''
"""
    return DetectionRule(
        title="Test Rule",
        technique_ids=["T1059"],
        source_file=Path(source),
        raw_tags=[],
        raw_toml=toml,
    )


def test_elastic_supports_eql_rule() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("process where process.name == \"powershell.exe\"")
    m = ElasticMatcher()
    assert m.supports(rule) is True


def test_elastic_eql_simple_process_match() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("process where process.name == \"powershell.exe\"")
    events = [
        {"event": {"category": "process"}, "process": {"name": "powershell.exe"}},
        {"event": {"category": "process"}, "process": {"name": "notepad.exe"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0}


def test_elastic_eql_sequence_pattern() -> None:
    """A two-step sequence: process spawn followed by network connection from same parent."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule(
        'sequence by process.entity_id\n'
        '  [process where event.action == "start"]\n'
        '  [network where event.action == "connection"]'
    )
    events = [
        {"event": {"category": "process", "action": "start"}, "process": {"entity_id": "p1", "name": "x"}},  # noqa: E501
        {"event": {"category": "network", "action": "connection"}, "process": {"entity_id": "p1"}},
        {"event": {"category": "process", "action": "start"}, "process": {"entity_id": "p2"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    # The sequence "[process start] [network connection]" closes on event
    # index 1 (the network connection from process p1). Event 2 is a
    # second process start that doesn't pair with a network event.
    assert [f.event_index for f in fires] == [1]



def test_elastic_esql_rule_unsupported() -> None:
    """ESQL rules report as unsupported with a clear reason."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    toml = """
[rule]
name = "ESQL test"
type = "esql"
language = "esql"
query = 'FROM logs | WHERE process.name == "powershell.exe"'
"""
    rule = DetectionRule(
        title="ESQL test",
        technique_ids=["T1059"],
        source_file=Path("/r.toml"),
        raw_tags=[],
        raw_toml=toml,
    )
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "esql" in (reason or "").lower() or "es|ql" in (reason or "").lower()


def test_elastic_invalid_eql_unsupported_with_reason() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("THIS IS NOT VALID EQL")
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "parse" in (reason or "").lower() or "syntax" in (reason or "").lower()


def test_elastic_eql_handles_ecs_list_category() -> None:
    """ECS v8 represents event.category as a list — must be unwrapped."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("process where process.name == \"powershell.exe\"")
    events = [
        {"event": {"category": ["process"]}, "process": {"name": "powershell.exe"}},
        {"event": {"category": ["network"]}, "process": {"name": "powershell.exe"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    # Only event 0 matches: process category + powershell.exe.
    assert [f.event_index for f in fires] == [0]


def test_elastic_eql_events_without_category_dont_fire_typed_queries() -> None:
    """Events missing event.category fall through to 'generic' and don't
    satisfy category-filtered EQL queries (documented v0.1 limitation)."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _eql_rule("process where process.name == \"powershell.exe\"")
    events = [
        # Has process.name but no event.category — type defaults to 'generic'.
        {"process": {"name": "powershell.exe"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    assert fires == []


def _kql_rule(query: str, source: str = "/r.toml") -> DetectionRule:
    toml = f"""
[rule]
name = "KQL Test"
type = "query"
language = "kuery"
query = '{query}'
"""
    return DetectionRule(
        title="KQL Test",
        technique_ids=["T1059"],
        source_file=Path(source),
        raw_tags=[],
        raw_toml=toml,
    )


def test_kql_supports_basic_field_equality() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule('process.name : "powershell.exe"')
    m = ElasticMatcher()
    assert m.supports(rule) is True


def test_kql_field_equality_matches_event() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule('process.name : "powershell.exe"')
    events = [
        {"process": {"name": "powershell.exe"}},
        {"process": {"name": "notepad.exe"}},
        {"process": {"name": "powershell.exe", "pid": 1234}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 2}


def test_kql_wildcard_match() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule('process.name : "power*"')
    events = [
        {"process": {"name": "powershell.exe"}},
        {"process": {"name": "powershell_ise.exe"}},
        {"process": {"name": "cmd.exe"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 1}


def test_kql_and_or_not_composition() -> None:
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule(
        '(process.name : "powershell.exe" or process.name : "cmd.exe") and not user.name : "admin"'
    )
    events = [
        {"process": {"name": "powershell.exe"}, "user": {"name": "alice"}},
        {"process": {"name": "powershell.exe"}, "user": {"name": "admin"}},
        {"process": {"name": "notepad.exe"}, "user": {"name": "alice"}},
        {"process": {"name": "cmd.exe"}, "user": {"name": "bob"}},
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 3}


def test_kql_field_less_keyword_search_unsupported() -> None:
    """KQL allows 'foo' (no field) — we treat as unsupported."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule('"powershell.exe"')
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "field-less" in (reason or "").lower() or "keyword" in (reason or "").lower()


def test_kql_exists_query_unsupported() -> None:
    """KQL 'exists' (field: *) is out of v0.1 subset."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule('process.name : *')
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "exists" in (reason or "").lower() or "*" in (reason or "")


def test_kql_nested_object_query_unsupported() -> None:
    """KQL nested object query (field:{ ... }) is out of v0.1 subset."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule('process:{ name : "powershell.exe" }')
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "nested" in (reason or "").lower() or "{" in (reason or "")


def test_kql_premature_eof_raises_unsupported() -> None:
    """Incomplete query (e.g., trailing colon) routes to unsupported, not a crash."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule('process.name :')
    m = ElasticMatcher()
    supports, reason = m.support_reason(rule)
    assert supports is False
    assert "end" in (reason or "").lower() or "incomplete" in (reason or "").lower()


def test_elastic_missing_language_defaults_to_kuery() -> None:
    """Elastic rules commonly omit `language`; it defaults to kuery, not unsupported."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    toml = """
[rule]
name = "No language field"
type = "query"
query = 'process.name : "powershell.exe"'
"""
    rule = DetectionRule(
        title="No language field",
        technique_ids=["T1059"],
        source_file=Path("/r.toml"),
        raw_tags=[],
        raw_toml=toml,
    )
    m = ElasticMatcher()
    assert m.supports(rule) is True
    fires = m.match(rule, [{"process": {"name": "powershell.exe"}}], "ds1")
    assert {f.event_index for f in fires} == {0}


def test_kql_matches_ecs_list_valued_fields() -> None:
    """ECS list-valued fields (e.g., host.ip) match if any element matches."""
    from detect_forge.backtest.matchers.elastic import ElasticMatcher

    rule = _kql_rule('host.ip : "1.1.1.1"')
    events = [
        {"host": {"ip": ["1.1.1.1", "2.2.2.2"]}},        # list, contains target -> match
        {"host": {"ip": ["3.3.3.3"]}},                     # list, no match
        {"host": {"ip": "1.1.1.1"}},                       # scalar, matches -> match
        {"host": {"ip": ["4.4.4.4", "5.5.5.5", "1.1.1.1"]}},  # list, contains target -> match
    ]
    m = ElasticMatcher()
    fires = m.match(rule, events, "ds1")
    assert {f.event_index for f in fires} == {0, 2, 3}
