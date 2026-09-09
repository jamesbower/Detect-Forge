"""Sigma matcher for JSON event sequences.

Supports a subset of the Sigma specification:
- detection blocks with selection_* mappings + condition expressions
- modifiers (added in Task 6): contains, startswith, endswith, re
- correlations (added in Task 7): event_count, value_count, temporal, temporal_ordered

Unsupported (rule routes to status='unsupported'):
- pySigma logsource pipelines / field renames
- |cidr, |gt, |lt, |gte, |lte modifiers
- 'keywords' (unfielded search)
"""

from __future__ import annotations

import datetime
import logging
import re
from typing import Any

import yaml

from ...stale.models import DetectionRule
from ..models import FireRecord

log = logging.getLogger(__name__)

_UNSUPPORTED_MODIFIERS = {"cidr", "gt", "lt", "gte", "lte"}
_SUPPORTED_MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
_SUPPORTED_CORRELATION_TYPES = {
    "event_count",
    "value_count",
    "temporal",
    "temporal_ordered",
}

# Tuple shape for stamped events used during correlation eval:
# (timestamp_seconds, original_event_index, event_dict, matched_rule_ids, group_key)
_TsEvent = tuple[float, int, dict[str, Any], set[str], tuple[Any, ...]]


class SigmaMatcher:
    """Sigma → JSON event evaluator."""

    def supports(self, rule: DetectionRule) -> bool:
        supports, _ = self.support_reason(rule)
        return supports

    def support_reason(self, rule: DetectionRule) -> tuple[bool, str | None]:
        if rule.raw_yaml is None:
            return False, "Sigma rule missing raw_yaml"
        try:
            parsed = yaml.safe_load(rule.raw_yaml)
        except yaml.YAMLError as exc:
            return False, f"Sigma YAML parse error: {exc}"
        if not isinstance(parsed, dict):
            return False, "Sigma rule top-level is not a mapping"
        if "correlation" in parsed:
            corr = parsed.get("correlation") or {}
            corr_type = corr.get("type") if isinstance(corr, dict) else None
            if corr_type not in _SUPPORTED_CORRELATION_TYPES:
                return False, f"Sigma correlation type not supported: {corr_type}"
            # Fall through: still require a detection block to resolve
            # referenced selection_<name> entries.
        detection = parsed.get("detection")
        if not isinstance(detection, dict):
            return False, "Sigma rule has no detection block"
        # Reject unsupported modifiers + keywords.
        for sel_name, sel_value in detection.items():
            if sel_name == "condition":
                continue
            if sel_name == "keywords":
                return False, "Sigma uses unfielded keywords"
            if isinstance(sel_value, dict):
                for field_key in sel_value:
                    if "|" in field_key:
                        parts = field_key.split("|")[1:]
                        for modifier in parts:
                            if modifier in _UNSUPPORTED_MODIFIERS:
                                return False, f"Sigma uses unsupported modifier: |{modifier}"
                            if modifier not in _SUPPORTED_MODIFIERS:
                                return False, f"unsupported modifier: {modifier}"
        return True, None

    def match(
        self,
        rule: DetectionRule,
        events: list[dict[str, Any]],
        dataset_id: str,
    ) -> list[FireRecord]:
        if not self.supports(rule):
            return []
        assert rule.raw_yaml is not None  # narrowed by supports()
        parsed = yaml.safe_load(rule.raw_yaml)
        if "correlation" in parsed:
            return self._match_correlation(parsed, rule, events, dataset_id)
        detection = parsed["detection"]
        condition_expr = detection.get("condition", "")
        selection_names = [k for k in detection if k != "condition"]
        condition_ast = _parse_condition(condition_expr, selection_names)

        fires: list[FireRecord] = []
        for idx, event in enumerate(events):
            sel_results = {
                name: _evaluate_selection(detection[name], event)
                for name in selection_names
            }
            if _evaluate_condition(condition_ast, sel_results):
                fires.append(
                    FireRecord(
                        rule_id=rule.rule_id or rule.title,
                        technique_id=rule.technique_ids[0] if rule.technique_ids else "",
                        dataset_id=dataset_id,
                        event_index=idx,
                    )
                )
        return fires

    # ---------- correlation evaluation ----------

    def _match_correlation(
        self,
        parsed: dict[str, Any],
        rule: DetectionRule,
        events: list[dict[str, Any]],
        dataset_id: str,
    ) -> list[FireRecord]:
        corr = parsed["correlation"]
        corr_type = corr["type"]
        detection = parsed.get("detection", {}) or {}
        rule_ids: list[str] = list(corr.get("rules", []) or [])

        # Resolve referenced rule names → selection_<name> in detection block.
        # v0.1 restriction: single-file correlations only. A referenced rule_id
        # that has no matching selection_<rule_id> block is warned and dropped.
        selection_map: dict[str, Any] = {}
        for rid in rule_ids:
            sel_name = f"selection_{rid}"
            if sel_name in detection:
                selection_map[rid] = detection[sel_name]
            else:
                log.warning(
                    "Sigma correlation in rule %s references rule '%s' but no "
                    "matching '%s' block exists in detection. v0.1 only supports "
                    "single-file correlations.",
                    rule.rule_id or rule.title,
                    rid,
                    sel_name,
                )

        timespan_seconds = _parse_timespan(str(corr.get("timespan", "5m")))
        group_by: list[str] = list(corr.get("group-by", []) or [])
        condition: dict[str, Any] = dict(corr.get("condition", {}) or {})

        # Stamp each event with which referenced rules it matches + timestamp.
        ts_events: list[_TsEvent] = []
        for idx, event in enumerate(events):
            ts = _event_timestamp(event)
            if ts is None:
                continue
            matched: set[str] = {
                rid
                for rid, sel in selection_map.items()
                if _evaluate_selection(sel, event)
            }
            if not matched and corr_type in {"event_count", "value_count"}:
                # For count-based correlations, an event that matches no
                # referenced rule contributes nothing.
                continue
            group_key: tuple[Any, ...] = (
                tuple(event.get(g) for g in group_by) if group_by else ()
            )
            ts_events.append((ts, idx, event, matched, group_key))

        if corr_type == "event_count":
            return self._eval_event_count(
                ts_events, condition, timespan_seconds, rule, dataset_id,
            )
        if corr_type == "value_count":
            return self._eval_value_count(
                ts_events, condition, timespan_seconds, rule, dataset_id,
            )
        if corr_type == "temporal":
            return self._eval_temporal(
                ts_events, rule_ids, timespan_seconds, rule, dataset_id,
                ordered=False,
            )
        if corr_type == "temporal_ordered":
            return self._eval_temporal(
                ts_events, rule_ids, timespan_seconds, rule, dataset_id,
                ordered=True,
            )
        return []

    def _eval_event_count(
        self,
        ts_events: list[_TsEvent],
        condition: dict[str, Any],
        window: float,
        rule: DetectionRule,
        dataset_id: str,
    ) -> list[FireRecord]:
        """Sliding window: at each match, count matches in [t - window, t] per group."""
        fires: list[FireRecord] = []
        for ts, idx, _event, matched, group_key in ts_events:
            if not matched:
                continue
            window_start = ts - window
            count = sum(
                1
                for (ts2, _, _, m2, gk2) in ts_events
                if ts2 >= window_start and ts2 <= ts and m2 and gk2 == group_key
            )
            if _check_threshold(count, condition):
                fires.append(_make_fire(rule, dataset_id, idx))
        return fires

    def _eval_value_count(
        self,
        ts_events: list[_TsEvent],
        condition: dict[str, Any],
        window: float,
        rule: DetectionRule,
        dataset_id: str,
    ) -> list[FireRecord]:
        """Distinct count of `condition.field` values in window per group."""
        field = str(condition.get("field", ""))
        fires: list[FireRecord] = []
        for ts, idx, _event, matched, group_key in ts_events:
            if not matched:
                continue
            window_start = ts - window
            distinct: set[Any] = {
                ev.get(field)
                for (ts2, _, ev, m2, gk2) in ts_events
                if ts2 >= window_start and ts2 <= ts and m2 and gk2 == group_key
            }
            distinct.discard(None)
            if _check_threshold(len(distinct), condition):
                fires.append(_make_fire(rule, dataset_id, idx))
        return fires

    def _eval_temporal(
        self,
        ts_events: list[_TsEvent],
        rule_ids: list[str],
        window: float,
        rule: DetectionRule,
        dataset_id: str,
        *,
        ordered: bool,
    ) -> list[FireRecord]:
        """All referenced rules fire within the window (optionally in order).

        Fires are anchored to the event that "completes" the correlation —
        i.e., an event matching at least one referenced rule, whose
        backward-looking [t - window, t] sweep contains matches for every
        required rule. Neutral (non-matching) events do not anchor fires,
        even if they fall inside a window where all rules have already
        fired. This avoids over-firing on unrelated log entries.
        """
        fires: list[FireRecord] = []
        required = set(rule_ids)
        for ts, idx, _event, matched, _gk in ts_events:
            if not matched:
                continue
            window_start = ts - window
            in_window = [
                (ts2, idx2, ev, m2)
                for (ts2, idx2, ev, m2, _) in ts_events
                if ts2 >= window_start and ts2 <= ts
            ]
            seen: set[str] = set()
            for _, _, _, m2 in in_window:
                seen.update(m2)
            if not required.issubset(seen):
                continue
            if ordered:
                # Verify each rule_id appears in order within the window.
                order_idx = 0
                for _, _, _, m2 in in_window:
                    if rule_ids[order_idx] in m2:
                        order_idx += 1
                        if order_idx == len(rule_ids):
                            break
                if order_idx < len(rule_ids):
                    continue
            fires.append(_make_fire(rule, dataset_id, idx))
        return fires


# ---------- selection evaluation ----------

def _evaluate_selection(selection: Any, event: dict[str, Any]) -> bool:
    """A selection is a mapping of field_spec → value(s). All entries must match (AND)."""
    if isinstance(selection, list):
        # List-form selection means OR over the entries.
        return any(_evaluate_selection(s, event) for s in selection)
    if not isinstance(selection, dict):
        return False
    for field_spec, value_spec in selection.items():
        field_name, modifiers = _parse_field_spec(field_spec)
        actual = event.get(field_name)
        if not _value_matches(actual, value_spec, modifiers):
            return False
    return True


def _parse_field_spec(field_spec: str) -> tuple[str, list[str]]:
    """'Image|endswith' → ('Image', ['endswith'])"""
    parts = field_spec.split("|")
    return parts[0], parts[1:]


def _wildcard_to_regex(spec: str) -> str:
    """Translate a Sigma plain-value wildcard pattern to an anchored regex.

    ``*`` matches any run of characters, ``?`` matches a single character;
    every other character is escaped literally.
    """
    out: list[str] = []
    for ch in spec:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    return "^" + "".join(out) + "$"


def _value_matches(actual: Any, value_spec: Any, modifiers: list[str]) -> bool:
    """Apply modifiers to compare actual (event value) against value_spec.

    Modifiers in v0.1: contains, startswith, endswith, re, all. The ``all``
    modifier flips list-value semantics from OR (default) to AND — every
    element of a list value_spec must match. Typically chained as e.g.
    ``field|contains|all``. Other modifiers are filtered out at supports(),
    so only these five can appear here.
    List value_spec is OR'd by default; AND'd when ``all`` is in modifiers.

    Comparisons follow the SigmaHQ spec: plain values and the string
    modifiers (contains/startswith/endswith) are case-insensitive, plain
    values honour ``*``/``?`` wildcards, and non-string event values are
    stringified so ``EventID: 1`` matches an event carrying ``"1"``. The
    ``re`` modifier stays case-sensitive (use ``re|i`` for insensitive —
    not yet supported).
    """
    use_all = "all" in modifiers
    if use_all:
        modifiers = [m for m in modifiers if m != "all"]
    if isinstance(value_spec, list):
        check = all if use_all else any
        return check(_value_matches(actual, v, modifiers) for v in value_spec)
    if value_spec is None:
        # Sigma ``field: null`` matches when the field is absent/None.
        return actual is None
    if isinstance(actual, list):
        # ECS multi-value event fields: match if ANY element matches.
        return any(_value_matches(item, value_spec, modifiers) for item in actual)
    if actual is None:
        return False
    actual_str = str(actual)
    spec_str = str(value_spec)
    if not modifiers:
        if isinstance(value_spec, str) and ("*" in value_spec or "?" in value_spec):
            return re.match(_wildcard_to_regex(spec_str), actual_str, re.IGNORECASE) is not None
        return actual_str.casefold() == spec_str.casefold()
    actual_cf = actual_str.casefold()
    spec_cf = spec_str.casefold()
    for mod in modifiers:
        if mod == "contains":
            if spec_cf not in actual_cf:
                return False
        elif mod == "startswith":
            if not actual_cf.startswith(spec_cf):
                return False
        elif mod == "endswith":
            if not actual_cf.endswith(spec_cf):
                return False
        elif mod == "re":
            if not re.search(spec_str, actual_str):
                return False
        else:
            # Unreachable when called via match() — unsupported modifiers are
            # rejected by support_reason() before match() is invoked.
            return False  # defense-in-depth
    return True


# ---------- condition parsing + evaluation ----------

class _CondNode:
    """Tiny condition AST."""


class _Ref(_CondNode):
    def __init__(self, name: str) -> None:
        self.name = name


class _And(_CondNode):
    def __init__(self, left: _CondNode, right: _CondNode) -> None:
        self.left = left
        self.right = right


class _Or(_CondNode):
    def __init__(self, left: _CondNode, right: _CondNode) -> None:
        self.left = left
        self.right = right


class _Not(_CondNode):
    def __init__(self, inner: _CondNode) -> None:
        self.inner = inner


class _AllOf(_CondNode):
    def __init__(self, names: list[str]) -> None:
        self.names = names


class _OneOf(_CondNode):
    def __init__(self, names: list[str]) -> None:
        self.names = names


class _NOf(_CondNode):
    """`N of <glob>` — at least ``n`` of the expanded selections are true."""

    def __init__(self, n: int, names: list[str]) -> None:
        self.n = n
        self.names = names


def _parse_condition(expr: str, selection_names: list[str]) -> _CondNode:
    """Small recursive-descent parser for Sigma condition expressions.

    Grammar (Task 5 subset):
        expr := or_expr
        or_expr := and_expr ('or' and_expr)*
        and_expr := unary ('and' unary)*
        unary := 'not' unary | primary
        primary := IDENT | '(' expr ')' | 'all of' GLOB | '<N> of' GLOB

    ``GLOB`` may be ``them`` (all search identifiers), a literal selection
    name, or a ``selection_*`` wildcard. ``N`` is any positive integer;
    ``1 of`` is the common special case.
    """
    tokens = _tokenize_condition(expr)
    parser = _CondParser(tokens, selection_names)
    return parser.parse_expr()


def _tokenize_condition(expr: str) -> list[str]:
    # Replace operators with spaced tokens; split on whitespace and parens.
    pattern = r"\(|\)|\ball of\b|\b\d+ of\b|\band\b|\bor\b|\bnot\b|[A-Za-z_][A-Za-z_0-9\*]*"
    return re.findall(pattern, expr)


class _CondParser:
    def __init__(self, tokens: list[str], selection_names: list[str]) -> None:
        self.tokens = tokens
        self.pos = 0
        self.selection_names = selection_names

    def _peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _consume(self) -> str:
        t = self.tokens[self.pos]
        self.pos += 1
        return t

    def parse_expr(self) -> _CondNode:
        node = self.parse_and()
        while self._peek() == "or":
            self._consume()
            right = self.parse_and()
            node = _Or(node, right)
        return node

    def parse_and(self) -> _CondNode:
        node = self.parse_unary()
        while self._peek() == "and":
            self._consume()
            right = self.parse_unary()
            node = _And(node, right)
        return node

    def parse_unary(self) -> _CondNode:
        if self._peek() == "not":
            self._consume()
            return _Not(self.parse_unary())
        return self.parse_primary()

    def parse_primary(self) -> _CondNode:
        t = self._consume()
        if t == "(":
            node = self.parse_expr()
            if self._consume() != ")":
                raise SyntaxError("Expected ')'")
            return node
        if t == "all of":
            glob = self._consume()
            return _AllOf(_expand_glob(glob, self.selection_names))
        n_of = re.match(r"^(\d+) of$", t)
        if n_of:
            glob = self._consume()
            n = int(n_of.group(1))
            names = _expand_glob(glob, self.selection_names)
            return _OneOf(names) if n <= 1 else _NOf(n, names)
        return _Ref(t)


def _expand_glob(glob: str, names: list[str]) -> list[str]:
    """'them' → all search identifiers; 'selection_*' → matching names; literal → [name]."""
    if glob == "them":
        return list(names)
    if "*" not in glob:
        return [glob]
    pattern = re.compile("^" + re.escape(glob).replace(r"\*", ".*") + "$")
    return [n for n in names if pattern.match(n)]


def _evaluate_condition(node: _CondNode, sel_results: dict[str, bool]) -> bool:
    if isinstance(node, _Ref):
        return sel_results.get(node.name, False)
    if isinstance(node, _And):
        return _evaluate_condition(node.left, sel_results) and _evaluate_condition(
            node.right, sel_results
        )
    if isinstance(node, _Or):
        return _evaluate_condition(node.left, sel_results) or _evaluate_condition(
            node.right, sel_results
        )
    if isinstance(node, _Not):
        return not _evaluate_condition(node.inner, sel_results)
    if isinstance(node, _AllOf):
        return all(sel_results.get(n, False) for n in node.names)
    if isinstance(node, _OneOf):
        return any(sel_results.get(n, False) for n in node.names)
    if isinstance(node, _NOf):
        return sum(1 for name in node.names if sel_results.get(name, False)) >= node.n
    return False


# ---------- correlation helpers ----------

def _parse_timespan(spec: str) -> float:
    """Parse '5m', '1h', '30s', '2d' (case-insensitive) to seconds.

    Falls back to plain float seconds if no unit suffix.
    """
    if not spec:
        return 0.0
    spec = spec.strip().lower()
    if spec.endswith("s"):
        return float(spec[:-1])
    if spec.endswith("m"):
        return float(spec[:-1]) * 60
    if spec.endswith("h"):
        return float(spec[:-1]) * 3600
    if spec.endswith("d"):
        return float(spec[:-1]) * 86400
    return float(spec)


def _event_timestamp(event: dict[str, Any]) -> float | None:
    """Try a few common timestamp fields; return Unix-epoch seconds or None.

    Handles int/float epoch values and ISO-8601 strings (including trailing 'Z').
    """
    for field in ("@timestamp", "TimeCreated", "timestamp", "Timestamp"):
        v = event.get(field)
        if v is None:
            continue
        if isinstance(v, (int, float)):
            return float(v)
        if not isinstance(v, str):
            continue
        try:
            s = v[:-1] + "+00:00" if v.endswith("Z") else v
            dt = datetime.datetime.fromisoformat(s)
            return dt.timestamp()
        except (ValueError, TypeError):
            continue
    return None


def _check_threshold(count: int, condition: dict[str, Any]) -> bool:
    """Apply gt/gte/eq/lt/lte comparison from a correlation condition block."""
    if "gt" in condition:
        return bool(count > condition["gt"])
    if "gte" in condition:
        return bool(count >= condition["gte"])
    if "eq" in condition:
        return bool(count == condition["eq"])
    if "lt" in condition:
        return bool(count < condition["lt"])
    if "lte" in condition:
        return bool(count <= condition["lte"])
    return False


def _make_fire(rule: DetectionRule, dataset_id: str, event_index: int) -> FireRecord:
    return FireRecord(
        rule_id=rule.rule_id or rule.title,
        technique_id=rule.technique_ids[0] if rule.technique_ids else "",
        dataset_id=dataset_id,
        event_index=event_index,
    )
