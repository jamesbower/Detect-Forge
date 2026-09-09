"""Elastic Detection Rules matcher.

Routes by the rule's ``language`` field:
- ``eql``            → eql Python library
- ``kuery`` / ``kql`` → custom KQL evaluator (see ``_kql``)
- ``esql``           → unsupported (deferred to v0.2)

A missing ``language`` defaults to ``kuery`` — the Elastic default — so
rules that omit the field are still evaluated rather than skipped.

Uses tomllib to parse the rule's raw TOML and extract the [rule] block.
"""

from __future__ import annotations

import logging
import tomllib
from typing import Any

import eql

from ...stale.models import DetectionRule
from ..models import FireRecord

log = logging.getLogger(__name__)


class ElasticMatcher:
    """Elastic Detection Rules → JSON event evaluator.

    Supports EQL rules (``language = "eql"``) and KQL/kuery rules (the
    ``_kql`` subset). A missing ``language`` is treated as kuery. ES|QL
    (``esql``) returns ``supports=False`` with a descriptive reason
    (deferred to v0.2).
    """

    def supports(self, rule: DetectionRule) -> bool:
        """Return True for syntactically-valid EQL or supported KQL rules."""
        supports, _ = self.support_reason(rule)
        return supports

    def support_reason(self, rule: DetectionRule) -> tuple[bool, str | None]:
        """Return (supports, reason).

        ``reason`` is None when supported; a human-readable string otherwise.
        """
        if rule.raw_toml is None:
            return False, "Elastic rule missing raw_toml"
        try:
            parsed = tomllib.loads(rule.raw_toml)
        except tomllib.TOMLDecodeError as exc:
            return False, f"Elastic TOML parse error: {exc}"

        rule_block = parsed.get("rule", {})
        # Elastic Detection Rules default to kuery when `language` is omitted.
        language = rule_block.get("language", "").lower() or "kuery"

        if language == "esql":
            return False, "ES|QL matcher deferred to v0.2"
        if language in ("kuery", "kql"):
            from ._kql import KqlUnsupported, parse_kql

            query = rule_block.get("query", "")
            try:
                parse_kql(query)
            except KqlUnsupported as exc:
                return False, f"KQL: {exc}"
            return True, None
        if language != "eql":
            return False, f"Unsupported Elastic language: {language!r}"

        query = rule_block.get("query", "").strip()
        try:
            eql.parse_query(query)
        except Exception as exc:  # noqa: BLE001 — eql raises EqlParseError/EqlSyntaxError etc.
            return False, f"EQL parse error: {exc}"

        return True, None

    def match(
        self,
        rule: DetectionRule,
        events: list[dict[str, Any]],
        dataset_id: str,
        technique_id: str | None = None,
    ) -> list[FireRecord]:
        """Evaluate the rule query against *events* and return fire records.

        Each ``FireRecord.event_index`` is the position (0-based) of the
        **closing event** of the match in the input list — for a simple
        ``where`` query this is the matching event itself; for a sequence
        query it is the last event of the matched sequence.

        Dispatches by ``language``: ``eql`` → EQL engine, ``kuery``/``kql``
        → KQL evaluator, others → empty list.

        Returns an empty list when the rule is not supported or produces no
        matches.
        """
        if not self.supports(rule):
            return []

        assert rule.raw_toml is not None  # guarded by supports()
        tech = technique_id if technique_id is not None else (
            rule.technique_ids[0] if rule.technique_ids else ""
        )
        parsed_toml = tomllib.loads(rule.raw_toml)
        rule_block = parsed_toml.get("rule", {})
        language = rule_block.get("language", "").lower() or "kuery"
        query = rule_block.get("query", "").strip()

        if language == "eql":
            return self._match_eql(rule, query, events, dataset_id, tech)
        if language in ("kuery", "kql"):
            return self._match_kql(rule, query, events, dataset_id, tech)
        log.warning(
            "ElasticMatcher.match() received unsupported language %r for rule %s; "
            "this should have been caught by support_reason().",
            language,
            rule.rule_id or rule.title,
        )
        return []

    def _match_eql(
        self,
        rule: DetectionRule,
        query: str,
        events: list[dict[str, Any]],
        dataset_id: str,
        technique_id: str,
    ) -> list[FireRecord]:
        """Evaluate an EQL query against *events* using the eql Python library."""
        parsed_query = eql.parse_query(query)

        fires: list[FireRecord] = []

        def _on_match(output: eql.AnalyticOutput) -> None:
            # The closing event is the last one in the sequence (or the sole
            # event for a simple where-clause query).
            closing_event = output.events[-1]
            # We stash the original list index in the Event's ``time`` field.
            event_idx: int = closing_event.time
            fires.append(
                FireRecord(
                    rule_id=rule.rule_id or rule.title,
                    technique_id=technique_id,
                    dataset_id=dataset_id,
                    event_index=event_idx,
                )
            )

        engine = eql.PythonEngine()
        engine.add_query(parsed_query)
        engine.add_output_hook(_on_match)

        for idx, evt in enumerate(events):
            # EQL requires an explicit event type as the first positional
            # argument.  We derive it from ``event.category`` (the ECS field
            # used by Elastic Detection Rules) and fall back to "generic".
            event_type = _event_type(evt)
            # NOTE: We overload eql.Event's `time` slot to carry the original
            # list index for recovery in the output hook. Queries that filter
            # on real time fields (e.g., `where @timestamp > "2024-..."`) are
            # not supported in v0.1; the eql engine sees integer indices here.
            engine.stream_event(eql.Event(event_type, idx, evt))

        engine.finalize()
        return fires

    def _match_kql(
        self,
        rule: DetectionRule,
        query: str,
        events: list[dict[str, Any]],
        dataset_id: str,
        technique_id: str,
    ) -> list[FireRecord]:
        """Evaluate a KQL/kuery query against *events* using the custom evaluator."""
        from ._kql import evaluate, parse_kql

        node = parse_kql(query)
        fires: list[FireRecord] = []
        for idx, event in enumerate(events):
            if evaluate(node, event):
                fires.append(
                    FireRecord(
                        rule_id=rule.rule_id or rule.title,
                        technique_id=technique_id,
                        dataset_id=dataset_id,
                        event_index=idx,
                    )
                )
        return fires


def _event_type(event: dict[str, Any]) -> str:
    """Extract the EQL event type from an ECS-shaped event dict.

    Elastic Detection Rules use ``event.category`` as the event type
    (e.g., ``"process"``, ``"network"``, ``"file"``).  Falls back to
    ``"generic"`` when the field is absent or unparseable.

    ECS v8 normalises ``event.category`` as a list of strings (e.g.
    ``["process"]``); older events and some test fixtures use a plain
    string.  Both forms are handled here.
    """
    try:
        category = event["event"]["category"]
    except (KeyError, TypeError):
        return "generic"
    if isinstance(category, list):
        return str(category[0]) if category else "generic"
    if isinstance(category, str):
        return category
    return "generic"
