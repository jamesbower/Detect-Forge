from __future__ import annotations

import logging
import tomllib
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from ._dates import _parse_rule_date
from .models import DetectionRule

log = logging.getLogger(__name__)


def _extract_elastic_technique_ids(threats: list[Any]) -> list[str]:
    """Walk ``rule.threat[].technique[].id`` (and each ``subtechnique[].id``).

    Output is uppercase, preserving source order. Skips any entry that
    isn't a dict, or whose ``id`` isn't a string beginning with ``T``.
    """
    ids: list[str] = []
    for entry in threats:
        if not isinstance(entry, dict):
            continue
        techniques = entry.get("technique", []) or []
        if not isinstance(techniques, list):
            continue
        for tech in techniques:
            if not isinstance(tech, dict):
                continue
            tech_id = tech.get("id")
            if isinstance(tech_id, str) and tech_id.upper().startswith("T"):
                ids.append(tech_id.upper())
            subtechniques = tech.get("subtechnique", []) or []
            if not isinstance(subtechniques, list):
                continue
            for sub in subtechniques:
                if not isinstance(sub, dict):
                    continue
                sub_id = sub.get("id")
                if isinstance(sub_id, str) and sub_id.upper().startswith("T"):
                    ids.append(sub_id.upper())
    return ids


def parse_rule_file(path: Path) -> DetectionRule | None:
    """Parse a single Elastic Detection Rules TOML file.

    Returns None if the file can't be read, isn't valid TOML, isn't a TOML
    table at the top level, or fails DetectionRule validation. Covers EQL,
    KQL (kuery), and ESQL languages — they share the same schema and only
    differ in the ``rule.language`` / ``rule.type`` fields, which this
    parser doesn't read.
    """
    try:
        text = path.read_text(encoding="utf-8")
        raw = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, OSError) as exc:
        log.warning("Failed to read %s: %s", path, exc)
        return None

    if not isinstance(raw, dict):
        log.debug("Skipping non-dict TOML in %s", path)
        return None

    metadata = raw.get("metadata") or {}
    rule = raw.get("rule") or {}
    if not isinstance(metadata, dict):
        metadata = {}
    if not isinstance(rule, dict):
        rule = {}

    try:
        # A malformed `threat` (scalar, ...) must not abort the scan.
        threat_value = rule.get("threat", [])
        threats = threat_value if isinstance(threat_value, list) else []
        technique_ids = _extract_elastic_technique_ids(threats)

        return DetectionRule(
            rule_id=rule.get("rule_id"),
            title=rule.get("name", path.stem),
            description=rule.get("description"),
            status=metadata.get("maturity"),
            rule_date=_parse_rule_date(metadata.get("creation_date")),
            modified_date=_parse_rule_date(metadata.get("updated_date")),
            technique_ids=technique_ids,
            source_file=path.resolve(),
            raw_tags=[],
            raw_toml=text,
        )
    except (ValidationError, TypeError, ValueError, AttributeError) as exc:
        log.warning("Skipping malformed Elastic rule %s: %s", path, exc)
        return None
