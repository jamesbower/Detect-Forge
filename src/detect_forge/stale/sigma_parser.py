from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import ValidationError

from ._dates import _parse_rule_date
from .models import DetectionRule

log = logging.getLogger(__name__)

# Matches technique IDs: "attack." + "t" + 4 digits, optionally followed by ".<3 digits>".
_TECHNIQUE_PATTERN = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def _extract_technique_ids(tags: Sequence[object]) -> list[str]:
    """Return normalised ATT&CK technique IDs from a Sigma tags list.

    Skips tactics, groups, software refs, non-ATT&CK namespaces, and any
    non-string values (YAML can yield ints or bools for malformed tags).
    The output is uppercase dot-notation (e.g. "T1059.001") preserving
    source order.
    """
    ids: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        m = _TECHNIQUE_PATTERN.match(tag.strip())
        if m:
            ids.append(m.group(1).upper())
    return ids


def parse_rule_file(path: Path) -> DetectionRule | None:
    """Parse a single Sigma YAML rule file.

    Returns None if the file can't be read, isn't valid YAML, isn't a YAML dict,
    or fails DetectionRule validation.
    """
    try:
        text = path.read_text(encoding="utf-8")
        raw = yaml.safe_load(text)
    except (yaml.YAMLError, OSError) as exc:
        log.warning("Failed to read %s: %s", path, exc)
        return None

    if not isinstance(raw, dict):
        log.debug("Skipping non-dict YAML in %s", path)
        return None

    try:
        raw_tags_value = raw.get("tags")
        # A malformed `tags:` (scalar, mapping, ...) must not abort the scan —
        # treat anything that isn't a list as "no tags".
        tags: list[object] = raw_tags_value if isinstance(raw_tags_value, list) else []
        technique_ids = _extract_technique_ids(tags)
        # raw_tags is typed list[str]; keep scalar tags (stringified), drop
        # containers, so one non-string tag can't discard an otherwise-valid rule.
        safe_tags = [str(t) for t in tags if isinstance(t, (str, int, float, bool))]

        return DetectionRule(
            rule_id=raw.get("id"),
            title=raw.get("title", path.stem),
            description=raw.get("description"),
            status=raw.get("status"),
            rule_date=_parse_rule_date(raw.get("date")),
            modified_date=_parse_rule_date(raw.get("modified")),
            technique_ids=technique_ids,
            source_file=path.resolve(),
            raw_tags=safe_tags,
            raw_yaml=text,
        )
    except (ValidationError, TypeError, ValueError, AttributeError) as exc:
        log.warning("Skipping malformed Sigma rule %s: %s", path, exc)
        return None
