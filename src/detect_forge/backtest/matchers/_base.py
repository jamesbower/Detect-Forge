"""Matcher protocol and format-detection helper.

Each matcher is stateless: given a parsed rule and a JSON event list, return
the rule's fire records for that event sequence. Per-rule capability is
expressed via ``supports()``; rules the matcher can't evaluate route through
the ``unsupported`` status path with a reason string.
"""

from __future__ import annotations

from typing import Any, Literal, Protocol

from ...stale.models import DetectionRule
from ..models import FireRecord


class Matcher(Protocol):
    """Stateless matcher protocol."""

    def supports(self, rule: DetectionRule) -> bool:
        """Can this matcher evaluate this rule? False → status='unsupported'."""
        ...

    def support_reason(self, rule: DetectionRule) -> tuple[bool, str | None]:
        """Returns (supports, reason). Reason populated when supports=False
        (e.g., 'Sigma correlation', 'ES|QL', 'uses |cidr modifier')."""
        ...

    def match(
        self,
        rule: DetectionRule,
        events: list[dict[str, Any]],
        dataset_id: str,
        technique_id: str | None = None,
    ) -> list[FireRecord]:
        """Return fire records for this rule against this dataset's events.

        ``technique_id`` is the technique the orchestrator is currently
        evaluating; fires are stamped with it (falling back to the rule's
        first tagged technique when omitted). Caller truncates per-pair to 20.
        """
        ...


def select_matcher(
    rule: DetectionRule,
) -> tuple[Matcher | None, Literal["sigma", "elastic"]]:
    """Pick a matcher based on the rule's source-file suffix.

    Returns (None, 'sigma') for unknown formats; the orchestrator surfaces
    those as ``unsupported``. Imports are deferred to avoid module-load
    cycles between this base and the concrete matcher implementations.
    """
    suffix = rule.source_file.suffix.lower()
    if suffix == ".toml":
        from .elastic import ElasticMatcher

        return ElasticMatcher(), "elastic"
    if suffix in (".yml", ".yaml"):
        from .sigma import SigmaMatcher

        return SigmaMatcher(), "sigma"
    return None, "sigma"
