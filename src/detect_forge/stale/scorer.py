from __future__ import annotations

import logging
import os
from datetime import UTC, date, datetime
from pathlib import Path

from ._semantic import SEMANTIC_THRESHOLD_DEFAULT, score_rule_semantic
from .models import (
    AttackIndex,
    DetectionRule,
    ReportSummary,
    RuleScore,
    SeverityLevel,
    StalenessReport,
    TechniqueFinding,
)

log = logging.getLogger(__name__)

_SEVERITY_ORDER: dict[SeverityLevel, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


def _severity(days_stale: int) -> SeverityLevel:
    if days_stale >= 365:
        return "critical"
    if days_stale >= 180:
        return "high"
    if days_stale >= 90:
        return "medium"
    return "low"


def _score_technique(
    technique_id: str,
    rule_effective_date: date | None,
    index: AttackIndex,
) -> TechniqueFinding:
    # Use UTC date to match technique modified timestamps (stored in UTC).
    today = datetime.now(UTC).date()
    tech = index.techniques.get(technique_id)

    if tech is None:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=None,
            technique_modified=None,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="info",
            kind="unknown_technique",
        )

    if tech.revoked:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="high",
            kind="revoked_technique",
        )

    if tech.deprecated:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="high",
            kind="deprecated_technique",
        )

    technique_date = tech.modified.date()

    if rule_effective_date is None:
        # "We don't know the rule's date" must not be conflated with "the rule
        # is dangerously stale". Emit an informational (non-gating) finding and
        # do NOT derive staleness from the technique's age.
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=None,
            days_stale=0,
            severity="low",
            kind="no_rule_date",
        )

    if rule_effective_date >= technique_date:
        return TechniqueFinding(
            technique_id=technique_id,
            technique_name=tech.name,
            technique_modified=tech.modified,
            rule_effective_date=rule_effective_date,
            days_stale=0,
            severity="low",
            kind="current",
        )

    # Rule predates the technique's last modification: stale.
    # Staleness = how old MITRE's technique info is (bounded by technique_date, not by rule age).
    days_stale = (today - technique_date).days
    return TechniqueFinding(
        technique_id=technique_id,
        technique_name=tech.name,
        technique_modified=tech.modified,
        rule_effective_date=rule_effective_date,
        days_stale=days_stale,
        severity=_severity(days_stale),
        kind="stale",
    )



def score_rule(
    rule: DetectionRule,
    index: AttackIndex,
    *,
    rule_embedding: list[float] | None = None,
    technique_embeddings: dict[str, list[float]] | None = None,
    semantic_threshold: float = SEMANTIC_THRESHOLD_DEFAULT,
) -> RuleScore:
    effective_date = rule.modified_date or rule.rule_date

    if not rule.technique_ids:
        return RuleScore(
            rule_id=rule.rule_id,
            title=rule.title,
            source_file=rule.source_file,
            status=rule.status,
            findings=[],
            worst_severity="info",
            worst_days_stale=0,
            has_attack_tags=False,
        )

    findings: list[TechniqueFinding] = [
        _score_technique(tid, effective_date, index) for tid in rule.technique_ids
    ]

    if technique_embeddings is not None:
        findings.extend(
            score_rule_semantic(
                rule,
                index,
                rule_embedding,
                technique_embeddings,
                threshold=semantic_threshold,
            )
        )

    # Derive both from the same winning finding: severity first, then days_stale for tie-break.
    worst_finding = max(
        findings, key=lambda f: (_SEVERITY_ORDER[f.severity], f.days_stale)
    )

    return RuleScore(
        rule_id=rule.rule_id,
        title=rule.title,
        source_file=rule.source_file,
        status=rule.status,
        findings=findings,
        worst_severity=worst_finding.severity,
        worst_days_stale=worst_finding.days_stale,
        has_attack_tags=True,
    )


def score_rules(
    rules: list[DetectionRule],
    index: AttackIndex,
    *,
    cache_dir: Path | None = None,
    semantic_threshold: float = SEMANTIC_THRESHOLD_DEFAULT,
    llm_model: str | None = None,
    max_proposals: int = 5,
) -> StalenessReport:
    """Score rules against an ATT&CK index.

    Returns a StalenessReport with scores sorted worst-first. If ``cache_dir``
    is provided, this also batches the embedding work for semantic alignment:
    one fastembed call for all techniques (cache-aware), one for all rules
    (cache-aware), then per-rule scoring receives the pre-computed vectors.

    When ``cache_dir`` is None, semantic scoring is skipped — preserves the
    original timestamp-only behavior for callers that haven't migrated.

    When ``llm_model`` is provided AND ``OPENAI_API_KEY`` is set, the scorer
    will additionally attempt to generate a diff proposal for every rule with
    a ``semantic_drift`` finding, up to ``max_proposals`` total per scan. Every
    attempt counts against the quota, regardless of outcome — so the quota is
    a hard cost ceiling.
    """
    rule_emb_map: dict[str, list[float]] | None = None  # keyed by str(source_file)
    tech_emb_map: dict[str, list[float]] | None = None  # keyed by technique_id

    if cache_dir is not None:
        from . import _semantic
        from . import embeddings as emb_mod

        # Collect candidate texts up front so we can short-circuit when there is
        # nothing to embed (empty rule set or empty index) — avoids touching the
        # STIX bundle on disk just to compute a hash that nothing consumes.
        tech_texts: dict[str, str] = {}
        for tid, tech in index.techniques.items():
            text = _semantic._technique_text(tech)
            if text is not None:
                tech_texts[tid] = text

        rule_text_map: dict[str, str] = {}      # source_file str → text
        rule_text_hashes: dict[str, str] = {}   # source_file str → hash
        for r in rules:
            text = _semantic._rule_text(r)
            if text is not None:
                key = str(r.source_file)
                rule_text_map[key] = text
                rule_text_hashes[key] = emb_mod.rule_text_hash(text)

        if tech_texts or rule_text_map:
            # ---- Technique embeddings (per-STIX-bundle cache) ----
            stix_hash = emb_mod.stix_bundle_hash(cache_dir, index.source_domain)
            tech_cache = emb_mod.load_technique_cache(
                cache_dir, emb_mod.MODEL_ID_SLUG, stix_hash
            )
            missing_tech_ids = [tid for tid in tech_texts if tid not in tech_cache]

            # ---- Rule embeddings (persistent cache, keyed by text hash) ----
            rule_cache = emb_mod.load_rule_cache(cache_dir, emb_mod.MODEL_ID_SLUG)
            missing_rule_hashes = [
                h for h in rule_text_hashes.values() if h not in rule_cache
            ]

            # ---- Compute missing embeddings (one model load, two batched calls) ----
            model = None
            if missing_tech_ids or missing_rule_hashes:
                model = emb_mod.EmbeddingModel(cache_dir=cache_dir)

            if missing_tech_ids and model is not None:
                texts = [tech_texts[tid] for tid in missing_tech_ids]
                vecs = model.embed_batch(texts)
                for tid, v in zip(missing_tech_ids, vecs, strict=True):
                    tech_cache[tid] = v
                emb_mod.save_technique_cache(
                    cache_dir, emb_mod.MODEL_ID_SLUG, stix_hash, tech_cache
                )

            if missing_rule_hashes and model is not None:
                unique = list(dict.fromkeys(missing_rule_hashes))  # dedupe, preserve order
                hash_to_text: dict[str, str] = {}
                for key, h in rule_text_hashes.items():
                    if h in unique and h not in hash_to_text:
                        hash_to_text[h] = rule_text_map[key]
                texts = [hash_to_text[h] for h in unique]
                vecs = model.embed_batch(texts)
                for h, v in zip(unique, vecs, strict=True):
                    rule_cache[h] = v
                emb_mod.save_rule_cache(cache_dir, emb_mod.MODEL_ID_SLUG, rule_cache)

            tech_emb_map = tech_cache
            rule_emb_map = {
                str(r.source_file): rule_cache[rule_text_hashes[str(r.source_file)]]
                for r in rules
                if str(r.source_file) in rule_text_hashes
            }

    # ---- Score each rule, injecting its embedding if available ----
    scores: list[RuleScore] = []
    for r in rules:
        rule_vec = rule_emb_map.get(str(r.source_file)) if rule_emb_map else None
        scores.append(
            score_rule(
                r,
                index,
                rule_embedding=rule_vec,
                technique_embeddings=tech_emb_map,
                semantic_threshold=semantic_threshold,
            )
        )

    # ---- LLM diff proposals (Phase 4) ----
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key and llm_model is not None and max_proposals > 0:
        from . import _proposals as proposals_mod

        today_str = datetime.now(UTC).date().strftime("%Y/%m/%d")
        proposals_remaining = max_proposals
        rule_by_source: dict[str, DetectionRule] = {
            str(r.source_file): r for r in rules
        }
        for score in scores:
            if proposals_remaining <= 0:
                break
            drift_findings = [f for f in score.findings if f.kind == "semantic_drift"]
            if not drift_findings:
                continue
            drift = min(
                drift_findings,
                key=lambda f: f.similarity_score if f.similarity_score is not None else 1.0,
            )
            rule = rule_by_source.get(str(score.source_file))
            if rule is None:
                continue
            technique = index.techniques.get(drift.technique_id)
            if technique is None or technique.description is None:
                continue
            try:
                original_text = rule.source_file.read_text(encoding="utf-8")
            except OSError as exc:
                log.debug("Cannot read rule file %s for proposal: %s", rule.source_file, exc)
                continue
            original_format = (
                "elastic" if rule.source_file.suffix.lower() == ".toml" else "sigma"
            )
            proposal = proposals_mod.generate_proposal(
                rule=rule,
                original_rule_text=original_text,
                original_format=original_format,
                technique_id=drift.technique_id,
                technique_name=drift.technique_name or "",
                technique_description=technique.description,
                similarity_score=drift.similarity_score or 0.0,
                threshold=semantic_threshold,
                llm_model=llm_model,
                api_key=api_key,
                today=today_str,
            )
            proposals_remaining -= 1  # every attempt counts against the quota
            if proposal is None:
                continue
            if not proposals_mod.validate_proposed_rule(
                proposal.proposed_rule, original_format
            ):
                log.debug("Skipping invalid proposal for %s", rule.source_file)
                continue
            score.proposals.append(proposal)

    scores.sort(
        key=lambda s: (_SEVERITY_ORDER[s.worst_severity], s.worst_days_stale),
        reverse=True,
    )

    def _count(sev: SeverityLevel) -> int:
        return sum(1 for s in scores if s.worst_severity == sev)

    summary = ReportSummary(
        total_rules=len(rules),
        rules_with_findings=sum(
            1 for s in scores if s.worst_severity != "low" or not s.has_attack_tags
        ),
        critical=_count("critical"),
        high=_count("high"),
        medium=_count("medium"),
        low=_count("low"),
        no_attack_tags=sum(1 for s in scores if not s.has_attack_tags),
        unknown_techniques=sum(
            1 for s in scores for f in s.findings if f.kind == "unknown_technique"
        ),
        deprecated_techniques=sum(
            1 for s in scores for f in s.findings if f.kind == "deprecated_technique"
        ),
        revoked_techniques=sum(
            1 for s in scores for f in s.findings if f.kind == "revoked_technique"
        ),
        generated_at=datetime.now(UTC),
        attack_domain=index.source_domain,
        attack_fetched_at=index.fetched_at,
    )

    return StalenessReport(summary=summary, scores=scores)
