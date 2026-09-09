# Changelog

All notable changes to Detect-Forge are documented here. The format is based
on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.1] - 2026-09-09

Backtest hotfix — the bundled corpus was unusable against the live
Security-Datasets repo.

### Fixed
- `backtest` now parses JSON Lines datasets (the real Security-Datasets
  on-disk format, one event per line). The loader previously assumed a JSON
  array and failed every real dataset with "Extra data", silently reporting
  all rules as `untested`.
- Pruned the bundled Mordor index to the datasets that are still live upstream
  (14 of 16 URLs had 404'd) and populated their real SHA256 hashes, so
  integrity is verified and runs no longer emit 404 warnings.

## [0.1.0] - 2026-09-09

Initial public release.

### Added
- `stale` — score Sigma/Elastic rules for ATT&CK technique staleness
  (timestamp drift, semantic drift, opt-in LLM diff proposals).
- `coverage` — map rules to the ATT&CK matrix (full/shallow/gap) with
  CTID-weighted priority gating and Navigator export.
- `backtest` — adversarial replay against the bundled Mordor corpus with
  Sigma + Elastic (EQL/KQL) matchers and two CI gates.
- `audit` — one-step composite gate over stale + coverage + backtest.
- `cti ingest` registered as a stub (Q3–Q4 2026).

### Fixed
- Sigma matcher correctness: plain-value wildcards, `all/1/N of them`,
  case-insensitive matching, int/str coercion, list-valued fields, `field: null`.
- Backtest security: SHA256 verified before extraction, decompression size
  caps, local-source path sanitization.
- Stale: undated rules no longer false-gate as critical; malformed tags/threat
  no longer abort the scan; threshold range validation.
- Coverage/audit: empty/mistyped priority list is a loud error; sub-technique
  coverage rolls up to parents; audit honors per-subcommand config + gate flags.

[Unreleased]: https://github.com/jamesbower/Detect-Forge/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/jamesbower/Detect-Forge/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/jamesbower/Detect-Forge/releases/tag/v0.1.0
