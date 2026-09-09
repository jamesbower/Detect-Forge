# Detect-Forge

AI-Native Detection engineering toolkit. One install, one config, one CI step.

## Overview

Detect-Forge is a composable CLI for detection engineers. Each capability is a subcommand; they share configuration, output formatting, caching, and a single CI gate. No platform, no sign-up.

The first shipping capability is `stale` — it scores your Sigma (YAML) and Elastic Detection Rules (TOML — covering EQL, KQL, and ESQL) for ATT&CK technique staleness along three dimensions:

1. **Timestamp drift** — compares ATT&CK STIX `modified` timestamps to rule modification dates (deterministic).
2. **Semantic alignment** ✅ — embeddings-based cosine similarity between rule text (title + description) and current ATT&CK technique description. Flags rules whose alignment falls below a configurable threshold (`--semantic-threshold`, default 0.65). True historical drift (comparing against past MITRE definitions) is Phase 3.b.
3. **LLM diff proposals** ✅ — opt-in, BYOLLM via OpenAI structured output; proposes rewritten rules for `semantic_drift` findings. Never auto-applied — every proposal is reviewed manually. Anthropic Claude support deferred to v0.2.

Designed to run in GitHub Actions as a CI gate. No data leaves your environment.

## Status

🚀 June 8, 2026 — `audit` ships: composes stale + coverage + backtest into a single CI step with strict-AND gate semantics, three per-dimension scores, and a unified report in terminal/json/html.

🚀 May 29, 2026 — `backtest` ships with adversarial replay against bundled Mordor (Security-Datasets) corpus, Sigma matcher (selections + modifiers + correlations), Elastic matcher (EQL via `eql` Python lib + custom KQL evaluator), four output formats including ATT&CK Navigator layer JSON, and two CI gates (priority silence + broken rules).

🚀 May 23, 2026 launch — `stale` ships with all three scoring dimensions: timestamp drift, semantic drift (Phase 3.a), and LLM diff proposals (Phase 4). True historical drift (Phase 3.b) deferred to v0.2. `coverage` ships with full/shallow/gap analysis, CTID-weighted priority gating, and ATT&CK Navigator export. Remaining subcommands (`cti ingest`, `audit`) are registered as stubs.

## Requirements

- Python **3.12** or newer

## Install

```bash
# Requires Python 3.12+ — use python3.12 explicitly, or any python3 that is >= 3.12
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Usage

```bash
detect-forge --help
detect-forge --version
detect-forge stale path/to/rules
```

### Subcommands

| Command | Status | Description |
|---|---|---|
| `stale` | ✅ Available | Score detection rules for ATT&CK technique staleness. |
| `backtest` | ✅ Available | Adversarial replay (Types 3 + 4). |
| `coverage` | ✅ Available | Coverage gap mapping (Type 6a expansion). |
| `cti ingest` | 📝 Q3–Q4 2026 | CTI-to-detection generation. |
| `audit` | ✅ Available | Runs every check (stale + coverage + backtest) in one step. |

### `stale` options

| Option | Default | Description |
|---|---|---|
| `RULE_DIR` (positional) | — | Directory of detection rules to scan. Recursively picks up `.yml`/`.yaml` (Sigma) and `.toml` (Elastic Detection Rules: EQL/KQL/ESQL). Must exist. |
| `--format {terminal,json,html}` | `terminal` | Output format. |
| `-o, --output PATH` | _stdout_ | Write output to a file instead of stdout. |
| `--min-severity {info,low,medium,high,critical}` | `low` | Only show rules at or above this severity. `info` surfaces no-ATT&CK-tag and unknown-technique findings. |
| `--no-cache` | off | Bypass the disk cache and fetch a fresh ATT&CK bundle. |
| `--domain {enterprise-attack,ics-attack,mobile-attack}` | `enterprise-attack` | ATT&CK domain to fetch. |
| `--semantic-threshold FLOAT` | `0.65` | Cosine similarity threshold; pairs below this value emit a `semantic_drift` finding. |

Supported rule formats are auto-detected by extension. `.yml`/`.yaml` files are parsed as Sigma rules; `.toml` files are parsed as Elastic Detection Rules. The Elastic schema covers EQL, KQL (kuery), and ESQL — they share the same TOML structure and only differ in the `language` field.

### How alignment is scored

Each rule is embedded as `title + description` (the natural-language portion — the detection-query body is NOT embedded, since query languages don't align well with general-purpose text embeddings). Each ATT&CK technique is embedded as `name + description` from the STIX bundle. For every technique a rule tags, we compute the cosine similarity between the two vectors; pairs whose score falls strictly below `--semantic-threshold` (default `0.65`) emit a `semantic_drift` finding at `medium` severity, with the score visible in the `Similarity` column of the report.

Embeddings are computed once with [`fastembed`](https://github.com/qdrant/fastembed) (model `BAAI/bge-small-en-v1.5`, ~30MB, auto-downloaded on first run) and cached under `$CACHE_DIR/embeddings/`. Subsequent runs read from cache. There is no `--no-semantic` flag: warm-cache cost is near-zero, and cold-cache work has to happen at least once anyway.

#### Similarity score reference

| Similarity | What it means |
|---|---|
| < 0.50 | Major concept divergence — rule and technique are describing different things |
| 0.50–0.70 | Significant drift — technique has evolved substantially |
| 0.70–0.85 | Moderate drift — wording changes, some behavioral shifts |
| > 0.85 | Minor or no drift |

The default trigger (`semantic_threshold = 0.65`) catches rules with significant or major drift — meaningful divergence that warrants attention, not just a flag.

Progress spinners go to **stderr**; the report goes to **stdout** so JSON output can be piped safely:

```bash
detect-forge stale path/to/rules --format json | jq '.scores'
detect-forge stale path/to/rules --format json -o report.json
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed; no gating findings (CI passes). |
| `1` | Tool error, stub command, or unimplemented capability. |
| `2` | CI-gating condition met (e.g. `stale` found a critical finding). |

Use exit-code `2` to fail your CI pipeline:

```bash
detect-forge stale path/to/rules
code=$?
if [ "$code" -eq 2 ]; then exit 2; fi
```

### Environment variables

All settings can be overridden via `DETECT_FORGE_`-prefixed env vars (or a `.env` file in the working directory). Copy `.env.sample` at the repo root to `.env` to get started.

| Variable | Default | Purpose |
|---|---|---|
| `DETECT_FORGE_CACHE_DIR` | `$XDG_CACHE_HOME/detect-forge` (or `~/.cache/detect-forge`) | Where the ATT&CK bundle is cached. |
| `DETECT_FORGE_CACHE_TTL_HOURS` | `24` | Cache lifetime in hours. |
| `DETECT_FORGE_ATTACK_DOMAIN` | `enterprise-attack` | Default `--domain` value. |
| `DETECT_FORGE_NO_CACHE` | `false` | If truthy, always bypass the cache. |
| `DETECT_FORGE_SEMANTIC_THRESHOLD` | unset | Overrides `semantic_threshold` from `.detect-forge.toml` and the CLI flag (highest precedence). |
| `OPENAI_API_KEY` | unset | Required to enable LLM diff proposals. When unset, scans complete normally and print a skip banner. |

### LLM Diff Proposals (Phase 4)

When a rule emits a `semantic_drift` finding, `stale` can optionally call OpenAI's structured-output API to propose a rewritten rule aligned with the current ATT&CK technique. Proposals are **BYOLLM** and **never auto-applied** — the practitioner reviews every suggestion and manually decides what to keep.

#### Enabling

Set `OPENAI_API_KEY` in your environment. Without it, the scan completes normally and prints `💡 LLM diff proposals skipped` at the end of the report.

```bash
export OPENAI_API_KEY=sk-...
detect-forge stale ./rules
```

#### Configuration via `.detect-forge.toml`

LLM proposal settings live in `.detect-forge.toml` (discovered upward from your CWD, halting at the git root). There are no CLI flags for these. A starter `.detect-forge.toml` with the defaults ships at the repo root — edit in place or copy to your own project.

```toml
[stale]
semantic_threshold = 0.65   # Cosine similarity floor; pairs below trigger a proposal
llm_model = "gpt-4o-mini"   # Any OpenAI chat-completion model that supports structured outputs
max_proposals = 5           # Hard ceiling on LLM calls per scan run (cost guard)
```

`max_proposals` is your primary cost lever — every proposal attempt (success, refusal, or validation rejection) counts against this quota.

#### Cost

At default settings (`gpt-4o-mini`, 5 proposals): well under $0.01 per scan. Roughly $0.0005 per proposal. The `max_proposals` setting is your hard cost ceiling.

#### What proposals look like

For each candidate rule, you get a terminal panel with the rule filename, the model's confidence (0–1), the list of fields it changed, a brief explanation, and the rewritten rule body in syntax-highlighted YAML (Sigma) or TOML (Elastic). The HTML report adds a "LLM Proposals" section at the bottom with color-coded confidence badges.

#### What proposals don't do

- They never modify your rules on disk. Apply changes manually after review.
- They don't run if `OPENAI_API_KEY` is unset.
- They use only the rule's natural-language fields and your current ATT&CK technique description — no telemetry leaves your environment beyond the OpenAI API call.
- They're not a substitute for human review. The model's `confidence` field is self-reported and unreliable — treat every proposal as a draft.

### Coverage gap analysis

`detect-forge coverage` maps your detection rule corpus to the ATT&CK matrix and reports which techniques have full, shallow, or no coverage. Priority techniques (by default, a CTID-style top-25 list) drive CI gating.

#### Quick start

```bash
detect-forge coverage ./rules
detect-forge coverage ./rules --format html --output coverage.html
detect-forge coverage ./rules --format navigator --output layer.json
```

The Navigator JSON output drops directly into https://mitre-attack.github.io/attack-navigator/ for a heatmap view.

#### Coverage states

| State | Meaning |
|---|---|
| **full** | At least one rule is tagged with this exact technique ID. |
| **shallow** | Covered only indirectly — either the parent is tagged and this sub is inferred (rule tags `T1059`; sub `T1059.001` is shallow), or a sub is tagged and its parent is inferred (rule tags `T1059.001`; parent `T1059` is shallow). |
| **gap** | No rules reference this technique or any of its sub-techniques. |

#### Configuration

Settings live in `.detect-forge.toml` `[coverage]`. A starter section ships at the repo root.

```toml
[coverage]
priority_list = ""              # path to custom JSON; empty = built-in CTID default
gate_on_priority_gaps = true    # exit 2 when priority techniques have no rules
```

#### Custom priority list

Drop a JSON file with your own technique IDs (industry threat model, internal red-team priorities, etc.):

```json
{
  "name": "Acme Corp Priorities 2026",
  "technique_ids": ["T1078", "T1190", "T1059.001", "T1486"]
}
```

Point at it via `[coverage] priority_list = "/path/to/list.json"` or `--priority-list /path/to/list.json` for a one-off scan.

#### CI gating

When any priority-list technique has gap status (no rules at all), the command exits with code 2. Suppress with `--no-gate` for informational scans, or set `gate_on_priority_gaps = false` in config for permanent off.

#### What coverage does NOT do (v0.1)

- No coverage diff over time — that's git-for-coverage, deferred to v0.2.
- No threat-intel weighting from `cti ingest` — composes with that subcommand when it ships.
- No per-rule-status filtering (e.g. count only `status: stable` rules).
- No rule-quality weighting (untested rule = same weight as a battle-tested one).

### Backtest (Roberts Types 3+4 replay)

`detect-forge backtest` replays your detection rules against bundled Mordor (Security-Datasets) samples to see which rules actually fire, which are silent on tested datasets, and which target techniques with no data at all.

#### Quick start

```bash
detect-forge backtest ./rules
detect-forge backtest ./rules --format json -o report.json
detect-forge backtest ./rules --format html -o report.html
detect-forge backtest ./rules --format navigator -o layer.json
```

The Navigator JSON output drops directly into https://mitre-attack.github.io/attack-navigator/ for a heatmap view coloured by fire status.

#### Fire status model (per dataset)

| Status | Meaning |
|---|---|
| **verified** | At least one event from this dataset matched the rule's detection logic. |
| **silent** | Dataset was loaded and evaluated; rule produced zero matches. |
| **untested** | No dataset found for this technique in the bundled Mordor index. |
| **unsupported** | Rule format or query language not supported by any matcher. |

#### Per-rule status model

| Status | Meaning |
|---|---|
| **fires** | Rule fired on at least one dataset across all targeted techniques. |
| **partial** | Rule fired on some datasets but was silent on others. |
| **silent_on_all** | Rule was evaluated against ≥1 dataset and produced zero matches everywhere. |
| **untested** | All targeted techniques had no Mordor data available. |
| **unsupported** | No matcher could handle this rule's format/language. |

#### Configuration (`.detect-forge.toml [backtest]`)

```toml
[backtest]
gate_on_priority_silence = true   # exit 2 when priority technique is silent
gate_on_broken_rules = true       # exit 2 when any rule is silent on all tested datasets
mordor_source = ""                # local Security-Datasets checkout; empty = fetch
platform = "all"                  # windows | linux | macos | all
```

#### Custom priority list

Backtest reuses the same priority list format as `coverage`. Point at it via `[coverage] priority_list` or `--priority-list` — see the [Custom priority list](#custom-priority-list) section under Coverage.

#### CI gating semantics

Two independent gates can fail the CI pipeline (exit code `2`):

- **Priority silence gate** (`gate_on_priority_silence`): triggers when a priority-list technique has at least one rule tagged to it, but none of those rules fire on any Mordor dataset. The technique is covered on paper but silent in replay — a signal worth investigating.
- **Broken-rules gate** (`gate_on_broken_rules`): triggers when any rule is evaluated against at least one dataset and produces zero matches across all of them (`silent_on_all` status). These rules are candidates for revision or retirement.

Both gates can be suppressed together with `--no-gate` for informational scans, or independently via config.

#### Mordor source override

By default, datasets are fetched from GitHub (Security-Datasets) on first use and cached locally. For airgapped environments or a local clone:

```bash
detect-forge backtest ./rules --mordor-source /path/to/Security-Datasets
```

Or set `mordor_source = "/path/to/Security-Datasets"` in `.detect-forge.toml`.

#### Platform filter

Limit evaluation to datasets matching a specific platform:

```bash
detect-forge backtest ./rules --platform windows
detect-forge backtest ./rules --platform linux
```

Default is `all`. Available values: `windows`, `linux`, `macos`, `all`.

#### Technique filter

Restrict the scan to specific techniques (useful for targeted triage):

```bash
detect-forge backtest ./rules --techniques T1059.001,T1078
```

#### What backtest does NOT do (v0.1)

- No ES|QL matcher — deferred to v0.2.
- No Sigma `|cidr`, `|gt`, `|lt`, `|gte`, `|lte` modifiers.
- No Sigma `keywords` (unfielded search).
- No Mordor `compound/` datasets (multi-technique chains).
- No per-rule TP/FP/FN matrix.
- No backtest → coverage `verified` state integration.
- No sandbox / execute mode (replay-only — no live detonation).
- No detection latency / time-to-fire metrics.

### Audit (one-step CI gate)

`detect-forge audit` runs `stale` + `coverage` + `backtest` sequentially in a single
Python session and emits a unified report. Honors the "One install, one config, one
CI step" tagline:

```bash
detect-forge audit ./rules
```

#### Quick start (all formats)

```bash
detect-forge audit ./rules                                # terminal
detect-forge audit ./rules --format json -o audit.json
detect-forge audit ./rules --format html -o audit.html
```

Navigator output is NOT supported in v0.1 — run `coverage` or `backtest` directly
for technique heatmaps.

#### Three per-dimension scores

The header surfaces three percentages (0–100, no composite):

- **Stale health** = `100 × (total_rules − critical) / total_rules`
- **Coverage completeness** = `100 × full / total_techniques`
- **Backtest verification rate** = `100 × rules_fires / (rules_parsed − rules_unsupported)`

Each score is `null` when the corresponding subcommand was skipped or errored.

#### Strict-AND gate semantics

The audit gate fires (exit code 2) only when **every enabled subcommand** would have
gated standalone. This is intentionally permissive — fine-grained signal is best
served by running each subcommand directly. Audit's gate is the "everything is
broken" alarm.

Override with `--no-gate` or set `[audit].gate_strategy = "never"` in config for
informational mode (always exit 0/1).

#### CI exit codes

| Code | Meaning |
|---|---|
| `0` | Clean OR audit gate didn't fire |
| `1` | At least one subcommand crashed (tool error) |
| `2` | Audit gate fired |

#### Configuration (`.detect-forge.toml [audit]`)

```toml
[audit]
gate_strategy = "all"             # "all" | "never"
subcommands = ["stale", "coverage", "backtest"]  # subset to run
include_llm_proposals = false     # cost gate
```

The existing `[stale]`, `[coverage]`, `[backtest]` sections continue to drive each
subcommand's own config (semantic threshold, priority list path, mordor source,
etc.). Audit just composes — it doesn't override per-subcommand config.

#### Skip a subcommand for incremental adoption

```bash
detect-forge audit ./rules --skip stale --skip backtest   # only coverage
```

CLI `--skip` is subtractive from `[audit].subcommands`. If your config disables a
subcommand and you `--skip` another, the effective set is the intersection.

#### LLM proposals are off by default

The `stale` subcommand's LLM diff proposals are skipped in audit mode unless you
opt in via `--with-llm-proposals` or `[audit].include_llm_proposals = true`. This
is a cost gate — every proposal call costs ~$0.0005 (defaults).

#### What audit does NOT do (v0.1)

- Doesn't merge findings across subcommands (no "verified" coverage state from
  backtest, etc.)
- Doesn't run subcommands in parallel
- Doesn't emit a Navigator layer
- Doesn't diff against a prior baseline
- Doesn't propagate per-subcommand exit codes (audit summarizes; run subcommands
  directly if you need their individual exit codes)

## Python API

Each subcommand exposes a programmatic API for power users:

```python
from pathlib import Path
from detect_forge.stale import scan

report = scan(Path("./rules"), domain="enterprise-attack")
for score in report.scores:
    if score.worst_severity == "critical":
        print(f"{score.title}: {score.worst_days_stale} days stale")
```

## Development

```bash
pytest -q                     # run the test suite
ruff check src/ tests/        # lint
mypy src/                     # type-check (strict)
```

The package layout:

```
src/detect_forge/
├── cli.py              # click root group; registers all subcommands
├── settings.py         # DETECT_FORGE_* pydantic-settings config
├── console.py          # rich stdout + stderr consoles
├── cache.py            # XDG-aware cache (default_cache_dir() factory)
├── common.py           # @common_output_options decorator
├── exit_codes.py       # CLEAN=0, RESERVED=1, GATED=2
├── _stubs.py           # stub_command() helper
├── stale/              # the staleness pipeline (real subcommand)
├── backtest/           # adversarial replay (real subcommand)
├── coverage/           # ATT&CK coverage mapping (real subcommand)
├── cti/                # group + ingest stub (not yet implemented)
└── audit/              # one-step composite gate (real subcommand)
```

## License

MIT

---
 
## Stay in the loop
 
- 📧 **Newsletter** — subscribers get each tool's GitHub link 24 hours
  before public launch → [Subscribe](https://james-bower.kit.com/newsletter)
- 🎮 **Discord — Machine Learning in Security**
  → [Join](https://james-bower.kit.com/mlsecdiscord)
- 📝 **Deep dives on the design** → [jamesbower.com](https://jamesbower.com)
---
 
> Built by [James Bower](https://jamesbower.com) · ML cybersec with a
> quant finance edge · [Newsletter](https://james-bower.kit.com/newsletter)
> · [Discord](https://james-bower.kit.com/mlsecdiscord)
