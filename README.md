# Detect-Forge

[![PyPI](https://img.shields.io/pypi/v/detect-forge.svg)](https://pypi.org/project/detect-forge/)
[![CI](https://github.com/jamesbower/Detect-Forge/actions/workflows/ci.yml/badge.svg)](https://github.com/jamesbower/Detect-Forge/actions/workflows/ci.yml)

**AI-native detection-engineering toolkit. One install, one config, one CI step.**

Detect-Forge scores, maps, and stress-tests your Sigma (YAML) and Elastic (TOML) detection
rules against MITRE ATT&CK — then fails your CI when something needs attention. No platform,
no sign-up, no data leaves your environment.

```bash
pip install detect-forge
detect-forge audit ./rules      # run every check in one gate
```

## What it does

| Command | What it checks | Try it |
|---|---|---|
| `stale` | Rules drifting from current ATT&CK — by timestamp, by meaning (embeddings), with optional LLM rewrite suggestions | `detect-forge stale ./rules` |
| `coverage` | Which ATT&CK techniques your rules cover (full / shallow / gap) | `detect-forge coverage ./rules` |
| `backtest` | Which rules actually **fire** when replayed against real attack telemetry | `detect-forge backtest ./rules` |
| `audit` | All of the above in a single run + unified report | `detect-forge audit ./rules` |
| `cti ingest` | CTI-report → detection generation _(coming Q3–Q4 2026)_ | — |

Rules are auto-detected by extension: `.yml`/`.yaml` → Sigma, `.toml` → Elastic (EQL/KQL/ESQL).
Every command takes `--format {terminal,json,html}` (`coverage` and `backtest` also export
`--format navigator` for the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/))
and `-o/--output PATH`. The report goes to **stdout**, progress to **stderr**, so JSON pipes cleanly:

```bash
detect-forge stale ./rules --format json | jq '.scores'
```

## Built for CI

Every command shares one exit-code contract, so a single step gates your pipeline:

| Code | Meaning |
|---|---|
| `0` | Clean — no gating findings |
| `1` | Tool error |
| `2` | A CI gate fired (e.g. a critical staleness finding, a priority coverage gap, a silent priority technique) |

```yaml
# .github/workflows/detections.yml
- run: pip install detect-forge
- run: detect-forge audit ./rules   # non-zero exit fails the job
```

Gates are on by default and can be relaxed per command with `--no-gate` or in config.

## Configuration

Optional. Settings resolve from a `.detect-forge.toml` (discovered upward from your CWD to the
git root), overridable by `DETECT_FORGE_*` env vars or a local `.env`. A starter config and
`.env.sample` ship in the repo root.

```toml
[stale]
semantic_threshold = 0.65   # cosine floor; pairs below flag as semantic_drift
llm_model = "gpt-4o-mini"   # OpenAI model for opt-in rewrite proposals
max_proposals = 5           # hard cap on LLM calls per run (cost guard)

[coverage]
priority_list = ""          # custom priority-technique JSON; empty = built-in CTID top-25
gate_on_priority_gaps = true

[backtest]
gate_on_priority_silence = true
gate_on_broken_rules = true
platform = "all"            # windows | linux | macos | all
mordor_source = ""          # local Security-Datasets checkout; empty = fetch on demand

[audit]
gate_strategy = "all"       # "all" = fire only if every enabled check would gate; "never" = off
subcommands = ["stale", "coverage", "backtest"]
```

Common env vars: `DETECT_FORGE_CACHE_DIR`, `DETECT_FORGE_CACHE_TTL_HOURS`,
`DETECT_FORGE_ATTACK_DOMAIN`, `DETECT_FORGE_NO_CACHE`, `DETECT_FORGE_SEMANTIC_THRESHOLD`, and
`OPENAI_API_KEY` (enables LLM proposals; without it, scans run normally and print a skip banner).

## Python API

Each subcommand has a programmatic entry point:

```python
from pathlib import Path
from detect_forge.stale import scan

report = scan(Path("./rules"), domain="enterprise-attack")
for score in report.scores:
    if score.worst_severity == "critical":
        print(f"{score.title}: {score.worst_days_stale} days stale")
```

## Reference

<details>
<summary><b>stale</b> — how staleness is scored</summary>

Three dimensions, worst wins:

- **Timestamp drift** — compares each rule's date to the ATT&CK STIX `modified` date of the
  techniques it tags. Undated rules are informational, never gating.
- **Semantic drift** — cosine similarity between the rule's `title + description` and the
  technique's `name + description`, embedded once with [`fastembed`](https://github.com/qdrant/fastembed)
  (`BAAI/bge-small-en-v1.5`, ~30 MB, auto-downloaded and cached). Pairs below
  `--semantic-threshold` (default `0.65`) flag as `semantic_drift`. As a rough guide: `<0.50`
  major divergence, `0.50–0.70` significant, `0.70–0.85` moderate, `>0.85` minor/none.
- **LLM diff proposals** _(opt-in, BYOLLM)_ — with `OPENAI_API_KEY` set, `stale` asks OpenAI to
  propose a rewritten rule for each `semantic_drift` finding. Proposals are **never auto-applied**
  — you review and apply manually. `max_proposals` caps cost (~$0.0005 each at defaults).
  Use `--min-severity info` to surface no-tag / unknown-technique findings.
</details>

<details>
<summary><b>backtest</b> — status model & options</summary>

Replays rules against a bundled corpus of real attack telemetry (OTRF
[Security-Datasets](https://github.com/OTRF/Security-Datasets), fetched on demand, SHA-verified).

Per (rule, technique): **verified** (matched an event) · **silent** (evaluated, no match) ·
**untested** (no dataset for that technique) · **unsupported** (matcher can't handle it).
Rules roll up to **fires / partial / silent_on_all / untested / unsupported**.

Options: `--platform`, `--techniques T1059.001,T1078`, `--mordor-source /path/to/checkout`.
Two gates (both exit `2`): priority-silence (a covered priority technique fires on nothing) and
broken-rules (a rule is silent on every dataset it was tested against).

_Not yet (v0.x): ES\|QL matcher, Sigma `|cidr/|gt/|lt` modifiers & unfielded `keywords`, compound
multi-technique datasets, live detonation._
</details>

<details>
<summary><b>coverage</b> — states & priority gating</summary>

- **full** — a rule tags this exact technique ID.
- **shallow** — covered only indirectly (parent tagged → sub inferred, or sub tagged → parent inferred).
- **gap** — nothing references this technique or its sub-techniques.

Priority techniques (a built-in CTID top-25 by default, or your own JSON via `priority_list` /
`--priority-list`) drive the gate: any priority technique in `gap` exits `2`. Custom list format:

```json
{ "name": "Acme Priorities 2026", "technique_ids": ["T1078", "T1190", "T1059.001", "T1486"] }
```
</details>

<details>
<summary><b>audit</b> — composition & scores</summary>

Runs `stale` + `coverage` + `backtest` in one session and prints three independent scores
(0–100, `null` if skipped/errored): **stale health**, **coverage completeness**, **backtest
verification rate**. The gate uses **strict-AND** — it fires only when *every* enabled check would
have gated on its own (the "everything's broken" alarm); run subcommands directly for fine-grained
signal. Skip checks with `--skip stale --skip backtest`. Audit honors each subcommand's own config.
</details>

## Development

```bash
pip install -e ".[dev]"                 # editable install (Python 3.12+)
pytest -q && ruff check src/ tests/ && mypy src/
python -m build && twine check dist/*   # verify the package builds
```

See [CHANGELOG.md](CHANGELOG.md) for release notes and [RELEASING.md](RELEASING.md) for how to
cut a PyPI release.

## License

MIT © James Bower

---

- 📧 **Newsletter** — tool links 24h before public launch → [Subscribe](https://james-bower.kit.com/newsletter)
- 🎮 **Discord — Machine Learning in Security** → [Join](https://james-bower.kit.com/mlsecdiscord)
- 📝 **Design deep-dives** → [jamesbower.com](https://jamesbower.com)
