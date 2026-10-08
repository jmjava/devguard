# DevGuard architecture (M0)

DevGuard is a Cargo workspace with a single CLI binary and shared library crates.

## Current crates

| Crate | Role |
|---|---|
| `devguard-cli` | `clap` commands, human/JSON output |
| `devguard-core` | config, errors, exit codes, JSON envelope, redaction, doctor, collector contract |
| `devguard-store` | SQLite file `devguard.db` in the state directory; migrations for `runs`, `observations`, and `snapshots` |

Later milestones add `devguard-host`, `devguard-health`, `devguard-security`, `devguard-backup`, and `devguard-dev` without changing the JSON envelope versioning rules.

## Data locations

- Config: `~/.config/devguard/config.toml` (mode `0600` on init)
- State: `~/.local/state/devguard/devguard.db` (SQLite tables `runs`, `observations`, `snapshots`)
- `devguard schedule dry-run` prints a systemd user unit and does not write `~/.config/systemd`

## SLM metrics direction

Priority focus after M0: read-only **host + NVIDIA GPU** collectors for small-language-model workloads, aligned with academic reporting (see [`slm-research-metrics.md`](slm-research-metrics.md)):

- GPU utilization, VRAM used/total, temperature, power (GPU-rail)
- Host CPU, system memory, disk
- Optional process highlights from `[slm].process_name_hints`
- Inventory of configured `model_dirs` (paths/sizes only; never upload weights)
- `SlmRunRecord` schema for combining system samples with harness TTFT/TPOT/token/quality annotations

Collectors return `CollectionStatus::{Complete, Partial, Unavailable}` so missing `nvidia-smi` never looks “healthy.”

## Output contract

`--json` prints exactly one `JsonEnvelope` document to stdout (`schema_version`, `command`, `observed_at`, `ok`, `data`, `warnings`, `error`). Human progress and warnings go to stderr where appropriate.
