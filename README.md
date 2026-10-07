# DevGuard

Rust CLI toolkit for workstation **backup**, **audit**, **health**, and **SLM (small language model) metrics** on Ubuntu/Linux.

Read-only by default. Mutating actions (backup/restore) require explicit configuration and confirmation.

See [`SPEC.md`](SPEC.md) for the full implementation contract.

## Current status (M0)

Working today:

- `devguard --help`
- `devguard doctor` — prerequisites, permissions, **NVIDIA/SLM GPU coverage**
- `devguard config init` / `devguard config validate`
- `devguard status` — placeholder until collectors persist scans
- Versioned `--json` envelopes, redacted logging helpers, unit + CLI smoke tests

**Next priority (given SLM / academic workloads):** health + GPU collectors and run bracketing for paper-ready efficiency tables (TTFT/TPOT annotations + VRAM/power/temp). See [`docs/slm-research-metrics.md`](docs/slm-research-metrics.md).

## Quick start

```bash
cargo build -p devguard-cli
cargo run -p devguard-cli -- config init
cargo run -p devguard-cli -- doctor
cargo run -p devguard-cli -- --json doctor
cargo run -p devguard-cli -- config validate
```

Optional config for local models (`~/.config/devguard/config.toml`):

```toml
[slm]
workspace_label = "local-inference"
model_dirs = ["~/models"]
process_name_hints = ["ollama", "llama", "vllm"]
capture_gpu = true
capture_host = true

[health]
warn_gpu_temp_c = 85
warn_gpu_mem_percent = 90
```

## Task backlog (reloadable)

Canonical Obsidian/MCP task store: [`docs/tasks/`](docs/tasks/)

```bash
python3 scripts/generate_task_backlog.py   # regenerate deep backlog
./docs/tasks/reload.sh                     # verify counts
# deep:      docs/tasks/backlog-deep.md
# priority:  docs/tasks/backlog-50.md
# synergies: docs/tasks/SYNERGIES.md
# machine:   docs/tasks/manifest.json
```

## Develop

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## License

MIT — see [`LICENSE`](LICENSE).
