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
- `devguard health fan` — read-only observations and hypotheses. Process names only. Missing `sensors` or `nvidia-smi` is `unavailable`, never a clean result. Does not use sudo or change fan curves.
- `devguard health sensors` — package, CPU, and board temperatures plus fan RPM from hwmon files. If `sensors` is missing and no hwmon file is readable, the reading is `unavailable` and not clean. Does not install packages, use sudo, load modules, or change a fan curve.
- `devguard health os` — kernel release, boot id, and uptime from `/proc`. The hostname is stored only as a privacy-preserving hash. A missing `/proc` source is `unavailable` and not clean. Does not use sudo, open a port, or collect package lists.
- `devguard health units` — unit name, enabled state, active state, and whether the unit is failed. If `systemctl` is missing or the listing is unreadable, the result is `unavailable` and not clean. Does not start, stop, enable, or disable units, and does not use sudo.
- `devguard health packages` — installed package names and versions, plus pending updates when local APT list files are readable. Missing or unreadable lists make pending updates `unavailable` and the result not clean. Does not run apt install, apt upgrade, or any command that changes packages, and does not use sudo.
- `devguard health watch --interval 5s` — ratatui view of that same fan diagnostic. Refreshes on a bounded interval and exits on Ctrl+C. Does not start a background service or signal processes. Missing `sensors` or `nvidia-smi` stays `unavailable`.
- `devguard health ports` — local listening sockets from `ss` (protocol, address, port, process name). A missing `ss` is `unavailable` and not clean. A row with no process name is attribution missing, which is still listening. Does not open a port, scan a remote host, or collect command arguments.
- `devguard health gpu-id` — NVIDIA driver version, GPU name, and PCI bus id for upgrade diffs. A missing `nvidia-smi` or a missing field is `unavailable` and not clean. Does not use sudo or load a kernel module.
- `devguard health files` — SHA-256 of each path in `snapshot.config_hash_allowlist`, plus byte size and mtime. A missing or unreadable path is `unavailable` and not clean. Does not store or print file bytes.
- `devguard gpu scan` — one-shot NVIDIA reading (human and `--json`). A hash of the GPU UUID, never the raw UUID. Missing `nvidia-smi` or a missing field is `unavailable`, never a clean result. Does not use sudo or load modules.
- `devguard remote status` — host and tunnel reachability. Off until local config names an SSH host and user. Does not print that target.
- `devguard remote tunnel up` / `down` — SSH local-forward to Ollama on `127.0.0.1` inside WSL. No bind on all interfaces, no public tunnel, no arbitrary command, no file upload, no firewall change, and no resident daemon.
- `devguard dev env` — version lines for `rustc`, `cargo`, `python3`, `node`, `git`, and `gcc` when they are on `PATH`. A tool that is not on `PATH` is `unavailable`, and the report is not clean. Does not install tools, use the network, or run a package audit.
- `devguard dev repos scan [PATH...]` — dirty, untracked, branch, upstream, and unpublished commits for git work trees under an explicit path or `dev.repo_roots`. No path and no configured root is `unavailable`, and that result is not clean. A missing `git` binary or an unreadable path is the same. Does not fetch, pull, push, walk the home directory, or use sudo.
- `devguard-dashboard` — read-only window over the doctor report and status already returned by the library. `devguard-dashboard --smoke` prints that snapshot and exits without opening a display. It does not start a daemon.
- `devguard-store` — SQLite file `devguard.db` under the state directory, with migrations for `runs`, `observations`, and `snapshots`. Opening the file applies those migrations. This slice does not collect OS inventory, packages, or sockets, and it does not listen on a port.
- Versioned `--json` envelopes, redacted logging helpers, unit + CLI smoke tests

**Next priority (given SLM / academic workloads):** health + GPU collectors and run bracketing for paper-ready efficiency tables (TTFT/TPOT annotations + VRAM/power/temp). See [`docs/slm-research-metrics.md`](docs/slm-research-metrics.md).

## Quick start

```bash
cargo build -p devguard-cli
cargo run -p devguard-cli -- config init
cargo run -p devguard-cli -- doctor
cargo run -p devguard-cli -- --json doctor
cargo run -p devguard-cli -- config validate
cargo run -p devguard-dashboard -- --smoke
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
