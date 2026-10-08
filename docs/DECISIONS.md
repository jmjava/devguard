# Decision log

## 2026-10-07 — M1 persistence is a local SQLite file

- The store is crate `devguard-store`, using `rusqlite` 0.32.1 with bundled SQLite so the toolchain stays on rustc 1.85 and does not need a system `libsqlite3`.
- The database file is `devguard.db` under the XDG state directory (`~/.local/state/devguard/`).
- Schema version 1 creates `runs`, `observations`, and `snapshots`. Findings and backup tables stay out of this slice.
- This slice stores rows the caller supplies. It does not collect OS inventory, packages, or sockets, and it does not open a port.

## 2026-10-07 — M0 skeleton; prioritize SLM GPU metrics after M0

- **License:** MIT (repo `LICENSE`).
- **M0 crates only:** `devguard-cli`, `devguard-core`. No stub crates for later modules.
- **Config extension:** added `[slm]` for opt-in model dir inventory, process name hints, and gpu/host capture flags — inventory/metrics only, no model loading.
- **Health thresholds:** added `warn_gpu_mem_percent` / `warn_mem_percent` for VRAM/RAM pressure signals useful during SLM runs.
- **Milestone order tweak:** after M0 acceptance, implement a narrow **M2-leaning GPU/host metrics slice** before broad M1 snapshot breadth, because SLM project metric capture is the immediate user need. Full M1 snapshot remains on the roadmap.
- **Backup engine:** still deferred to M4; default config names `restic` but does not invoke it in M0.

## 2026-10-07 — Academic SLM metric set

- Documented literature mapping in `docs/slm-research-metrics.md` (Lu et al. 2409.15790, Wang survey 2410.20011, MLPerf TTFT/TPOT, ML.ENERGY, edge energy papers).
- **Split responsibilities:** DevGuard auto-captures host/GPU (util, VRAM, temp, power); harness supplies TTFT/TPOT/tokens/task scores via `SlmRunRecord` annotations.
- **Measurement plane:** default `gpu_rail` (`nvidia-smi`); never claim wall-AC MLPerf Power equivalence without an external meter field.
- **Derived metrics:** `energy_j ≈ P_mean * duration`, `J/token`, `tokens/J`, `throughput/Watt` when annotations + samples exist.
- JSON schema: `docs/schemas/slm-run-metrics.schema.json`; Rust types: `devguard_core::slm`.

## 2026-10-07 — Deep task store + portfolio synergies

- Canonical store: `docs/tasks/` with generated `backlog-deep.md` (~400 tasks) + `manifest.json` for Obsidian MCP reload.
- Synergy map (`SYNERGIES.md`) prioritizes: **slm-setup** (bracket Ollama), **embabel-slm** (paper tables), **obsidian-mcp** (vault reload), **sdlc-spdd**, **docgen**.
- External: import llama-bench / vLLM metrics / Zeus energy; do not reinvent Ollama MCP or training.
