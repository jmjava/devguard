---
title: DevGuard — 50-task backlog
project: DevGuard
store: docs/tasks
source: SPEC.md + docs/slm-research-metrics.md
created: 2026-10-07
updated: 2026-10-07
tags:
  - devguard
  - backlog
  - obsidian
---

# DevGuard — 50 tasks

Canonical store: `docs/tasks/`. Reload via [`README.md`](README.md) or `manifest.json`.

`[x]` = done · `[ ]` = open · **50 total**

---

## A. Foundation (M0) — 5

- [x] #devguard #m0 Cargo workspace: `devguard-cli` + `devguard-core`
- [x] #devguard #m0 CLI: `--help`, `doctor`, `config init|validate`, `status` + JSON envelopes/exit codes
- [x] #devguard #m0 TOML config validation, redaction helpers, CI (fmt/clippy/test)
- [ ] #devguard #m0 Changelog + CONTRIBUTING with SPEC §11 Cursor milestone workflow
- [ ] #devguard #m0 Decision log: restic vs rustic, SQLite vs JSON snapshots, credential mechanism

## B. SLM research metrics (priority) — 9

- [x] #devguard #slm Literature map + `SlmRunRecord` schema/types (`docs/slm-research-metrics.md`)
- [ ] #devguard #slm NVIDIA collector: util %, VRAM used/total, temp °C, power W, clocks, driver
- [x] #devguard #slm Host companion sample: CPU %, RAM/swap, disk free (bytes; RFC3339)
- [ ] #devguard #slm `devguard slm run begin|end` — bracket runs; interval samples; merge harness annotations
- [ ] #devguard #slm Ingest harness JSON: TTFT/TPOT p50/p99, tokens, batch, ctx, quantization, backend
- [ ] #devguard #slm Derive GPU-rail energy (J≈P̄·Δt, J/token, tokens/J, tok/W); label `measurement_plane`
- [ ] #devguard #slm `devguard slm export` — paper-ready CSV/JSON with locked experimental cell columns
- [ ] #devguard #slm Fixtures: no `nvidia-smi` / no GPU / cool-down notes; redacted paths; never “healthy” if unavailable
- [ ] #devguard #slm Vault/export template: 10-field academic checklist per published config row

## C. Snapshot / upgrade guardian (M1) — 10

- [ ] #devguard #m1 SQLite store + migrations (`runs`, `observations`, `snapshots`) under XDG state
- [ ] #devguard #m1 Collect OS/kernel/boot-id/uptime + privacy-preserving hostname hash
- [x] #devguard #m1 Collect APT inventory (+ optional Snap) and pending updates when readable
- [x] #devguard #m1 Collect systemd enabled/running/failed units
- [ ] #devguard #m1 Collect listening sockets via `ss` (proto/addr/port/process; missing attribution distinct)
- [x] #devguard #m1 Collect NVIDIA driver/GPU + selected PCI/modules for upgrade diffs
- [ ] #devguard #m1 Collect toolchain versions (rustc/cargo, gcc/clang, java, python, node, git, docker)
- [x] #devguard #m1 Allowlist config-file hashing (hash+metadata only; never persist secret bytes)
- [x] #devguard #m1 `snapshot create [--label]` / `list` / `diff` — stable order; severity hints ≠ facts
- [x] #devguard #m1 Upgrade fixtures: kernel/driver/port/package drift; partial coverage never marked clean

## D. Health & fan diagnostics (M2) — 6

- [ ] #devguard #m2 `health scan` — CPU, memory/swap, disk, uptime, top processes (args redacted)
- [ ] #devguard #m2 lm-sensors adapter: package/CPU/board temps + fan RPM when present
- [ ] #devguard #m2 NVIDIA health adapter; distinguish GPU fan vs case/CPU fans
- [ ] #devguard #m2 `health watch --interval` TUI; Ctrl+C clean; bounded poll; no background daemon
- [ ] #devguard #m2 Config threshold warnings (`warn_*`) labeled rules-of-thumb, not hardware guarantees
- [ ] #devguard #m2 Fan-regression diagnostic: observations vs possible causes; no sudo/BIOS/module changes

## E. Security Sentinel (M3) — 6

- [x] #devguard #m3 Port + service drift vs baseline → findings (`info|warning|critical|unknown`)
- [x] #devguard #m3 Firewall status (`ufw`/nftables) + readable SSH exposure/config checks
- [x] #devguard #m3 SSH login / failed-auth adapter (no credentials or full journal dumps)
- [x] #devguard #m3 OS security-update status via Ubuntu interfaces (never auto-install)
- [x] #devguard #m3 Allowlisted sensitive path permission checks (no global recursive scan)
- [x] #devguard #m3 `security scan` / `diff` / `findings [--severity]`; missing perms ≠ clean in fixtures

## F. Backup Guardian (M4) — 6

- [ ] #devguard #m4 Choose first engine (restic **or** rustic); pin versions; document password-file/FD/keyring
- [x] #devguard #m4 `backup plan` dry-run: includes/excludes, unreadable paths, huge-model warnings
- [ ] #devguard #m4 `backup run` / `list` against configured repo only; never log/argv/config passwords
- [ ] #devguard #m4 `backup verify [--sample]` — metadata vs sampled content; record snapshot identity
- [ ] #devguard #m4 Safe restore (`--dry-run` → `--apply` + confirm) + integration hash-match test
- [ ] #devguard #m4 Runbook: offsite/offline media + restore drills (no ransomware claims from encryption alone)

## G. Developer Workflow Guardian (M5) — 4

- [ ] #devguard #m5 `dev env` — compiler/SDK/package-manager inventory (reproducibility report, not bit-identical)
- [x] #devguard #m5 `dev repos scan` — dirty/untracked/branch/upstream/unpushed; safe git; no network by default
- [x] #devguard #m5 Opt-in `dev deps audit` (cargo-audit/npm/pip/maven); network scans explicit only
- [x] #devguard #m5 Sanitize output/logs so token-like fixture strings never appear

## H. Ops & multi-node (M6–M7) — 4

- [ ] #devguard #m6 Opt-in `systemd --user` timers + local alerts/report files + retention dry-run
- [ ] #devguard #m6 Packaging/release notes + idle-overhead benchmark (no port until user enables)
- [ ] #devguard #m7 Multi-node PoC design: allowlisted read-only metrics, mTLS, peer allowlist — **no remote shell**
- [ ] #devguard #m7 AMD ROCm/Halo health provider spike only after NVIDIA path is stable

---

## Obsidian Tasks queries

```tasks
not done
tags include #devguard
group by tags
```

```tasks
not done
tags include #slm
```
