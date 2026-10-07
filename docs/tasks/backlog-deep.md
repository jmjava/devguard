---
title: DevGuard — deep task backlog
project: DevGuard
store: docs/tasks
source: SPEC.md + SYNERGIES.md + slm-research-metrics.md
generated: 2026-10-07
tags:
  - devguard
  - backlog
  - obsidian
---

# DevGuard — deep task backlog

Canonical **deep** store for Obsidian MCP reload. Prefer this over the short `backlog-50.md` priority slice.

See also: [`SYNERGIES.md`](SYNERGIES.md) · [`STATUS.md`](STATUS.md) · [`manifest.json`](manifest.json)

```bash
./docs/tasks/reload.sh
```

## A. Foundation (M0) — deepen & harden

_20 tasks_

- [x] #devguard #m0 Cargo workspace: devguard-cli + devguard-core
- [x] #devguard #m0 CLI: help, doctor, config init|validate, status + JSON envelopes/exit codes
- [x] #devguard #m0 TOML config validation, redaction helpers, CI fmt/clippy/test
- [x] #devguard #m0 #slm Literature map + SlmRunRecord schema/types
- [ ] #devguard #m0 Add CHANGELOG.md with Keep-a-Changelog format
- [ ] #devguard #m0 Add CONTRIBUTING.md with SPEC §11 Cursor milestone workflow
- [ ] #devguard #m0 Add CODE_OF_CONDUCT / SECURITY.md disclosure process
- [ ] #devguard #m0 Decision: restic vs rustic as sole M4 engine
- [ ] #devguard #m0 Decision: SQLite vs JSON-file snapshots for M1 persistence
- [ ] #devguard #m0 Decision: credential mechanism (password-file vs FD vs keyring)
- [ ] #devguard #m0 Pin MSRV in CI matrix (1.85 + stable)
- [ ] #devguard #m0 Add cargo deny / audit job for supply-chain
- [ ] #devguard #m0 Document exit codes 0/1/2/3/64 in --help and man-style docs
- [ ] #devguard #m0 Structured tracing fields with redaction layer on Display
- [ ] #devguard #m0 Config schema_version migration stub (v1 only, tested)
- [ ] #devguard #m0 XDG path override tests for --config and custom state dir
- [ ] #devguard #m0 Refuse world-writable config files with clear error
- [ ] #devguard #m0 Doctor JSON schema fixture in docs/schemas/
- [ ] #devguard #m0 Smoke script scripts/smoke_m0.sh for offline Ubuntu
- [ ] #devguard #m0 README quickstart GIF/asciinema via docgen synergy later

## B. SLM collectors & research harness

_41 tasks_

- [ ] #devguard #slm NVIDIA collector: name, UUID hash, driver, CUDA version if readable
- [ ] #devguard #slm NVIDIA collector: utilization.gpu / utilization.memory %
- [ ] #devguard #slm NVIDIA collector: memory.used / memory.total bytes
- [ ] #devguard #slm NVIDIA collector: temperature.gpu °C
- [ ] #devguard #slm NVIDIA collector: power.draw / power.limit watts
- [ ] #devguard #slm NVIDIA collector: clocks.sm / clocks.mem MHz when available
- [ ] #devguard #slm NVIDIA collector: fan.speed % if exposed
- [ ] #devguard #slm NVIDIA collector: ecc / throttling reasons when readable
- [ ] #devguard #slm Multi-GPU enumeration with stable index ordering
- [ ] #devguard #slm Host sample: loadavg 1/5/15
- [ ] #devguard #slm Host sample: CPU percent (sysinfo)
- [ ] #devguard #slm Host sample: memory used/total/available + swap
- [ ] #devguard #slm Host sample: disk free/total for model_dirs mount points
- [ ] #devguard #slm Host sample: top-N processes filtered by slm.process_name_hints
- [ ] #devguard #slm Mark CollectionStatus Unavailable when nvidia-smi missing
- [ ] #devguard #slm Timeouts + bounded stdout capture for all nvidia-smi calls
- [ ] #devguard #slm Fixture parsers from sanitized nvidia-smi CSV
- [ ] #devguard #slm devguard gpu scan --json one-shot
- [ ] #devguard #slm devguard health scan includes GPU block when capture_gpu
- [ ] #devguard #slm devguard slm run begin --label --backend --model
- [ ] #devguard #slm devguard slm run sample (manual mid-run sample)
- [ ] #devguard #slm devguard slm run end --annotations path.json
- [ ] #devguard #slm Background sampler thread/process with interval from config
- [ ] #devguard #slm Persist run under ~/.local/state/devguard/slm-runs/<id>/
- [ ] #devguard #slm Write run.json + samples.jsonl per run
- [ ] #devguard #slm Ingest harness annotations: ttft/tpot p50/p99
- [ ] #devguard #slm Ingest harness annotations: prompt/output tokens, batch, ctx
- [ ] #devguard #slm Ingest harness annotations: quantization, backend, git_commit
- [ ] #devguard #slm Ingest quality: task_name, metric, score
- [ ] #devguard #slm Derive energy_gpu_approx_j from mean power × duration
- [ ] #devguard #slm Derive joules_per_token / tokens_per_joule / throughput_per_watt
- [ ] #devguard #slm Label measurement_plane gpu_rail|wall_ac|mixed|unknown
- [ ] #devguard #slm Optional energy_wall_j field from external meter file
- [ ] #devguard #slm devguard slm list [--json]
- [ ] #devguard #slm devguard slm show <run_id> [--json]
- [ ] #devguard #slm devguard slm export --format csv|json|markdown
- [ ] #devguard #slm Export columns match academic 10-field checklist
- [ ] #devguard #slm Cool-down reminder using suggested_cooldown_seconds
- [ ] #devguard #slm Reject incomplete cells when --strict-paper flag set
- [ ] #devguard #slm Unit tests for energy derivation edge cases (zero duration/tokens)
- [ ] #devguard #slm Integration: mock nvidia-smi script on PATH

## C. Synergy — jmjava/slm-setup (Ollama MCP bridge)

_15 tasks_

- [ ] #devguard #synergy/slm-setup #slm Document adapter: wrap prove_acceptance.py with slm run begin/end
- [ ] #devguard #synergy/slm-setup #slm Parse slm-setup harness JSONL into ExperimentMeta + LatencyMetrics
- [ ] #devguard #synergy/slm-setup #slm Map OLLAMA_BASE_URL safety: refuse public endpoints (align check_deployment_safety)
- [ ] #devguard #synergy/slm-setup #slm Process hints include ollama + model runner names from slm-setup
- [ ] #devguard #synergy/slm-setup #slm Capture metrics during scripts/run_harness.py live backend profile
- [ ] #devguard #synergy/slm-setup #slm Capture metrics during prove_refactor_acceptance fast/strong models
- [ ] #devguard #synergy/slm-setup #slm Tag runs with eval profile: observed|golden|stub
- [ ] #devguard #synergy/slm-setup #slm Correlate transport/format/structure/behavior scores with J/token
- [ ] #devguard #synergy/slm-setup #slm Downstairs WSL-GPU host profile example (SSH forward) in docs
- [ ] #devguard #synergy/slm-setup #slm Halo Ryzen AI host profile placeholders for future AMD collector
- [ ] #devguard #synergy/slm-setup #m7 Shared threat model: no public Ollama, no remote shell in DevGuard agent
- [ ] #devguard #synergy/slm-setup #slm Example config snippet linking model_dirs to Ollama model store
- [ ] #devguard #synergy/slm-setup #slm CI note: GPU metrics only on workstation; fixtures offline
- [ ] #devguard #synergy/slm-setup #slm Cross-link evaluation-protocol.md metrics to SlmRunRecord.quality
- [ ] #devguard #synergy/slm-setup #slm Script: scripts/synergy_slm_setup_bracket.sh template

## D. Synergy — jmjava/embabel-slm (research / paper)

_15 tasks_

- [ ] #devguard #synergy/embabel-slm #slm Align export schema with embabel-slm paper table needs
- [ ] #devguard #synergy/embabel-slm #slm Support experiment cells: base vs retrieval vs LoRA labels
- [ ] #devguard #synergy/embabel-slm #slm Pin official Ollama tags only in example configs (per standing rules)
- [ ] #devguard #synergy/embabel-slm #slm Never commit weights; inventory model_dirs sizes only
- [ ] #devguard #synergy/embabel-slm #slm Record git_commit + experiment dir path (refuse overwrite semantics)
- [ ] #devguard #synergy/embabel-slm #slm Pareto plot data export (accuracy vs J/token) as JSON for paper figs
- [ ] #devguard #synergy/embabel-slm #slm Zenodo/TechRxiv artifact packing checklist in docs
- [ ] #devguard #synergy/embabel-slm #slm Citation workflow: store BibTeX keys used for metric definitions
- [ ] #devguard #synergy/embabel-slm #slm Holdout-task runs tagged separately from training-split runs
- [ ] #devguard #synergy/embabel-slm #slm Compiler-accepted vs rejected generation outcome as quality metric
- [ ] #devguard #synergy/embabel-slm #slm Spring/Kotlin pattern-card eval latency capture
- [ ] #devguard #synergy/embabel-slm #slm Paper calendar milestones mapped to DevGuard export readiness
- [ ] #devguard #synergy/embabel-slm #slm Document measurement_plane honesty for preprint methods section
- [ ] #devguard #synergy/embabel-slm #slm Template methods paragraph for GPU-rail energy estimation
- [ ] #devguard #synergy/embabel-slm #slm Compare qwen3.5:9b vs devstral-small-2 efficiency cells

## E. Synergy — jmjava/obsidian-mcp (vault memory)

_12 tasks_

- [ ] #devguard #synergy/obsidian-mcp Vault note sync path for docs/tasks/backlog-deep.md
- [ ] #devguard #synergy/obsidian-mcp MCP reload recipe: read manifest.json into vault AI Memory
- [ ] #devguard #synergy/obsidian-mcp After slm run end → capture_work_session template fields
- [ ] #devguard #synergy/obsidian-mcp record_decision templates for DevGuard open design questions
- [ ] #devguard #synergy/obsidian-mcp get_project_context('devguard') starter note content
- [ ] #devguard #synergy/obsidian-mcp Tag taxonomy shared: #m0-#m7 #slm #synergy/*
- [ ] #devguard #synergy/obsidian-mcp Dataview queries committed beside backlog
- [ ] #devguard #synergy/obsidian-mcp Tasks plugin queries for not-done #slm
- [ ] #devguard #synergy/obsidian-mcp Export STATUS.md into vault dashboard note
- [ ] #devguard #synergy/obsidian-mcp Document OBSIDIAN_VAULT_PATH usage without requiring Obsidian running
- [ ] #devguard #synergy/obsidian-mcp Script to push completed task IDs from git to vault
- [ ] #devguard #synergy/obsidian-mcp Avoid secrets in vault notes (align redaction)

## F. Synergy — sdlc-spdd-orchestrator & documentation-generator

_10 tasks_

- [ ] #devguard #synergy/sdlc-spdd Create SPDD Work ID canvas for DevGuard M1 slice
- [ ] #devguard #synergy/sdlc-spdd Create SPDD Work ID canvas for SLM metrics vertical
- [ ] #devguard #synergy/sdlc-spdd Map SPEC milestones to ROADMAP.md style ledger entries
- [ ] #devguard #synergy/sdlc-spdd Capture pitfalls from failed collectors into lessons.jsonl shape
- [ ] #devguard #synergy/sdlc-spdd Quiet-mode note when dogfooding SDLC on DevGuard itself
- [ ] #devguard #synergy/docgen docgen scene outline: doctor → gpu scan → slm export
- [ ] #devguard #synergy/docgen docgen scene outline: snapshot pre/post upgrade diff
- [ ] #devguard #synergy/docgen Narrated demo script Markdown for academic metrics walkthrough
- [ ] #devguard #synergy/docgen PlantUML/C4 snippet linking DevGuard + slm-setup + embabel-slm
- [ ] #devguard #synergy/docgen Publish demo to GitHub Pages when ready

## G. External ecosystem adapters (don't reinvent)

_13 tasks_

- [ ] #devguard #slm #ecosystem Import adapter: llama-bench JSON → LatencyMetrics (pp/tg/pg)
- [ ] #devguard #slm #ecosystem Document llama-bench gap: no TTFT/VRAM/energy — DevGuard fills
- [ ] #devguard #slm #ecosystem Optional vLLM /metrics scrape during slm run (TTFT/TPOT histograms)
- [ ] #devguard #slm #ecosystem Document Zeus window API as preferred energy when Python harness uses it
- [ ] #devguard #slm #ecosystem Ingest Zeus/NVML joules as energy_wall_j or energy_gpu when labeled
- [ ] #devguard #slm #ecosystem DCGM field mapping doc (power, util, mem, energy counter)
- [ ] #devguard #slm #ecosystem Interop CSV with llm-inference-benchmark columns
- [ ] #devguard #slm #ecosystem Interop notes for LLenergyMeasure study exports
- [ ] #devguard #slm #ecosystem MLPerf metric naming alignment (TTFT/TPOT p99, tokens/s)
- [ ] #devguard #slm #ecosystem CodeCarbon optional annotation path (not default)
- [ ] #devguard #slm #ecosystem RAPL CPU energy optional on Linux when readable
- [ ] #devguard #slm #ecosystem Prometheus export sketch (opt-in, off by default — SPEC no listeners)
- [ ] #devguard #slm #ecosystem Explicit decision: file/JSONL export first, no daemon metrics port in MVP

## H. Snapshot / upgrade guardian (M1) — deep

_29 tasks_

- [ ] #devguard #m1 Introduce crate devguard-store with rusqlite bundled
- [ ] #devguard #m1 Migrations: runs, observations, snapshots, findings tables
- [ ] #devguard #m1 Retention config + dry-run cleanup command
- [ ] #devguard #m1 Run status enum: complete|partial|failed per provider
- [ ] #devguard #m1 Collector trait wired for host inventory
- [ ] #devguard #m1 OS release/version/arch collector (/etc/os-release)
- [ ] #devguard #m1 Kernel version + boot_id collector
- [ ] #devguard #m1 Uptime collector
- [ ] #devguard #m1 Hostname hash (privacy-preserving, stable)
- [ ] #devguard #m1 APT package list parser (dpkg-query) with fixtures
- [ ] #devguard #m1 Pending updates collector when readable without root magic
- [ ] #devguard #m1 Optional Snap list collector (Unavailable if missing)
- [ ] #devguard #m1 systemctl list-units enabled/running/failed parsers
- [ ] #devguard #m1 ss -lntup parser; missing process attribution flag
- [ ] #devguard #m1 NVIDIA driver/GPU summary in snapshot (reuse SLM collector)
- [ ] #devguard #m1 PCI devices of interest filter
- [ ] #devguard #m1 Loaded kernel modules names collector
- [ ] #devguard #m1 Toolchain version probes: rustc cargo gcc clang java python node git docker
- [ ] #devguard #m1 Config allowlist hashing (blake3/sha256) metadata only
- [ ] #devguard #m1 snapshot create --label pre-upgrade|post-upgrade
- [ ] #devguard #m1 snapshot list --json
- [ ] #devguard #m1 snapshot diff deterministic ordering
- [ ] #devguard #m1 Diff categories: added|removed|changed with severity hints
- [ ] #devguard #m1 Fixture: simulated Ubuntu upgrade kernel+driver+port+package
- [ ] #devguard #m1 Fixture: permission denied → Partial not clean
- [ ] #devguard #m1 Fixture: tool missing → Unavailable coverage
- [ ] #devguard #m1 status command shows latest snapshot timestamps
- [ ] #devguard #m1 JSON schema for snapshot documents
- [ ] #devguard #m1 Bench: typical snapshot finishes in seconds on healthy host

## I. Health & fan diagnostics (M2) — deep

_18 tasks_

- [ ] #devguard #m2 Crate devguard-health
- [ ] #devguard #m2 sysinfo CPU/memory/disk/process collection
- [ ] #devguard #m2 Redact sensitive argv in top processes
- [ ] #devguard #m2 lm-sensors adapter parse chips/temps/fans
- [ ] #devguard #m2 Distinguish CPU/package/board/GPU fan labels
- [ ] #devguard #m2 health scan human + JSON
- [ ] #devguard #m2 health watch TUI with ratatui + crossterm
- [ ] #devguard #m2 health watch interval bounds + Ctrl+C cleanup
- [ ] #devguard #m2 No background service/daemon in watch mode
- [ ] #devguard #m2 Threshold warnings from health.warn_* config
- [ ] #devguard #m2 Fan-regression report template (observations vs hypotheses)
- [ ] #devguard #m2 Include failed systemd units in fan-regression context
- [ ] #devguard #m2 Include kernel + NVIDIA driver in fan-regression context
- [ ] #devguard #m2 Tests: no sensors binary → Unavailable
- [ ] #devguard #m2 Tests: no NVIDIA → Unavailable GPU block
- [ ] #devguard #m2 Document non-sudo ordinary scanning
- [ ] #devguard #m2 Optional I/O wait stats when /proc provides
- [ ] #devguard #m2 Thermal throttle detection note when nvml throttling present

## J. Security Sentinel (M3) — deep

_19 tasks_

- [ ] #devguard #m3 Crate devguard-security
- [ ] #devguard #m3 Finding model: severity info|warning|critical|unknown + source/confidence
- [ ] #devguard #m3 Rule docs for every finding id
- [ ] #devguard #m3 Listening port drift vs baseline
- [ ] #devguard #m3 Service enablement drift vs baseline
- [ ] #devguard #m3 ufw status parser
- [ ] #devguard #m3 nftables detection without claiming full audit
- [ ] #devguard #m3 SSH config readable checks (PermitRootLogin etc.)
- [ ] #devguard #m3 SSH exposure: listening 22 on non-localhost
- [ ] #devguard #m3 journalctl/auth log adapter for failed logins (bounded)
- [ ] #devguard #m3 Never copy credentials or full journal payloads
- [ ] #devguard #m3 Ubuntu security update status interfaces
- [ ] #devguard #m3 Never auto-install updates
- [ ] #devguard #m3 Allowlisted path permission checks
- [ ] #devguard #m3 security scan / diff / findings CLI
- [ ] #devguard #m3 Fixtures: normal drift vs actionable warning
- [ ] #devguard #m3 Fixtures: missing perms ≠ clean
- [ ] #devguard #m3 Unfamiliar process is NOT malware proof (document)
- [ ] #devguard #m3 Opt-in dependency audit hook deferred to M5

## K. Backup Guardian (M4) — deep

_19 tasks_

- [ ] #devguard #m4 Crate devguard-backup
- [ ] #devguard #m4 Engine trait with restic OR rustic implementation (one first)
- [ ] #devguard #m4 Version pin + detect unsupported engine versions
- [ ] #devguard #m4 Credential via password file / FD only; test no argv leakage
- [ ] #devguard #m4 backup plan dry-run JSON
- [ ] #devguard #m4 Warn on excluded huge models (gguf/bin/models/**)
- [ ] #devguard #m4 Warn on unreadable includes
- [ ] #devguard #m4 backup run against configured repository only
- [ ] #devguard #m4 backup list snapshots
- [ ] #devguard #m4 backup verify metadata|sample|full modes
- [ ] #devguard #m4 Record backup_jobs + backup_verifications tables
- [ ] #devguard #m4 restore --dry-run default path
- [ ] #devguard #m4 restore --apply requires confirmation
- [ ] #devguard #m4 Block path traversal and symlink escape
- [ ] #devguard #m4 Refuse dangerous destinations (/, /etc, $HOME bare)
- [ ] #devguard #m4 Integration test synthetic dir hash roundtrip
- [ ] #devguard #m4 forget/prune explicitly NOT automatic (future feature flag)
- [ ] #devguard #m4 Runbook offsite/immutable media + restore drills
- [ ] #devguard #m4 Include DevGuard DB in recovery design notes

## L. Developer Workflow Guardian (M5) — deep

_15 tasks_

- [ ] #devguard #m5 Crate devguard-dev
- [ ] #devguard #m5 dev env inventory compilers/SDKs/package managers
- [ ] #devguard #m5 Reproducibility report language (not bit-identical claim)
- [ ] #devguard #m5 Scan repo_roots for git repos safely (no shell interpolation)
- [ ] #devguard #m5 Detect dirty worktree / untracked / branch / upstream
- [ ] #devguard #m5 Detect unpushed commits without network fetch by default
- [ ] #devguard #m5 dev repos scan --json
- [ ] #devguard #m5 Opt-in cargo audit adapter
- [ ] #devguard #m5 Opt-in npm audit adapter
- [ ] #devguard #m5 Opt-in Python audit adapter
- [ ] #devguard #m5 Opt-in Maven/Gradle scanner stub
- [ ] #devguard #m5 allow_network_audits gate enforced
- [ ] #devguard #m5 Redact token-like strings in logs (fixture test)
- [ ] #devguard #m5 Reuse inventory in snapshot diffs
- [ ] #devguard #m5 Synergy: flag embabel-slm / slm-setup / docgen dirty repos in multi-root scan

## M. Ops hardening & multi-node (M6–M7) — deep

_17 tasks_

- [ ] #devguard #m6 systemd --user timer unit templates (opt-in)
- [ ] #devguard #m6 Document how to disable timers completely
- [ ] #devguard #m6 No privileged system daemon
- [ ] #devguard #m6 Local alert: write report file under state dir
- [ ] #devguard #m6 Optional desktop notification if tool present
- [ ] #devguard #m6 DB retention cleanup --dry-run then --apply
- [ ] #devguard #m6 Idle overhead benchmark script + results doc
- [ ] #devguard #m6 Packaging notes (cargo install / distro later)
- [ ] #devguard #m6 Release checklist + signed tags process
- [ ] #devguard #m7 Multi-node architecture PoC doc only first
- [ ] #devguard #m7 Threat model review before any listener
- [ ] #devguard #m7 mTLS + peer allowlist design
- [ ] #devguard #m7 Allowlisted metrics API (CPU/GPU/VRAM/temp/disk)
- [ ] #devguard #m7 Explicitly no remote shell interface
- [ ] #devguard #m7 SSH user-initiated collection alternative (no agent)
- [ ] #devguard #m7 AMD ROCm/Halo adapter spike after NVIDIA stable
- [ ] #devguard #m7 #synergy/slm-setup Align Halo host profile with slm-setup examples/halo-ryzen-ai.md

## N. Cross-cutting quality, security, docs

_16 tasks_

- [ ] #devguard #quality Every milestone: unit tests for parsers/diff/path handling
- [ ] #devguard #quality Sanitized fixtures; no dependence on personal hardware in CI
- [ ] #devguard #quality Integration tests in disposable dirs
- [ ] #devguard #quality Manual acceptance commands documented with actual results
- [ ] #devguard #quality Permissions + prerequisites + rollback docs per command
- [ ] #devguard #quality Update SPEC decision log when interfaces change
- [ ] #devguard #quality JSON determinism tests excluding timestamps/ids
- [ ] #devguard #quality Property tests for redaction (secrets never leak)
- [ ] #devguard #quality Fuzz parsers for ss/sensors/nvidia-smi CSV
- [ ] #devguard #quality Clippy -D warnings enforced in CI
- [ ] #devguard #quality cargo fmt --check in CI
- [ ] #devguard #quality Coverage report optional job
- [ ] #devguard #quality SBOM generation for releases
- [ ] #devguard #quality Reproducible builds notes
- [ ] #devguard #quality Accessibility of human CLI output (no emoji reliance)
- [ ] #devguard #quality Internationalization: keep English MVP; avoid hard-coded locale assumes

## O. Academic paper metrics — granular fields

_30 tasks_

- [ ] #devguard #slm #paper Field: model_id stable string
- [ ] #devguard #slm #paper Field: parameter_count integer
- [ ] #devguard #slm #paper Field: quantization enum/string (Q4_K_M, Q8_0, fp16, …)
- [ ] #devguard #slm #paper Field: backend enum (ollama, llama.cpp, vllm, hf, other)
- [ ] #devguard #slm #paper Field: batch_size
- [ ] #devguard #slm #paper Field: context_length / n_ctx
- [ ] #devguard #slm #paper Field: prompt_tokens / output_tokens
- [ ] #devguard #slm #paper Field: ttft_ms mean
- [ ] #devguard #slm #paper Field: ttft_p50_ms / ttft_p99_ms
- [ ] #devguard #slm #paper Field: tpot_ms mean
- [ ] #devguard #slm #paper Field: tpot_p50_ms / tpot_p99_ms
- [ ] #devguard #slm #paper Field: e2e_latency_ms
- [ ] #devguard #slm #paper Field: tokens_per_second + throughput_kind
- [ ] #devguard #slm #paper Field: peak_vram_bytes / peak_host_rss_bytes
- [ ] #devguard #slm #paper Field: mean_gpu_power_w / max_gpu_power_w
- [ ] #devguard #slm #paper Field: energy_gpu_approx_j / joules_per_token / tokens_per_joule
- [ ] #devguard #slm #paper Field: throughput_per_watt
- [ ] #devguard #slm #paper Field: energy_delay_product optional
- [ ] #devguard #slm #paper Field: mean/max gpu_temperature_c
- [ ] #devguard #slm #paper Field: task_name / task_metric / task_score / higher_is_better
- [ ] #devguard #slm #paper Field: repetitions + stddev for llama-bench style averages
- [ ] #devguard #slm #paper Field: cool_down_seconds_observed
- [ ] #devguard #slm #paper Field: power_mode / n_gpu_layers / flash_attn flags
- [ ] #devguard #slm #paper Field: dataset_id / prompt_suite for ShareGPT-style loads
- [ ] #devguard #slm #paper Validate required fields for --paper-ready export mode
- [ ] #devguard #slm #paper Markdown table renderer matching embabel-slm paper outline
- [ ] #devguard #slm #paper BibTeX keys for Lu2024, Wang2025, MLENERGY, MLPerf in docs
- [ ] #devguard #slm #paper Methods boilerplate: GPU-rail vs wall-AC disclaimer
- [ ] #devguard #slm #paper Pareto CSV: task_score vs joules_per_token
- [ ] #devguard #slm #paper Ablation export: vary quant holding model/backend fixed

## P. Workstation profile — Ubuntu & ASUS/RTX lab

_13 tasks_

- [ ] #devguard #host Document target: Ubuntu 26.04 x86_64 primary
- [ ] #devguard #host Document hardware profile: ASUS PRIME Z490-P + RTX 3060
- [ ] #devguard #host Doctor check: NVIDIA driver present for 3060 class
- [ ] #devguard #host Fan-regression runbook for this chassis (SPEC special prompt)
- [ ] #devguard #host Collect motherboard/case fan RPM labels when sensors expose
- [ ] #devguard #host Collect GPU fan separately from chassis fans
- [ ] #devguard #host Note BIOS fan curve out of scope (read-only)
- [ ] #devguard #host smartctl optional disk health (Unavailable without perms)
- [ ] #devguard #host Confirm package availability list for Ubuntu 26.04 tools
- [ ] #devguard #host Secondary distro notes (Debian/Fedora) as adapter isolations
- [ ] #devguard #host WSL2 GPU caveats doc (synergy downstairs-wsl-gpu)
- [ ] #devguard #host Resource limits: subprocess timeouts defaults table
- [ ] #devguard #host Bounded memory for large apt inventory diffs

## Q. CLI surface — every command & flag

_18 tasks_

- [ ] #devguard #cli Global --config path
- [ ] #devguard #cli Global --json stdout contract
- [ ] #devguard #cli doctor human formatting polish
- [ ] #devguard #cli status shows last slm run + last snapshot
- [ ] #devguard #cli config init --force behavior tested
- [ ] #devguard #cli config validate warnings → exit 3
- [ ] #devguard #cli snapshot create/list/diff help texts: mutates? privileges?
- [ ] #devguard #cli health scan/watch help texts
- [ ] #devguard #cli gpu scan help texts
- [ ] #devguard #cli security scan/diff/findings help texts
- [ ] #devguard #cli backup plan/run/list/verify/restore help texts
- [ ] #devguard #cli dev env/repos/deps help texts
- [ ] #devguard #cli slm run begin/end/list/show/export help texts
- [ ] #devguard #cli Shell completions: bash/zsh/fish via clap
- [ ] #devguard #cli man page generation optional
- [ ] #devguard #cli Cancelation: Ctrl+C kills child processes
- [ ] #devguard #cli --include-paths documented opt-in only
- [ ] #devguard #cli Color vs NO_COLOR policy

## R. Persistence, schemas, retention

_16 tasks_

- [ ] #devguard #store SQLite PRAGMA foreign_keys + WAL mode
- [ ] #devguard #store Migration version table
- [ ] #devguard #store runs table columns + indexes
- [ ] #devguard #store observations table blob/json columns
- [ ] #devguard #store snapshots table + labels unique per host
- [ ] #devguard #store findings table + severity index
- [ ] #devguard #store backup_jobs / backup_verifications tables
- [ ] #devguard #store slm_runs table or filesystem layout decision
- [ ] #devguard #store Export DB to JSON for offline analysis
- [ ] #devguard #store Import fixtures into DB for demo
- [ ] #devguard #store Schema evolution tests backward compatible
- [ ] #devguard #store JSON Schema files for all envelopes
- [ ] #devguard #store Retention dry-run lists deletable run ids
- [ ] #devguard #store Vacuum after retention apply
- [ ] #devguard #store DB file mode 0600
- [ ] #devguard #store Backup of SQLite itself in recovery design

## S. Threat model & redaction — deep

_14 tasks_

- [ ] #devguard #security Never log GITHUB_TOKEN / API keys (tests)
- [ ] #devguard #security Redact user:pass@ in URLs
- [ ] #devguard #security Redact password=/token= assignments
- [ ] #devguard #security Treat filenames as data; no shell interpolation
- [ ] #devguard #security Canonicalize restore paths; reject escapes
- [ ] #devguard #security Baseline DB local integrity notes (later signed digest)
- [ ] #devguard #security No listening sockets by default (assert in tests)
- [ ] #devguard #security Missing sensor ≠ healthy (property across collectors)
- [ ] #devguard #security Path allowlists for hashing only
- [ ] #devguard #security model_dirs inventory never uploads weights
- [ ] #devguard #security Process cmdline truncation + redaction
- [ ] #devguard #security SSH log adapter strips hashes carefully / limits lines
- [ ] #devguard #security Document threat table from SPEC §8 in security-model.md expansion
- [ ] #devguard #security Dependency pin review for clap/serde/rusqlite

## T. Fixture catalog (tests/fixtures)

_23 tasks_

- [ ] #devguard #fixtures nvidia-smi CSV: single GPU happy path
- [ ] #devguard #fixtures nvidia-smi CSV: multi GPU
- [ ] #devguard #fixtures nvidia-smi: command not found
- [ ] #devguard #fixtures nvidia-smi: permission / driver mismatch stderr
- [ ] #devguard #fixtures sensors: typical desktop chips
- [ ] #devguard #fixtures sensors: empty / missing
- [ ] #devguard #fixtures ss -lntup: with and without process fields
- [ ] #devguard #fixtures systemctl: failed units present
- [ ] #devguard #fixtures os-release Ubuntu 26.04 sample
- [ ] #devguard #fixtures dpkg-query truncated package list
- [ ] #devguard #fixtures upgrade-diff: kernel change
- [ ] #devguard #fixtures upgrade-diff: NVIDIA driver change
- [ ] #devguard #fixtures upgrade-diff: new listening port
- [ ] #devguard #fixtures upgrade-diff: package add/remove
- [ ] #devguard #fixtures git status porcelain dirty/untracked
- [ ] #devguard #fixtures git rev-list unpushed
- [ ] #devguard #fixtures restic snapshots JSON
- [ ] #devguard #fixtures ufw status verbose
- [ ] #devguard #fixtures auth.log failed ssh samples sanitized
- [ ] #devguard #fixtures slm harness annotations complete/partial
- [ ] #devguard #fixtures llama-bench JSON import sample
- [ ] #devguard #fixtures vLLM metrics text exposition sample
- [ ] #devguard #fixtures token-like strings for redaction tests

## U. Synergy execution playbooks

_12 tasks_

- [ ] #devguard #synergy/slm-setup #playbook Playbook: live Ollama accept + DevGuard bracket on same host
- [ ] #devguard #synergy/slm-setup #playbook Playbook: SSH-forwarded downstairs GPU + local DevGuard doctor
- [ ] #devguard #synergy/embabel-slm #playbook Playbook: one paper cell end-to-end (run → export → table)
- [ ] #devguard #synergy/embabel-slm #playbook Playbook: base vs retrieval efficiency comparison week
- [ ] #devguard #synergy/obsidian-mcp #playbook Playbook: import deep backlog into vault AI Memory
- [ ] #devguard #synergy/obsidian-mcp #playbook Playbook: weekly STATUS.md sync + decision capture
- [ ] #devguard #synergy/sdlc-spdd #playbook Playbook: open Work ID for next SLM collector slice
- [ ] #devguard #synergy/docgen #playbook Playbook: record 3-minute metrics demo video
- [ ] #devguard #synergy/slm-setup #playbook Playbook: correlate eval scores with J/token across models
- [ ] #devguard #playbook Playbook: pre-Ubuntu-upgrade snapshot ritual
- [ ] #devguard #playbook Playbook: fan-regression data capture without changing BIOS
- [ ] #devguard #playbook Playbook: backup restore drill quarterly

## V. Parked / future (explicitly deferred)

_14 tasks_

- [ ] #devguard #future Windows agent parity
- [ ] #devguard #future macOS sensors / powermetrics adapter
- [ ] #devguard #future Automatic remediation (NEVER in MVP — keep parked)
- [ ] #devguard #future Always-on privileged daemon (rejected)
- [ ] #devguard #future Cloud control plane (rejected)
- [ ] #devguard #future Homemade backup cryptosystem (rejected)
- [ ] #devguard #future Full EDR / packet inspection (rejected)
- [ ] #devguard #future Signed baseline digests phase 2
- [ ] #devguard #future Keyring-backed restic passwords
- [ ] #devguard #future Grafana dashboard from exported JSONL
- [ ] #devguard #future ROCm collector productionization
- [ ] #devguard #future Jetson / edge power-mode locking helpers
- [ ] #devguard #future Multi-node Halo cluster authenticated agent
- [ ] #devguard #future Training FLOPs accounting (leave to embabel-slm)

---

**Count:** 399 tasks · **done:** 4 · **open:** 395

## Obsidian Tasks

```tasks
not done
tags include #synergy/slm-setup
```

```tasks
not done
tags include #slm
path includes docs/tasks
```
