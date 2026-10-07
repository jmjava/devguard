#!/usr/bin/env python3
"""Generate deep DevGuard task backlog + manifest for Obsidian MCP reload."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STORE = ROOT / "docs" / "tasks"

# Each item: (done, tags, title)
# Tags always include #devguard; add milestone/synergy tags.

SECTIONS: list[tuple[str, list[tuple[bool, str, str]]]] = []


def T(done: bool, tags: str, title: str) -> tuple[bool, str, str]:
    return (done, tags, title)


def section(name: str, items: list[tuple[bool, str, str]]) -> None:
    SECTIONS.append((name, items))


# --- A. Foundation / M0 ---
section(
    "A. Foundation (M0) — deepen & harden",
    [
        T(True, "#m0", "Cargo workspace: devguard-cli + devguard-core"),
        T(True, "#m0", "CLI: help, doctor, config init|validate, status + JSON envelopes/exit codes"),
        T(True, "#m0", "TOML config validation, redaction helpers, CI fmt/clippy/test"),
        T(True, "#m0 #slm", "Literature map + SlmRunRecord schema/types"),
        T(False, "#m0", "Add CHANGELOG.md with Keep-a-Changelog format"),
        T(False, "#m0", "Add CONTRIBUTING.md with SPEC §11 Cursor milestone workflow"),
        T(False, "#m0", "Add CODE_OF_CONDUCT / SECURITY.md disclosure process"),
        T(False, "#m0", "Decision: restic vs rustic as sole M4 engine"),
        T(False, "#m0", "Decision: SQLite vs JSON-file snapshots for M1 persistence"),
        T(False, "#m0", "Decision: credential mechanism (password-file vs FD vs keyring)"),
        T(False, "#m0", "Pin MSRV in CI matrix (1.85 + stable)"),
        T(False, "#m0", "Add cargo deny / audit job for supply-chain"),
        T(False, "#m0", "Document exit codes 0/1/2/3/64 in --help and man-style docs"),
        T(False, "#m0", "Structured tracing fields with redaction layer on Display"),
        T(False, "#m0", "Config schema_version migration stub (v1 only, tested)"),
        T(False, "#m0", "XDG path override tests for --config and custom state dir"),
        T(False, "#m0", "Refuse world-writable config files with clear error"),
        T(False, "#m0", "Doctor JSON schema fixture in docs/schemas/"),
        T(False, "#m0", "Smoke script scripts/smoke_m0.sh for offline Ubuntu"),
        T(False, "#m0", "README quickstart GIF/asciinema via docgen synergy later"),
    ],
)

# --- B. SLM collectors & research ---
section(
    "B. SLM collectors & research harness",
    [
        T(False, "#slm", "NVIDIA collector: name, UUID hash, driver, CUDA version if readable"),
        T(False, "#slm", "NVIDIA collector: utilization.gpu / utilization.memory %"),
        T(False, "#slm", "NVIDIA collector: memory.used / memory.total bytes"),
        T(False, "#slm", "NVIDIA collector: temperature.gpu °C"),
        T(False, "#slm", "NVIDIA collector: power.draw / power.limit watts"),
        T(False, "#slm", "NVIDIA collector: clocks.sm / clocks.mem MHz when available"),
        T(False, "#slm", "NVIDIA collector: fan.speed % if exposed"),
        T(False, "#slm", "NVIDIA collector: ecc / throttling reasons when readable"),
        T(False, "#slm", "Multi-GPU enumeration with stable index ordering"),
        T(False, "#slm", "Host sample: loadavg 1/5/15"),
        T(False, "#slm", "Host sample: CPU percent (sysinfo)"),
        T(False, "#slm", "Host sample: memory used/total/available + swap"),
        T(False, "#slm", "Host sample: disk free/total for model_dirs mount points"),
        T(False, "#slm", "Host sample: top-N processes filtered by slm.process_name_hints"),
        T(False, "#slm", "Mark CollectionStatus Unavailable when nvidia-smi missing"),
        T(False, "#slm", "Timeouts + bounded stdout capture for all nvidia-smi calls"),
        T(False, "#slm", "Fixture parsers from sanitized nvidia-smi CSV"),
        T(False, "#slm", "devguard gpu scan --json one-shot"),
        T(False, "#slm", "devguard health scan includes GPU block when capture_gpu"),
        T(False, "#slm", "devguard slm run begin --label --backend --model"),
        T(False, "#slm", "devguard slm run sample (manual mid-run sample)"),
        T(False, "#slm", "devguard slm run end --annotations path.json"),
        T(False, "#slm", "Background sampler thread/process with interval from config"),
        T(False, "#slm", "Persist run under ~/.local/state/devguard/slm-runs/<id>/"),
        T(False, "#slm", "Write run.json + samples.jsonl per run"),
        T(False, "#slm", "Ingest harness annotations: ttft/tpot p50/p99"),
        T(False, "#slm", "Ingest harness annotations: prompt/output tokens, batch, ctx"),
        T(False, "#slm", "Ingest harness annotations: quantization, backend, git_commit"),
        T(False, "#slm", "Ingest quality: task_name, metric, score"),
        T(False, "#slm", "Derive energy_gpu_approx_j from mean power × duration"),
        T(False, "#slm", "Derive joules_per_token / tokens_per_joule / throughput_per_watt"),
        T(False, "#slm", "Label measurement_plane gpu_rail|wall_ac|mixed|unknown"),
        T(False, "#slm", "Optional energy_wall_j field from external meter file"),
        T(False, "#slm", "devguard slm list [--json]"),
        T(False, "#slm", "devguard slm show <run_id> [--json]"),
        T(False, "#slm", "devguard slm export --format csv|json|markdown"),
        T(False, "#slm", "Export columns match academic 10-field checklist"),
        T(False, "#slm", "Cool-down reminder using suggested_cooldown_seconds"),
        T(False, "#slm", "Reject incomplete cells when --strict-paper flag set"),
        T(False, "#slm", "Unit tests for energy derivation edge cases (zero duration/tokens)"),
        T(False, "#slm", "Integration: mock nvidia-smi script on PATH"),
    ],
)

# --- C. Synergy: slm-setup ---
section(
    "C. Synergy — jmjava/slm-setup (Ollama MCP bridge)",
    [
        T(False, "#synergy/slm-setup #slm", "Document adapter: wrap prove_acceptance.py with slm run begin/end"),
        T(False, "#synergy/slm-setup #slm", "Parse slm-setup harness JSONL into ExperimentMeta + LatencyMetrics"),
        T(False, "#synergy/slm-setup #slm", "Map OLLAMA_BASE_URL safety: refuse public endpoints (align check_deployment_safety)"),
        T(False, "#synergy/slm-setup #slm", "Process hints include ollama + model runner names from slm-setup"),
        T(False, "#synergy/slm-setup #slm", "Capture metrics during scripts/run_harness.py live backend profile"),
        T(False, "#synergy/slm-setup #slm", "Capture metrics during prove_refactor_acceptance fast/strong models"),
        T(False, "#synergy/slm-setup #slm", "Tag runs with eval profile: observed|golden|stub"),
        T(False, "#synergy/slm-setup #slm", "Correlate transport/format/structure/behavior scores with J/token"),
        T(False, "#synergy/slm-setup #slm", "Downstairs WSL-GPU host profile example (SSH forward) in docs"),
        T(False, "#synergy/slm-setup #slm", "Halo Ryzen AI host profile placeholders for future AMD collector"),
        T(False, "#synergy/slm-setup #m7", "Shared threat model: no public Ollama, no remote shell in DevGuard agent"),
        T(False, "#synergy/slm-setup #slm", "Example config snippet linking model_dirs to Ollama model store"),
        T(False, "#synergy/slm-setup #slm", "CI note: GPU metrics only on workstation; fixtures offline"),
        T(False, "#synergy/slm-setup #slm", "Cross-link evaluation-protocol.md metrics to SlmRunRecord.quality"),
        T(False, "#synergy/slm-setup #slm", "Script: scripts/synergy_slm_setup_bracket.sh template"),
    ],
)

# --- D. Synergy: embabel-slm ---
section(
    "D. Synergy — jmjava/embabel-slm (research / paper)",
    [
        T(False, "#synergy/embabel-slm #slm", "Align export schema with embabel-slm paper table needs"),
        T(False, "#synergy/embabel-slm #slm", "Support experiment cells: base vs retrieval vs LoRA labels"),
        T(False, "#synergy/embabel-slm #slm", "Pin official Ollama tags only in example configs (per standing rules)"),
        T(False, "#synergy/embabel-slm #slm", "Never commit weights; inventory model_dirs sizes only"),
        T(False, "#synergy/embabel-slm #slm", "Record git_commit + experiment dir path (refuse overwrite semantics)"),
        T(False, "#synergy/embabel-slm #slm", "Pareto plot data export (accuracy vs J/token) as JSON for paper figs"),
        T(False, "#synergy/embabel-slm #slm", "Zenodo/TechRxiv artifact packing checklist in docs"),
        T(False, "#synergy/embabel-slm #slm", "Citation workflow: store BibTeX keys used for metric definitions"),
        T(False, "#synergy/embabel-slm #slm", "Holdout-task runs tagged separately from training-split runs"),
        T(False, "#synergy/embabel-slm #slm", "Compiler-accepted vs rejected generation outcome as quality metric"),
        T(False, "#synergy/embabel-slm #slm", "Spring/Kotlin pattern-card eval latency capture"),
        T(False, "#synergy/embabel-slm #slm", "Paper calendar milestones mapped to DevGuard export readiness"),
        T(False, "#synergy/embabel-slm #slm", "Document measurement_plane honesty for preprint methods section"),
        T(False, "#synergy/embabel-slm #slm", "Template methods paragraph for GPU-rail energy estimation"),
        T(False, "#synergy/embabel-slm #slm", "Compare qwen3.5:9b vs devstral-small-2 efficiency cells"),
    ],
)

# --- E. Synergy: obsidian-mcp ---
section(
    "E. Synergy — jmjava/obsidian-mcp (vault memory)",
    [
        T(False, "#synergy/obsidian-mcp", "Vault note sync path for docs/tasks/backlog-deep.md"),
        T(False, "#synergy/obsidian-mcp", "MCP reload recipe: read manifest.json into vault AI Memory"),
        T(False, "#synergy/obsidian-mcp", "After slm run end → capture_work_session template fields"),
        T(False, "#synergy/obsidian-mcp", "record_decision templates for DevGuard open design questions"),
        T(False, "#synergy/obsidian-mcp", "get_project_context('devguard') starter note content"),
        T(False, "#synergy/obsidian-mcp", "Tag taxonomy shared: #m0-#m7 #slm #synergy/*"),
        T(False, "#synergy/obsidian-mcp", "Dataview queries committed beside backlog"),
        T(False, "#synergy/obsidian-mcp", "Tasks plugin queries for not-done #slm"),
        T(False, "#synergy/obsidian-mcp", "Export STATUS.md into vault dashboard note"),
        T(False, "#synergy/obsidian-mcp", "Document OBSIDIAN_VAULT_PATH usage without requiring Obsidian running"),
        T(False, "#synergy/obsidian-mcp", "Script to push completed task IDs from git to vault"),
        T(False, "#synergy/obsidian-mcp", "Avoid secrets in vault notes (align redaction)"),
    ],
)

# --- F. Synergy: SDLC-SPDD / docgen ---
section(
    "F. Synergy — sdlc-spdd-orchestrator & documentation-generator",
    [
        T(False, "#synergy/sdlc-spdd", "Create SPDD Work ID canvas for DevGuard M1 slice"),
        T(False, "#synergy/sdlc-spdd", "Create SPDD Work ID canvas for SLM metrics vertical"),
        T(False, "#synergy/sdlc-spdd", "Map SPEC milestones to ROADMAP.md style ledger entries"),
        T(False, "#synergy/sdlc-spdd", "Capture pitfalls from failed collectors into lessons.jsonl shape"),
        T(False, "#synergy/sdlc-spdd", "Quiet-mode note when dogfooding SDLC on DevGuard itself"),
        T(False, "#synergy/docgen", "docgen scene outline: doctor → gpu scan → slm export"),
        T(False, "#synergy/docgen", "docgen scene outline: snapshot pre/post upgrade diff"),
        T(False, "#synergy/docgen", "Narrated demo script Markdown for academic metrics walkthrough"),
        T(False, "#synergy/docgen", "PlantUML/C4 snippet linking DevGuard + slm-setup + embabel-slm"),
        T(False, "#synergy/docgen", "Publish demo to GitHub Pages when ready"),
    ],
)

# --- G. External ecosystem adapters ---
section(
    "G. External ecosystem adapters (don't reinvent)",
    [
        T(False, "#slm #ecosystem", "Import adapter: llama-bench JSON → LatencyMetrics (pp/tg/pg)"),
        T(False, "#slm #ecosystem", "Document llama-bench gap: no TTFT/VRAM/energy — DevGuard fills"),
        T(False, "#slm #ecosystem", "Optional vLLM /metrics scrape during slm run (TTFT/TPOT histograms)"),
        T(False, "#slm #ecosystem", "Document Zeus window API as preferred energy when Python harness uses it"),
        T(False, "#slm #ecosystem", "Ingest Zeus/NVML joules as energy_wall_j or energy_gpu when labeled"),
        T(False, "#slm #ecosystem", "DCGM field mapping doc (power, util, mem, energy counter)"),
        T(False, "#slm #ecosystem", "Interop CSV with llm-inference-benchmark columns"),
        T(False, "#slm #ecosystem", "Interop notes for LLenergyMeasure study exports"),
        T(False, "#slm #ecosystem", "MLPerf metric naming alignment (TTFT/TPOT p99, tokens/s)"),
        T(False, "#slm #ecosystem", "CodeCarbon optional annotation path (not default)"),
        T(False, "#slm #ecosystem", "RAPL CPU energy optional on Linux when readable"),
        T(False, "#slm #ecosystem", "Prometheus export sketch (opt-in, off by default — SPEC no listeners)"),
        T(False, "#slm #ecosystem", "Explicit decision: file/JSONL export first, no daemon metrics port in MVP"),
    ],
)

# --- H. M1 Snapshot deep ---
section(
    "H. Snapshot / upgrade guardian (M1) — deep",
    [
        T(False, "#m1", "Introduce crate devguard-store with rusqlite bundled"),
        T(False, "#m1", "Migrations: runs, observations, snapshots, findings tables"),
        T(False, "#m1", "Retention config + dry-run cleanup command"),
        T(False, "#m1", "Run status enum: complete|partial|failed per provider"),
        T(False, "#m1", "Collector trait wired for host inventory"),
        T(False, "#m1", "OS release/version/arch collector (/etc/os-release)"),
        T(False, "#m1", "Kernel version + boot_id collector"),
        T(False, "#m1", "Uptime collector"),
        T(False, "#m1", "Hostname hash (privacy-preserving, stable)"),
        T(False, "#m1", "APT package list parser (dpkg-query) with fixtures"),
        T(False, "#m1", "Pending updates collector when readable without root magic"),
        T(False, "#m1", "Optional Snap list collector (Unavailable if missing)"),
        T(False, "#m1", "systemctl list-units enabled/running/failed parsers"),
        T(False, "#m1", "ss -lntup parser; missing process attribution flag"),
        T(False, "#m1", "NVIDIA driver/GPU summary in snapshot (reuse SLM collector)"),
        T(False, "#m1", "PCI devices of interest filter"),
        T(False, "#m1", "Loaded kernel modules names collector"),
        T(False, "#m1", "Toolchain version probes: rustc cargo gcc clang java python node git docker"),
        T(False, "#m1", "Config allowlist hashing (blake3/sha256) metadata only"),
        T(False, "#m1", "snapshot create --label pre-upgrade|post-upgrade"),
        T(False, "#m1", "snapshot list --json"),
        T(False, "#m1", "snapshot diff deterministic ordering"),
        T(False, "#m1", "Diff categories: added|removed|changed with severity hints"),
        T(False, "#m1", "Fixture: simulated Ubuntu upgrade kernel+driver+port+package"),
        T(False, "#m1", "Fixture: permission denied → Partial not clean"),
        T(False, "#m1", "Fixture: tool missing → Unavailable coverage"),
        T(False, "#m1", "status command shows latest snapshot timestamps"),
        T(False, "#m1", "JSON schema for snapshot documents"),
        T(False, "#m1", "Bench: typical snapshot finishes in seconds on healthy host"),
    ],
)

# --- I. M2 Health deep ---
section(
    "I. Health & fan diagnostics (M2) — deep",
    [
        T(False, "#m2", "Crate devguard-health"),
        T(False, "#m2", "sysinfo CPU/memory/disk/process collection"),
        T(False, "#m2", "Redact sensitive argv in top processes"),
        T(False, "#m2", "lm-sensors adapter parse chips/temps/fans"),
        T(False, "#m2", "Distinguish CPU/package/board/GPU fan labels"),
        T(False, "#m2", "health scan human + JSON"),
        T(False, "#m2", "health watch TUI with ratatui + crossterm"),
        T(False, "#m2", "health watch interval bounds + Ctrl+C cleanup"),
        T(False, "#m2", "No background service/daemon in watch mode"),
        T(False, "#m2", "Threshold warnings from health.warn_* config"),
        T(False, "#m2", "Fan-regression report template (observations vs hypotheses)"),
        T(False, "#m2", "Include failed systemd units in fan-regression context"),
        T(False, "#m2", "Include kernel + NVIDIA driver in fan-regression context"),
        T(False, "#m2", "Tests: no sensors binary → Unavailable"),
        T(False, "#m2", "Tests: no NVIDIA → Unavailable GPU block"),
        T(False, "#m2", "Document non-sudo ordinary scanning"),
        T(False, "#m2", "Optional I/O wait stats when /proc provides"),
        T(False, "#m2", "Thermal throttle detection note when nvml throttling present"),
    ],
)

# --- J. M3 Security deep ---
section(
    "J. Security Sentinel (M3) — deep",
    [
        T(False, "#m3", "Crate devguard-security"),
        T(False, "#m3", "Finding model: severity info|warning|critical|unknown + source/confidence"),
        T(False, "#m3", "Rule docs for every finding id"),
        T(False, "#m3", "Listening port drift vs baseline"),
        T(False, "#m3", "Service enablement drift vs baseline"),
        T(False, "#m3", "ufw status parser"),
        T(False, "#m3", "nftables detection without claiming full audit"),
        T(False, "#m3", "SSH config readable checks (PermitRootLogin etc.)"),
        T(False, "#m3", "SSH exposure: listening 22 on non-localhost"),
        T(False, "#m3", "journalctl/auth log adapter for failed logins (bounded)"),
        T(False, "#m3", "Never copy credentials or full journal payloads"),
        T(False, "#m3", "Ubuntu security update status interfaces"),
        T(False, "#m3", "Never auto-install updates"),
        T(False, "#m3", "Allowlisted path permission checks"),
        T(False, "#m3", "security scan / diff / findings CLI"),
        T(False, "#m3", "Fixtures: normal drift vs actionable warning"),
        T(False, "#m3", "Fixtures: missing perms ≠ clean"),
        T(False, "#m3", "Unfamiliar process is NOT malware proof (document)"),
        T(False, "#m3", "Opt-in dependency audit hook deferred to M5"),
    ],
)

# --- K. M4 Backup deep ---
section(
    "K. Backup Guardian (M4) — deep",
    [
        T(False, "#m4", "Crate devguard-backup"),
        T(False, "#m4", "Engine trait with restic OR rustic implementation (one first)"),
        T(False, "#m4", "Version pin + detect unsupported engine versions"),
        T(False, "#m4", "Credential via password file / FD only; test no argv leakage"),
        T(False, "#m4", "backup plan dry-run JSON"),
        T(False, "#m4", "Warn on excluded huge models (gguf/bin/models/**)"),
        T(False, "#m4", "Warn on unreadable includes"),
        T(False, "#m4", "backup run against configured repository only"),
        T(False, "#m4", "backup list snapshots"),
        T(False, "#m4", "backup verify metadata|sample|full modes"),
        T(False, "#m4", "Record backup_jobs + backup_verifications tables"),
        T(False, "#m4", "restore --dry-run default path"),
        T(False, "#m4", "restore --apply requires confirmation"),
        T(False, "#m4", "Block path traversal and symlink escape"),
        T(False, "#m4", "Refuse dangerous destinations (/, /etc, $HOME bare)"),
        T(False, "#m4", "Integration test synthetic dir hash roundtrip"),
        T(False, "#m4", "forget/prune explicitly NOT automatic (future feature flag)"),
        T(False, "#m4", "Runbook offsite/immutable media + restore drills"),
        T(False, "#m4", "Include DevGuard DB in recovery design notes"),
    ],
)

# --- L. M5 Dev deep ---
section(
    "L. Developer Workflow Guardian (M5) — deep",
    [
        T(False, "#m5", "Crate devguard-dev"),
        T(False, "#m5", "dev env inventory compilers/SDKs/package managers"),
        T(False, "#m5", "Reproducibility report language (not bit-identical claim)"),
        T(False, "#m5", "Scan repo_roots for git repos safely (no shell interpolation)"),
        T(False, "#m5", "Detect dirty worktree / untracked / branch / upstream"),
        T(False, "#m5", "Detect unpushed commits without network fetch by default"),
        T(False, "#m5", "dev repos scan --json"),
        T(False, "#m5", "Opt-in cargo audit adapter"),
        T(False, "#m5", "Opt-in npm audit adapter"),
        T(False, "#m5", "Opt-in Python audit adapter"),
        T(False, "#m5", "Opt-in Maven/Gradle scanner stub"),
        T(False, "#m5", "allow_network_audits gate enforced"),
        T(False, "#m5", "Redact token-like strings in logs (fixture test)"),
        T(False, "#m5", "Reuse inventory in snapshot diffs"),
        T(False, "#m5", "Synergy: flag embabel-slm / slm-setup / docgen dirty repos in multi-root scan"),
    ],
)

# --- M. M6/M7 Ops ---
section(
    "M. Ops hardening & multi-node (M6–M7) — deep",
    [
        T(False, "#m6", "systemd --user timer unit templates (opt-in)"),
        T(False, "#m6", "Document how to disable timers completely"),
        T(False, "#m6", "No privileged system daemon"),
        T(False, "#m6", "Local alert: write report file under state dir"),
        T(False, "#m6", "Optional desktop notification if tool present"),
        T(False, "#m6", "DB retention cleanup --dry-run then --apply"),
        T(False, "#m6", "Idle overhead benchmark script + results doc"),
        T(False, "#m6", "Packaging notes (cargo install / distro later)"),
        T(False, "#m6", "Release checklist + signed tags process"),
        T(False, "#m7", "Multi-node architecture PoC doc only first"),
        T(False, "#m7", "Threat model review before any listener"),
        T(False, "#m7", "mTLS + peer allowlist design"),
        T(False, "#m7", "Allowlisted metrics API (CPU/GPU/VRAM/temp/disk)"),
        T(False, "#m7", "Explicitly no remote shell interface"),
        T(False, "#m7", "SSH user-initiated collection alternative (no agent)"),
        T(False, "#m7", "AMD ROCm/Halo adapter spike after NVIDIA stable"),
        T(False, "#m7 #synergy/slm-setup", "Align Halo host profile with slm-setup examples/halo-ryzen-ai.md"),
    ],
)

# --- N. Quality / DoD cross-cutting ---
section(
    "N. Cross-cutting quality, security, docs",
    [
        T(False, "#quality", "Every milestone: unit tests for parsers/diff/path handling"),
        T(False, "#quality", "Sanitized fixtures; no dependence on personal hardware in CI"),
        T(False, "#quality", "Integration tests in disposable dirs"),
        T(False, "#quality", "Manual acceptance commands documented with actual results"),
        T(False, "#quality", "Permissions + prerequisites + rollback docs per command"),
        T(False, "#quality", "Update SPEC decision log when interfaces change"),
        T(False, "#quality", "JSON determinism tests excluding timestamps/ids"),
        T(False, "#quality", "Property tests for redaction (secrets never leak)"),
        T(False, "#quality", "Fuzz parsers for ss/sensors/nvidia-smi CSV"),
        T(False, "#quality", "Clippy -D warnings enforced in CI"),
        T(False, "#quality", "cargo fmt --check in CI"),
        T(False, "#quality", "Coverage report optional job"),
        T(False, "#quality", "SBOM generation for releases"),
        T(False, "#quality", "Reproducible builds notes"),
        T(False, "#quality", "Accessibility of human CLI output (no emoji reliance)"),
        T(False, "#quality", "Internationalization: keep English MVP; avoid hard-coded locale assumes"),
    ],
)

# --- O. Academic paper metrics (granular) ---
section(
    "O. Academic paper metrics — granular fields",
    [
        T(False, "#slm #paper", "Field: model_id stable string"),
        T(False, "#slm #paper", "Field: parameter_count integer"),
        T(False, "#slm #paper", "Field: quantization enum/string (Q4_K_M, Q8_0, fp16, …)"),
        T(False, "#slm #paper", "Field: backend enum (ollama, llama.cpp, vllm, hf, other)"),
        T(False, "#slm #paper", "Field: batch_size"),
        T(False, "#slm #paper", "Field: context_length / n_ctx"),
        T(False, "#slm #paper", "Field: prompt_tokens / output_tokens"),
        T(False, "#slm #paper", "Field: ttft_ms mean"),
        T(False, "#slm #paper", "Field: ttft_p50_ms / ttft_p99_ms"),
        T(False, "#slm #paper", "Field: tpot_ms mean"),
        T(False, "#slm #paper", "Field: tpot_p50_ms / tpot_p99_ms"),
        T(False, "#slm #paper", "Field: e2e_latency_ms"),
        T(False, "#slm #paper", "Field: tokens_per_second + throughput_kind"),
        T(False, "#slm #paper", "Field: peak_vram_bytes / peak_host_rss_bytes"),
        T(False, "#slm #paper", "Field: mean_gpu_power_w / max_gpu_power_w"),
        T(False, "#slm #paper", "Field: energy_gpu_approx_j / joules_per_token / tokens_per_joule"),
        T(False, "#slm #paper", "Field: throughput_per_watt"),
        T(False, "#slm #paper", "Field: energy_delay_product optional"),
        T(False, "#slm #paper", "Field: mean/max gpu_temperature_c"),
        T(False, "#slm #paper", "Field: task_name / task_metric / task_score / higher_is_better"),
        T(False, "#slm #paper", "Field: repetitions + stddev for llama-bench style averages"),
        T(False, "#slm #paper", "Field: cool_down_seconds_observed"),
        T(False, "#slm #paper", "Field: power_mode / n_gpu_layers / flash_attn flags"),
        T(False, "#slm #paper", "Field: dataset_id / prompt_suite for ShareGPT-style loads"),
        T(False, "#slm #paper", "Validate required fields for --paper-ready export mode"),
        T(False, "#slm #paper", "Markdown table renderer matching embabel-slm paper outline"),
        T(False, "#slm #paper", "BibTeX keys for Lu2024, Wang2025, MLENERGY, MLPerf in docs"),
        T(False, "#slm #paper", "Methods boilerplate: GPU-rail vs wall-AC disclaimer"),
        T(False, "#slm #paper", "Pareto CSV: task_score vs joules_per_token"),
        T(False, "#slm #paper", "Ablation export: vary quant holding model/backend fixed"),
    ],
)

# --- P. Workstation / Ubuntu / hardware ---
section(
    "P. Workstation profile — Ubuntu & ASUS/RTX lab",
    [
        T(False, "#host", "Document target: Ubuntu 26.04 x86_64 primary"),
        T(False, "#host", "Document hardware profile: ASUS PRIME Z490-P + RTX 3060"),
        T(False, "#host", "Doctor check: NVIDIA driver present for 3060 class"),
        T(False, "#host", "Fan-regression runbook for this chassis (SPEC special prompt)"),
        T(False, "#host", "Collect motherboard/case fan RPM labels when sensors expose"),
        T(False, "#host", "Collect GPU fan separately from chassis fans"),
        T(False, "#host", "Note BIOS fan curve out of scope (read-only)"),
        T(False, "#host", "smartctl optional disk health (Unavailable without perms)"),
        T(False, "#host", "Confirm package availability list for Ubuntu 26.04 tools"),
        T(False, "#host", "Secondary distro notes (Debian/Fedora) as adapter isolations"),
        T(False, "#host", "WSL2 GPU caveats doc (synergy downstairs-wsl-gpu)"),
        T(False, "#host", "Resource limits: subprocess timeouts defaults table"),
        T(False, "#host", "Bounded memory for large apt inventory diffs"),
    ],
)

# --- Q. CLI UX surface area ---
section(
    "Q. CLI surface — every command & flag",
    [
        T(False, "#cli", "Global --config path"),
        T(False, "#cli", "Global --json stdout contract"),
        T(False, "#cli", "doctor human formatting polish"),
        T(False, "#cli", "status shows last slm run + last snapshot"),
        T(False, "#cli", "config init --force behavior tested"),
        T(False, "#cli", "config validate warnings → exit 3"),
        T(False, "#cli", "snapshot create/list/diff help texts: mutates? privileges?"),
        T(False, "#cli", "health scan/watch help texts"),
        T(False, "#cli", "gpu scan help texts"),
        T(False, "#cli", "security scan/diff/findings help texts"),
        T(False, "#cli", "backup plan/run/list/verify/restore help texts"),
        T(False, "#cli", "dev env/repos/deps help texts"),
        T(False, "#cli", "slm run begin/end/list/show/export help texts"),
        T(False, "#cli", "Shell completions: bash/zsh/fish via clap"),
        T(False, "#cli", "man page generation optional"),
        T(False, "#cli", "Cancelation: Ctrl+C kills child processes"),
        T(False, "#cli", "--include-paths documented opt-in only"),
        T(False, "#cli", "Color vs NO_COLOR policy"),
    ],
)

# --- R. Persistence & schemas ---
section(
    "R. Persistence, schemas, retention",
    [
        T(False, "#store", "SQLite PRAGMA foreign_keys + WAL mode"),
        T(False, "#store", "Migration version table"),
        T(False, "#store", "runs table columns + indexes"),
        T(False, "#store", "observations table blob/json columns"),
        T(False, "#store", "snapshots table + labels unique per host"),
        T(False, "#store", "findings table + severity index"),
        T(False, "#store", "backup_jobs / backup_verifications tables"),
        T(False, "#store", "slm_runs table or filesystem layout decision"),
        T(False, "#store", "Export DB to JSON for offline analysis"),
        T(False, "#store", "Import fixtures into DB for demo"),
        T(False, "#store", "Schema evolution tests backward compatible"),
        T(False, "#store", "JSON Schema files for all envelopes"),
        T(False, "#store", "Retention dry-run lists deletable run ids"),
        T(False, "#store", "Vacuum after retention apply"),
        T(False, "#store", "DB file mode 0600"),
        T(False, "#store", "Backup of SQLite itself in recovery design"),
    ],
)

# --- S. Threat model & redaction deep ---
section(
    "S. Threat model & redaction — deep",
    [
        T(False, "#security", "Never log GITHUB_TOKEN / API keys (tests)"),
        T(False, "#security", "Redact user:pass@ in URLs"),
        T(False, "#security", "Redact password=/token= assignments"),
        T(False, "#security", "Treat filenames as data; no shell interpolation"),
        T(False, "#security", "Canonicalize restore paths; reject escapes"),
        T(False, "#security", "Baseline DB local integrity notes (later signed digest)"),
        T(False, "#security", "No listening sockets by default (assert in tests)"),
        T(False, "#security", "Missing sensor ≠ healthy (property across collectors)"),
        T(False, "#security", "Path allowlists for hashing only"),
        T(False, "#security", "model_dirs inventory never uploads weights"),
        T(False, "#security", "Process cmdline truncation + redaction"),
        T(False, "#security", "SSH log adapter strips hashes carefully / limits lines"),
        T(False, "#security", "Document threat table from SPEC §8 in security-model.md expansion"),
        T(False, "#security", "Dependency pin review for clap/serde/rusqlite"),
    ],
)

# --- T. Fixtures catalog ---
section(
    "T. Fixture catalog (tests/fixtures)",
    [
        T(False, "#fixtures", "nvidia-smi CSV: single GPU happy path"),
        T(False, "#fixtures", "nvidia-smi CSV: multi GPU"),
        T(False, "#fixtures", "nvidia-smi: command not found"),
        T(False, "#fixtures", "nvidia-smi: permission / driver mismatch stderr"),
        T(False, "#fixtures", "sensors: typical desktop chips"),
        T(False, "#fixtures", "sensors: empty / missing"),
        T(False, "#fixtures", "ss -lntup: with and without process fields"),
        T(False, "#fixtures", "systemctl: failed units present"),
        T(False, "#fixtures", "os-release Ubuntu 26.04 sample"),
        T(False, "#fixtures", "dpkg-query truncated package list"),
        T(False, "#fixtures", "upgrade-diff: kernel change"),
        T(False, "#fixtures", "upgrade-diff: NVIDIA driver change"),
        T(False, "#fixtures", "upgrade-diff: new listening port"),
        T(False, "#fixtures", "upgrade-diff: package add/remove"),
        T(False, "#fixtures", "git status porcelain dirty/untracked"),
        T(False, "#fixtures", "git rev-list unpushed"),
        T(False, "#fixtures", "restic snapshots JSON"),
        T(False, "#fixtures", "ufw status verbose"),
        T(False, "#fixtures", "auth.log failed ssh samples sanitized"),
        T(False, "#fixtures", "slm harness annotations complete/partial"),
        T(False, "#fixtures", "llama-bench JSON import sample"),
        T(False, "#fixtures", "vLLM metrics text exposition sample"),
        T(False, "#fixtures", "token-like strings for redaction tests"),
    ],
)

# --- U. Synergy execution playbooks ---
section(
    "U. Synergy execution playbooks",
    [
        T(False, "#synergy/slm-setup #playbook", "Playbook: live Ollama accept + DevGuard bracket on same host"),
        T(False, "#synergy/slm-setup #playbook", "Playbook: SSH-forwarded downstairs GPU + local DevGuard doctor"),
        T(False, "#synergy/embabel-slm #playbook", "Playbook: one paper cell end-to-end (run → export → table)"),
        T(False, "#synergy/embabel-slm #playbook", "Playbook: base vs retrieval efficiency comparison week"),
        T(False, "#synergy/obsidian-mcp #playbook", "Playbook: import deep backlog into vault AI Memory"),
        T(False, "#synergy/obsidian-mcp #playbook", "Playbook: weekly STATUS.md sync + decision capture"),
        T(False, "#synergy/sdlc-spdd #playbook", "Playbook: open Work ID for next SLM collector slice"),
        T(False, "#synergy/docgen #playbook", "Playbook: record 3-minute metrics demo video"),
        T(False, "#synergy/slm-setup #playbook", "Playbook: correlate eval scores with J/token across models"),
        T(False, "#playbook", "Playbook: pre-Ubuntu-upgrade snapshot ritual"),
        T(False, "#playbook", "Playbook: fan-regression data capture without changing BIOS"),
        T(False, "#playbook", "Playbook: backup restore drill quarterly"),
    ],
)

# --- V. Future ideas / park ---
section(
    "V. Parked / future (explicitly deferred)",
    [
        T(False, "#future", "Windows agent parity"),
        T(False, "#future", "macOS sensors / powermetrics adapter"),
        T(False, "#future", "Automatic remediation (NEVER in MVP — keep parked)"),
        T(False, "#future", "Always-on privileged daemon (rejected)"),
        T(False, "#future", "Cloud control plane (rejected)"),
        T(False, "#future", "Homemade backup cryptosystem (rejected)"),
        T(False, "#future", "Full EDR / packet inspection (rejected)"),
        T(False, "#future", "Signed baseline digests phase 2"),
        T(False, "#future", "Keyring-backed restic passwords"),
        T(False, "#future", "Grafana dashboard from exported JSONL"),
        T(False, "#future", "ROCm collector productionization"),
        T(False, "#future", "Jetson / edge power-mode locking helpers"),
        T(False, "#future", "Multi-node Halo cluster authenticated agent"),
        T(False, "#future", "Training FLOPs accounting (leave to embabel-slm)"),
    ],
)


def render_markdown() -> str:
    lines: list[str] = [
        "---",
        "title: DevGuard — deep task backlog",
        "project: DevGuard",
        "store: docs/tasks",
        "source: SPEC.md + SYNERGIES.md + slm-research-metrics.md",
        f"generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "tags:",
        "  - devguard",
        "  - backlog",
        "  - obsidian",
        "---",
        "",
        "# DevGuard — deep task backlog",
        "",
        "Canonical **deep** store for Obsidian MCP reload. Prefer this over the short `backlog-50.md` priority slice.",
        "",
        "See also: [`SYNERGIES.md`](SYNERGIES.md) · [`STATUS.md`](STATUS.md) · [`manifest.json`](manifest.json)",
        "",
        "```bash",
        "./docs/tasks/reload.sh",
        "```",
        "",
    ]
    total = 0
    done = 0
    for name, items in SECTIONS:
        lines.append(f"## {name}")
        lines.append("")
        lines.append(f"_{len(items)} tasks_")
        lines.append("")
        for is_done, tags, title in items:
            total += 1
            if is_done:
                done += 1
            mark = "x" if is_done else " "
            # ensure #devguard present
            tag_str = tags if "#devguard" in tags else f"#devguard {tags}"
            lines.append(f"- [{mark}] {tag_str} {title}")
        lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(f"**Count:** {total} tasks · **done:** {done} · **open:** {total - done}")
    lines.append("")
    lines.append("## Obsidian Tasks")
    lines.append("")
    lines.append("```tasks")
    lines.append("not done")
    lines.append("tags include #synergy/slm-setup")
    lines.append("```")
    lines.append("")
    lines.append("```tasks")
    lines.append("not done")
    lines.append("tags include #slm")
    lines.append("path includes docs/tasks")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def build_manifest(md: str) -> dict:
    tasks = []
    section_name = None
    for line in md.splitlines():
        if line.startswith("## ") and not line.startswith("## Obsidian"):
            section_name = line[3:].strip()
            continue
        m = re.match(r"^- \[([ x])\] (.+)$", line)
        if not m:
            continue
        body = m.group(2)
        tags = re.findall(r"#([A-Za-z0-9_./-]+)", body)
        title = re.sub(r"\s*#[A-Za-z0-9_./-]+", "", body).strip()
        tasks.append(
            {
                "id": f"T{len(tasks)+1:03d}",
                "title": title,
                "done": m.group(1) == "x",
                "tags": tags,
                "section": section_name,
            }
        )
    done_n = sum(1 for t in tasks if t["done"])
    sections: dict = {}
    for t in tasks:
        sec = t["section"] or "unknown"
        sections.setdefault(sec, {"total": 0, "done": 0, "open": 0})
        sections[sec]["total"] += 1
        if t["done"]:
            sections[sec]["done"] += 1
        else:
            sections[sec]["open"] += 1
    return {
        "schema_version": 2,
        "project": "DevGuard",
        "store": "docs/tasks",
        "canonical_markdown": "docs/tasks/backlog-deep.md",
        "priority_slice": "docs/tasks/backlog-50.md",
        "synergies": "docs/tasks/SYNERGIES.md",
        "updated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total": len(tasks),
        "done": done_n,
        "open": len(tasks) - done_n,
        "sections": sections,
        "tasks": tasks,
    }


def render_status(manifest: dict) -> str:
    lines = [
        "# Task store status",
        "",
        f"Reloaded from [`manifest.json`](manifest.json) · deep backlog [`backlog-deep.md`](backlog-deep.md)",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Total | {manifest['total']} |",
        f"| Done | {manifest['done']} |",
        f"| Open | {manifest['open']} |",
        f"| Updated | {manifest['updated_at'][:10]} |",
        "",
        "## Section progress",
        "",
        "| Section | Done | Open | Total |",
        "|---|---|---|---|",
    ]
    for sec, s in manifest["sections"].items():
        lines.append(f"| {sec} | {s['done']} | {s['open']} | {s['total']} |")
    lines += [
        "",
        "## Priority next (synergy-aware)",
        "",
        "1. NVIDIA + host collectors (`#slm`)",
        "2. Bracket **slm-setup** live harness (`#synergy/slm-setup`)",
        "3. Export tables for **embabel-slm** paper cells (`#synergy/embabel-slm`)",
        "4. Reload backlog into **obsidian-mcp** vault (`#synergy/obsidian-mcp`)",
        "5. SQLite + snapshot collectors (`#m1`)",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    STORE.mkdir(parents=True, exist_ok=True)
    md = render_markdown()
    deep = STORE / "backlog-deep.md"
    deep.write_text(md)
    manifest = build_manifest(md)
    (STORE / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (STORE / "STATUS.md").write_text(render_status(manifest))
    print(f"Wrote {deep} with {manifest['total']} tasks ({manifest['done']} done)")


if __name__ == "__main__":
    main()
