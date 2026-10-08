# DevGuard — Rust Workstation Security, Backup & Developer Operations Toolkit

**Status:** Draft implementation specification v0.1  
**Platform:** Ubuntu Linux (x86_64), developed on Ubuntu 26.04.  
**Other systems:** Windows and macOS are not supported. Another Linux distribution can answer a command only when that host has the same source (`/proc`, systemd, APT, or the named tool). A missing source stays unavailable.  
**Working style:** Cursor-driven, test-first, incremental implementation  
**License recommendation:** Apache-2.0 or MIT (decision pending)

## 1. Product vision

Build **DevGuard**, a single, modular Rust CLI that makes it straightforward to back up, audit, monitor, and reproduce a developer workstation. Start with one Ubuntu host (ASUS PRIME Z490-P, NVIDIA RTX 3060), then extend to an opt-in, authenticated multi-node setup including future AMD Ryzen AI Max/Halo systems.

DevGuard is **not** an antivirus product, a replacement for `sudo`, or a homemade backup cryptosystem. It should orchestrate trusted tools, collect verifiable system facts, detect changes, and produce actionable reports. **Safe, read-only by default**; any action that alters system state needs explicit opt-in.

### Goals

1. Reliable, encrypted, deduplicated workstation backups with restore verification.
2. Baseline and drift reports before/after Ubuntu upgrades or configuration changes.
3. Read-only security posture auditing: services, ports, logins, firewall state, updates, and development dependencies.
4. Hardware health diagnostics including CPU, NVIDIA GPU, temperatures, fans, memory, storage.
5. Reproducible development-environment inventory and repository hygiene checks.
6. Structured machine-readable output, suitable for Cursor, scripting, CI and dashboards.
7. Expandable local monitoring for future remote Linux AI nodes.

### Non-goals (v0.1)

- Automatic remediation, unattended package installation, changing firewall policy, or killing processes.
- Replacing `restic`/`rustic`, implementing encryption primitives, or pretending that a successful backup equals a successful restore.
- Full EDR, packet inspection, keylogging, secret collection, or unrestricted network scanning.
- Remote administration/control plane, always-on privileged daemon, or cloud service.
- Windows parity in the first phase.

## 2. Principles and guardrails

- **Least privilege:** Regular user execution wherever possible. Privileged operations are separate, narrowly scoped, documented and optional.
- **Observe first:** `status`, `scan`, `diff`, and `plan` are read-only. `backup run` writes to an explicitly configured repository; `restore` cannot overwrite without confirmation and explicit target.
- **Never log secrets:** Redact environment variables, tokens, private keys, passwords, full command lines with potentially sensitive arguments, and credential-bearing URLs. Output paths can also be sensitive; support redaction.
- **No arbitrary remote execution:** Agent networking remains off by default; later implementations require mutually authenticated encryption and narrowly scoped APIs.
- **Failures must be visible:** Unavailable sensors, permission denials, uninstalled providers, and partial scans must be marked `unknown` or `unavailable`, never as clean.
- **Evidence over heuristics:** Security findings record observation, confidence, source, timestamp, and remediation suggestion; do not automatically label an unfamiliar service malicious.
- **Platform:** Collectors read Ubuntu Linux sources. There is no Windows or macOS adapter. A missing tool or file is unavailable.
- **Resource aware:** Bounded memory use, process timeouts, asynchronous tasks only where valuable, and limited polling overhead.
- **Versioned output:** JSON schemas contain `schema_version` and are tested for backward-compatible evolution.
- **Respect ownership:** Back up only configured, readable user directories; do not harvest credentials or private data by default.

## 3. Primary user stories

- As a workstation owner, I can record a baseline before upgrading Ubuntu and compare it with a later scan to identify a changed kernel, NVIDIA driver, fan temperature, startup service, or open port.
- As a developer, I can restore personal source code and important application configuration from an encrypted backup on another host.
- As a security-conscious user, I can review unexpected SSH logins, new listening ports, disabled security updates, and vulnerable dependencies, including explicit scan limitations.
- As a Rust/Java/Python developer, I can reproduce a toolchain inventory and detect uncommitted or unpushed changes across multiple Git repositories.
- As an operator of future AI nodes, I can compare GPU load, memory availability, disk utilization and basic health without exposing privileged shell access.

## 4. CLI interface (proposed)

```text
devguard --help
devguard doctor                         # prerequisites, tool versions, permissions, coverage
devguard status [--json]                # summary of most recent scans, with timestamps
devguard config init                    # create local config, no backup until user configures it
devguard config validate

devguard snapshot create [--label NAME] [--json]
devguard snapshot list [--json]
devguard snapshot diff <BASELINE_ID> <CURRENT_ID> [--json]

devguard health scan [--json]
devguard health fan [--json]            # observations and hypotheses; missing sensors or nvidia-smi is unavailable
devguard health sensors [--json]        # package, CPU, and board temperatures plus fan RPM from hwmon files
devguard health os [--json]             # kernel release, boot id, and uptime; hostname is only a hash
devguard health units [--json]          # systemd unit name, enabled, active, and failed; read-only
devguard health packages [--json]       # installed package names and versions; pending updates when APT lists are readable
devguard security updates [--json]      # OS security-update status from update-notifier or security-pocket APT lists
devguard security paths [--json]        # mode bits for allowlisted paths; a missing path is unavailable
devguard health watch --interval 5s     # TUI, exits cleanly on Ctrl+C
devguard health gpu-id [--json]         # NVIDIA driver, GPU name, and PCI bus id; a missing tool or field is unavailable
devguard gpu scan [--json]              # one-shot nvidia-smi reading; a missing tool or field is unavailable

devguard security firewall [--json]       # ufw and nftables detection; SSH config where readable
devguard security scan [--json]
devguard security diff <BASELINE_ID> <CURRENT_ID> [--json]
devguard security findings [--severity warning] [--json]

devguard backup plan [--json]
devguard backup run [--json]            # write operation, only against configured target
devguard backup list [--json]
devguard backup verify [--sample] [--json]
devguard backup restore --snapshot ID --target PATH --dry-run
# actual restore requires --apply and confirmation; refuse dangerous destinations

devguard dev env [--json]
devguard dev repos scan [PATH...] [--json]
devguard dev deps audit [--online] [--json]  # network audit only with --online
devguard schedule dry-run [--json]       # print an opt-in systemd --user timer; does not install it
```

CLI conventions:
- `--json` outputs exactly one well-formed JSON document to stdout; human-readable progress/errors go to stderr.
- Exit codes: `0` success/scan complete without configured threshold breaches; `1` operational error; `2` completed with policy findings; `3` partial/unknown coverage; `64` invalid CLI usage (refine before stabilizing).
- No sensitive fields in default output; use explicit, documented `--include-paths` options only if needed.
- Commands can be cancelled; external subprocesses must have timeouts and bounded captured output.
- `--help` documents privileges, dependencies, and whether a command mutates state.

## 5. Architecture

Rust Cargo workspace, initially a single binary and a few clean library crates; avoid premature microservices.

```text
devguard/
├── Cargo.toml
├── README.md
├── SPEC.md                  # this specification
├── docs/
│   ├── architecture.md
│   ├── security-model.md
│   ├── runbooks/
│   │   ├── backup-restore.md
│   │   └── ubuntu-upgrade.md
│   └── schemas/
├── crates/
│   ├── devguard-cli/        # clap commands, output formatting
│   ├── devguard-core/       # shared models, errors, config, provider contracts
│   ├── devguard-store/      # SQLite persistence, migrations, retention
│   ├── devguard-host/       # Linux host inventory/snapshots/diffs
│   ├── devguard-health/     # CPU/memory/disk, sensors, NVIDIA adapter
│   ├── devguard-security/   # service/port/firewall/login/updates checks
│   ├── devguard-backup/     # restic/rustic adapter; safety, verification
│   └── devguard-dev/        # env inventory, Git, optional dependency audit
├── tests/
│   ├── fixtures/            # sanitized command outputs and baseline snapshots
│   └── integration/
└── examples/
    └── config.example.toml
```

Suggested libraries (verify current maintenance and API compatibility before choosing versions):
- `clap`, `serde`, `serde_json`, `toml`, `thiserror`, `tracing`, `tracing-subscriber`
- `rusqlite` with bundled SQLite if appropriate; `chrono` or `time`; `uuid`
- `sysinfo` for portable CPU/memory/process data; native Linux `/proc` and `/sys` readers as needed
- `ratatui` + `crossterm` for TUI; `notify` only when filesystem events are needed
- `tokio` only if async adds value; prefer simple synchronous orchestration in MVP
- External tools, feature-detected: `sensors` (lm-sensors), `nvidia-smi`, `systemctl`, `ss`, `journalctl`, `ufw`, `smartctl`, `git`, `restic` or `rustic`, `cargo-audit`.

Provider contract example:

```rust
pub trait Collector {
    type Output: serde::Serialize;
    fn id(&self) -> &'static str;
    fn collect(&self) -> Result<Collection<Self::Output>, CollectError>;
}

pub struct Collection<T> {
    pub observed_at: String,
    pub status: CollectionStatus, // Complete | Partial | Unavailable
    pub data: Option<T>,
    pub warnings: Vec<String>,
}
```

Normalize values with units: temperatures in °C, memory and storage in bytes, power in watts, utilization as 0–100%, time in RFC 3339 UTC. Report provider versions, host identifier (privacy-preserving), and sources. Avoid hard-coded thresholds: defaults are configurable and labeled as rules-of-thumb, not hardware guarantees.

### Local data storage

- Default XDG state directory: `~/.local/state/devguard/` (SQLite DB, schema migrations).
- Default XDG config: `~/.config/devguard/config.toml` with restrictive permissions.
- Support a custom `--config`; no silent migration or cloud upload.
- DB tables: `runs`, `observations`, `snapshots`, `findings`, `backup_jobs`, `backup_verifications`; migrations under source control.
- Per-run statuses: `complete`, `partial`, `failed`; record every provider's actual coverage.
- Retention policy configurable, with dry-run of cleanup and safe defaults; database backup itself should be included in recovery design.

## 6. Module requirements

### A. Snapshot / Ubuntu Upgrade Guardian (MVP)

Collect:
- Host: OS release/version, architecture, hostname hash, uptime, kernel version, boot ID.
- Packages: APT package names/versions, optional Snap inventory, pending updates where readable.
- Boot/services: enabled and running systemd services, failed units, autostart state.
- Network: listening sockets (`ss`), protocol, address, port and process name when available; track missing process attribution distinctly.
- Drivers/hardware: NVIDIA driver and GPU summary, PCI devices of interest, loaded module names, selected thermal/fan readings.
- Developer tool versions: Rust/cargo, gcc/clang, Java, Python, Node, git, Docker if installed.
- Config hashes for an **allowlist** of explicitly chosen files; record hash and metadata without persisting contents or secret bytes.

`diff` returns added/removed/changed entries, including a severity/risk hint distinct from facts. Stable ordering and deterministic snapshots. Support `--label pre-upgrade` and `--label post-upgrade`.

**Fan-regression case:** compare CPU load, CPU/GPU temperatures, `sensors`/fan RPM where available, NVIDIA driver state, GPU utilization/power, kernel, failed services, and background process CPU consumption. Do not assume a fan-speed sensor exists or that high RPM implies a particular cause.

### B. Health Monitor

- Read CPU load, memory/swap, disk capacity, I/O (when available), system uptime and top resource consumers with sensitive command arguments suppressed.
- Sensor adapters: lm-sensors, NVIDIA CLI. Distinguish motherboard/case/CPU fan measurements from GPU fan speeds if observable.
- Show temperatures, power limits, fan RPM, GPU utilization and VRAM only when exposed by device/tool.
- `health scan` is single-shot. `health watch` refreshes the fan diagnostic in a ratatui terminal on a bounded interval (1s through 300s), exits on Ctrl+C, and does not start a background service or signal processes. Missing `sensors` or `nvidia-smi` stays unavailable.
- `health fan` prints observations and hypotheses for fan noise. It reads process names only, never command arguments. Missing `sensors` or `nvidia-smi`, and a missing chassis tachometer, are `unavailable` and the result is not clean. The command does not use sudo, load modules, write BIOS, or change fan curves.
- `health os` reports kernel release, boot id, and uptime from `/proc`. The hostname is stored only as a privacy-preserving hash. A missing `/proc` source is `unavailable` and the result is not clean. The command does not use sudo, open a port, or collect package lists.
- `health gpu-id` records the NVIDIA driver version, GPU name, and PCI bus id for upgrade diffs. It reads one `nvidia-smi` query. A missing `nvidia-smi` or a missing field is `unavailable`, and the result is not clean. Rows are ordered by PCI bus id. It does not use sudo or load a kernel module.
- `health packages` reports installed package names and versions from the dpkg status file, and pending updates when local APT list files are readable. Missing or unreadable lists make pending updates `unavailable`, and that result is not clean. The command does not run apt install, apt upgrade, or any command that changes packages, and it does not use sudo.
- `gpu scan` reads `nvidia-smi` once. It prints a hash of each GPU UUID and does not print the raw UUID. Missing `nvidia-smi` or a missing field is `unavailable`, and the result is not clean. Multiple GPUs stay in nvidia-smi index order. The call times out and keeps a bounded capture. It does not use sudo or load kernel modules. It does not collect process arguments.
- `health ports` reads local `ss -lntup` once and reports protocol, address, port, and process name. A missing `ss` is `unavailable`, and the result is not clean. A listening row with no process name is attribution missing, which is distinct from a closed port. The command does not open a port, scan a remote host, or collect command arguments.
- `health units` reports unit name, enabled state, active state, and whether the unit is failed. It reads one `systemctl show` listing. If `systemctl` is missing or the listing is unreadable, the result is `unavailable` and not clean. It does not start, stop, enable, or disable units, and it does not use sudo.
- `health files` hashes each path in `snapshot.config_hash_allowlist`. A regular file reports its path, byte size, mtime, and SHA-256. A missing or unreadable path is `unavailable`, and the result is not clean. The command does not store or print file bytes.
- Include diagnostic advice only when backed by collected metrics; avoid false precision.

### C. Security Sentinel

Read-only checks, each with source/coverage/confidence:
- New listening ports and changed services versus a baseline.
- `security diff <BASELINE_ID> <CURRENT_ID>` reads two snapshots already stored by `devguard snapshot`. It reports added and removed listening ports and added and removed failed systemd units. Each entry has a fact and a separate severity (`info`, `warning`, `critical`, or `unknown`). A missing snapshot is an operational error. A snapshot whose port or unit collector is unavailable is not clean, and that gap is `unknown` rather than proof that nothing changed. Unparsed port rows are the same kind of gap. The command does not rescan the host, use sudo, or open a network connection. An unfamiliar process name is not malware proof. A new loopback listener is `warning`. A new listener that is not loopback is `critical`. A listener or failed unit that disappeared is `info`. A unit that entered the failed set is `warning`. The default severities can be replaced without changing the fact.
- `security ssh-auth` reports SSH login history from `last` and failed auth attempts from the journal and the auth log, where each source is readable. It reports counts, timestamps, and source addresses only when those fields are already present. It does not copy credentials, passwords, private keys, or full journal payloads. A missing journal, missing `last`, or unreadable auth log is `unavailable`, and that result is not clean. The command does not use sudo, start or stop sshd, or change sshd config.
- Firewall status (`ufw`/nftables detection), SSH exposure/configuration where readable.
- `security firewall` reports `ufw status verbose` and an nftables ruleset listing, plus SSH port, listen address, and authentication settings where `sshd_config` is readable. A missing `ufw`, `nft`, or unreadable sshd config is `unavailable`, and the result is not clean. The command does not run `ufw enable` or `ufw disable`, does not change nftables rules, and does not use sudo. nftables output is detection, not a full audit. Match blocks are counted and not applied.
- OS security update status using Ubuntu-supported interfaces; never silently install updates. `security updates` reads the update-notifier status file or security-pocket APT list files already on disk. It does not run `apt install`, `apt upgrade`, `apt full-upgrade`, or `apt update`, and it does not use sudo. It does not inventory every installed package. A missing or unreadable security-update source is `unavailable`, and that result is not clean.
- File permission checks for selected sensitive user-owned paths; no recursive global scan by default.
- `security paths` reads mode bits for each path in `security.sensitive_path_allowlist`, and owner and group names when the local account database provides them without sudo. It does not recurse, follow symlinks, use sudo, or read file contents. A missing or unreadable path is `unavailable`, and the result is not clean. An empty allowlist means no paths were configured, and that result is not a clean scan of the disk.
- `security scan` calls `security firewall`, `security paths`, and `security updates` and prints findings. Each finding has a fact and a separate severity: `info`, `warning`, `critical`, or `unknown`. An unavailable source is `unknown`, and the scan is not clean. An unfamiliar name is not proof of malware. The command does not use sudo, recurse, read file contents, change firewall rules, or run apt. Exit `2` when every source answered and a finding is `warning` or `critical`. Exit `3` when any source is `unknown`.
- Developer dependency audit integration (opt-in; respect tool availability and potential network egress).

Severity categories: `info`, `warning`, `critical`, `unknown`; every rule is documented, configurable and unit-tested. An unfamiliar process is *not* malware proof.

### D. Backup Guardian

- Prefer orchestration of established `restic` or `rustic` binaries; pin and verify supported versions.
- Explicit include/exclude paths; exclude caches, build outputs and huge models unless configured; warn on excluded or unreadable files.
- Encryption handled by backup engine. Never persist repository passwords in config, command arguments, logs or snapshots. Prefer secure password-file/FD or supported credential mechanisms, following backend guidance.
- Backend destinations: local external drive first, then user-selected SFTP/cloud repo supported by chosen engine.
- Implement `plan`, `run`, `list`, `verify`, and `restore --dry-run` first.
- Backup completion checks repository availability, exit status and repository snapshot identity; verify reports distinguish metadata integrity and sampled versus full-content verification.
- Restore into a new, safe target; protect against path traversal, symlinks and unintended overwrite. Require `--apply` and explicit confirmation for destructive actions.
- Design retention with `forget/prune` as an **independent future feature**, never automatic for MVP.
- Document offsite copy, immutable/offline media and periodic full restore drills; do not promise ransomware resilience from encryption alone.

### E. Developer Workflow Guardian

- Scan opt-in directories for Git repositories, using safe `git` subprocess invocation and no shell interpolation.
- Identify dirty worktrees, untracked files, current branch, upstream status and unpublished local commits. Avoid remote network access by default.
- Inventory compilers, SDKs and package managers. Output a reproducibility report, not a claim of bit-for-bit reproducibility.
- Optional audit adapters: `cargo audit`, Python audit tool, npm audit, Maven/Gradle dependency scanners. Network scans must be opt-in; avoid transmitting private manifests without clear disclosure.
- `dev deps audit` checks local adapters for `cargo-audit`, a Python audit tool (`pip-audit`, or `safety` when `pip-audit` is absent), `npm`, and Maven (`mvn`) or Gradle (`gradle`). Without `--online` it reports that the network audit was not requested and does not run those tools, so it does not contact the network or transmit a private manifest. A missing local tool is `unavailable`, and that result is not clean. The command does not install audit tools and does not use sudo. `--online` runs the local tools; those tools may contact the network and may send dependency names. Token-like strings in tool output are redacted. `clean` means every local adapter was found. It does not mean the tree has no advisories.
- Reuse inventory in pre-upgrade/post-upgrade comparisons.

### F. Multi-Node / Halo Cluster (future)

- Read-only agent exposing a minimal allowlisted metrics API, disabled by default.
- Mutual TLS or equivalent strong authentication, short-lived credentials, explicit peer allowlist; no remote shell interface.
- Track CPU, GPU, VRAM/unified memory, temperature, disk space, network reachability, model-serving health from opt-in endpoints.
- Discover adapters per vendor; don't assume `nvidia-smi` works for AMD ROCm/Halo.
- Deployment can start with locally scheduled JSON export or SSH-based user-initiated collection instead of an agent.
- `devguard remote` is that user-initiated helper. It stays off unless local config names an SSH host and user (those values stay out of git and out of command output). It may only report host up or down, open or close an SSH local-forward to Ollama on `127.0.0.1`, read Ollama tags through that forward, and take a fixed GPU sample plus a fixed fan sample. It does not open a remote shell.

## 7. Example configuration

```toml
schema_version = 1

[general]
json_redact_paths = true
collect_interval_seconds = 5

[database]
retention_days = 90

[snapshot]
config_hash_allowlist = ["~/.config/devguard/config.toml"]

[health]
warn_cpu_temp_c = 85
warn_gpu_temp_c = 85
# Example thresholds only; user should adjust for specific hardware.

[security]
check_ssh_logs = true
check_firewall = true
check_listening_ports = true
sensitive_path_allowlist = []

[backup]
engine = "restic"                # or rustic, selected at initialization
repository = "/media/USER/backup/devguard-restic" # example only; never auto-create
include = ["~/Documents", "~/Projects"]
exclude = ["**/target", "**/node_modules", "**/.cache"]
verify_mode = "sample"
# Credentials are managed externally; never put passwords here.

[dev]
repo_roots = ["~/Projects"]
allow_network_audits = false
```

Config validation must expand `~` safely, verify destinations before any backup mutation, reject nonsensical intervals or thresholds and warn clearly if configured paths do not exist. The initial interactive setup should obtain and verify real user paths rather than assuming sample paths.

## 8. Security threat model (minimum)

Assets: user files/backups, developer secrets, machine configuration, security findings, DB history, optional remote node telemetry.

Threats and mitigations:

| Threat | Mitigation |
|---|---|
| Credentials in CLI args/logs | Secure engine integration; redact; tests against leakage |
| Malicious filenames and paths | Treat as data; no shell invocation; safe normalization/canonicalization |
| Destructive restore / unintended overwrite | Dry run default, allowlisted target, confirmation, explicit `--apply` |
| Attacker modifies baseline locally | Restrictive permissions; optional exported signed digest / offsite copy in later phase |
| Network exposure | No listening sockets by default; explicit opt-in for remote features |
| Sensor or audit tool absent | Coverage state `unavailable`; never report healthy by default |
| Backup repository corruption | Engine integrity checks plus scheduled restore test |
| Dependency supply-chain compromise | Lockfile, vetted crates, auditing, reproducible CI builds where possible |
| Excessive privilege | No privileged daemon in MVP; permissions-aware collectors |

## 9. Milestones & deliverables

### M0 — Skeleton and engineering baseline

Deliver: Cargo workspace, `clap` CLI, TOML config/validation, structured logging/redaction, JSON envelope schema, error/exit policy, test harness, GitHub Actions (Linux `cargo fmt`, `clippy`, `test`).

**Acceptance:** `devguard --help`, `doctor`, `config init`, `config validate` run on Ubuntu without root; unit tests pass; offline smoke test possible.

### M1 — Snapshot and diff (first genuinely useful release)

Deliver: OS/kernel/packages/services/ports/toolchain/GPU inventory, SQLite persistence, `snapshot create/list/diff`, fixture tests for missing permissions/tools.

**Acceptance:** A simulated Ubuntu upgrade fixture shows kernel and driver changes, newly listening port and package changes; stable JSON is parseable; incomplete collection explicitly shown.

### M2 — Health and fan diagnostics

Deliver: CPU/memory/process stats, lm-sensors and NVIDIA adapters, `health scan`, `health watch`, optional threshold warnings.

**Acceptance:** Running without NVIDIA or without lm-sensors does not crash; displays unavailable capability; bounded poll frequency; no sudo required for ordinary scanning.

### M3 — Security Sentinel

Deliver: listening-port baseline alerts, service changes, firewall status, SSH log adapter, findings rules and `security diff`.

**Acceptance:** Fixtures distinguish normal drift from actionable warnings and indicate missing permissions without marking scans clean.

### M4 — Backup Guardian

Deliver: configuration validation, restic/rustic provider selection, dry-run plan, run/list, integrity verification and safe restore preview. Full restore drill documentation.

**Acceptance:** Integration test backs up a synthetic directory, modifies a file, backs up again, verifies both snapshots, restores into a separate temp directory, and checks exact file hashes; failures safely stop operations.

### M5 — Developer Guardian

Deliver: Git workspace hygiene, environment inventory, opt-in dependency adapters, sanitized output.

**Acceptance:** Fixture repos with dirty/untracked/unpushed changes are correctly identified; no implicit network audit; token-like fixture strings do not appear in logs.

### M6 — Ops hardening

Deliver: systemd user timers for **opt-in** scheduled scans/backups, alert output (local notification or report file), rotation/retention controls, package/release instructions, benchmark of idle overhead.

**Acceptance:** Scheduling can be disabled completely; no hidden privileged service; safe restarts; documented maintenance and recovery.

`devguard schedule dry-run` is the first slice of that timer. It prints the user service and timer text for a later `devguard health scan`. It does not write `~/.config/systemd`, run `systemctl`, enable the timer, or use sudo. The timer stays off until `schedule.enabled` is true. Until then the result says the timer is not requested and is not clean. Alerts, retention, packaging, and multi-node stay later.

### M7 — Multi-node (explicitly deferred)

Deliver: architecture proof of concept with safe telemetry collection; authentication and threat model review before exposing a listener.

## 10. Tests and definition of done

For every milestone:

1. Unit tests for parsers, config, rule evaluation, diff stability and path handling.
2. Sanitized fixtures for both normal and failure scenarios; no dependence on exact developer hardware in CI.
3. Integration tests in disposable directories/VM where side effects are involved.
4. Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`.
5. Document manual acceptance commands plus actual results, not assumed passes.
6. Document permissions, dependency prerequisites and rollback method.
7. Update `README.md`, changelog and specification decision log when interfaces change.

Non-functional targets (initial design goals, measure rather than assert):
- Typical one-shot status scan finishes in seconds on a healthy host (excluding external audits/backup operations).
- Idle system has no polling process or open network port until the user explicitly enables one.
- JSON output deterministic for equivalent fixture input, excluding expected timestamps/IDs.
- All operations behave predictably without `nvidia-smi`, `sensors`, internet or sudo.

## 11. Cursor iteration process

Implement **one milestone at a time**. Cursor should first inspect the repository, propose a bounded plan and tests, then implement it. Do not scaffold all advanced features as fake or stubbed successes.

### Starter prompt for Cursor

> Read `SPEC.md` thoroughly and treat it as the source of truth. Build **M0 only**: a compiling Rust Cargo workspace with working `devguard --help`, `devguard doctor`, `devguard config init`, and `devguard config validate`. Implement structured errors, redacted logging, versioned JSON schema, and unit tests. Use current compatible stable crate releases; check APIs rather than assuming versions. Do not implement backup writes, privileged commands, security remediation, daemons, or remote access yet. Before coding, give a short plan identifying files and tests. After coding, run fmt/clippy/tests, report their actual results, document any blockers, and propose the smallest next milestone.

### Reusable follow-up prompt

> Compare the current repository against `SPEC.md`. Identify the next incomplete milestone and select **one narrow, testable vertical slice**. State assumptions, risks, dependencies and acceptance criteria. Implement only that slice with fixtures/tests; run checks; summarize changed files, what works, missing coverage and precise next step. Never claim success based on a mock or stub alone. Maintain read-only defaults and avoid secret leakage.

### Special prompt: diagnose my Ubuntu 26.04 fan issue

> Add or refine the read-only Linux `health scan` collection and snapshot diff so it can compare CPU/process activity, temperatures/fan RPM (when readable), NVIDIA driver/GPU state, loaded drivers, kernel version and failed services. Do not change fan curves, install kernel modules, modify BIOS or require sudo by default. Output a human-readable diagnostic report plus JSON, clearly distinguishing observations from possible causes. Add tests for absent sensors and non-NVIDIA systems.

## 12. Open design questions / decisions to record

- Choose **restic or rustic** as first supported backup engine based on installed tooling, documentation and safety of credential handling; do not simultaneously integrate both in M4.
- Decide how to securely provide repository credentials (supported password file, external secret store, or managed OS keyring) without accidental exposure.
- Confirm Ubuntu 26.04 package/tool availability on the target machine; avoid assuming Rust-based system commands change the external CLI contracts.
- Choose SQLite vs JSON snapshots if the initial implementation needs simplification; retain versioned schema regardless.
- Determine which private configuration paths are safe to hash versus exclude entirely.
- Select how to report findings with machine-readable policy thresholds without overwhelming the user.
- Decide whether scheduled monitoring belongs in `systemd --user` timers or a later dedicated process.
- Consider ROCm-compatible health providers only after the NVIDIA-first local implementation is stable.

---

**Implementation directive:** Prioritize measurable utility, working CLI commands, verification and safe defaults over large amounts of scaffolding. Treat this specification as an evolving contract: revise it after each milestone with evidence from implementation and tests.
