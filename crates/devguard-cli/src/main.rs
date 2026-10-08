//! DevGuard CLI entrypoint.

mod cmd_security_diff;
mod cmd_slm_checklist;
mod cmd_slm_energy;
mod cmd_slm_export;
mod cmd_slm_host;
mod cmd_slm_run;
mod cmd_snapshot;
mod output;
mod watch;

use std::path::PathBuf;
use std::process::ExitCode as StdExitCode;

use clap::{Parser, Subcommand};
use devguard_core::config::{Config, ConfigPaths};
use devguard_core::dev_deps::{format_deps_audit_human, scan_deps_audit};
use devguard_core::dev_env::{format_dev_env_human, scan_dev_env};
use devguard_core::dev_repos::{format_dev_repos_human, scan_dev_repos};
use devguard_core::doctor::run_doctor;
use devguard_core::exit::ExitCode;
use devguard_core::fan::{format_fan_human, scan_fan};
use devguard_core::files::{format_files_human, scan_config_files};
use devguard_core::firewall::{format_firewall_human, scan_firewall};
use devguard_core::gpu::{format_gpu_human, scan_gpu};
use devguard_core::gpu_id::{format_gpu_id_human, scan_gpu_id};
use devguard_core::health_scan::{format_health_scan_human, scan_health};
use devguard_core::json::JsonEnvelope;
use devguard_core::os_identity::{format_os_human, scan_os};
use devguard_core::packages::{format_packages_human, scan_packages};
use devguard_core::path_perms::{format_path_perms_human, scan_path_permissions};
use devguard_core::ports::{format_ports_human, scan_ports};
use devguard_core::remote::{
    collect_status, format_remote_status, format_tunnel, tunnel_down, tunnel_up,
};
use devguard_core::runaway::{format_runaway_human, scan_runaways, RunawayThresholds};
use devguard_core::security_scan::{format_security_scan_human, scan_security};
use devguard_core::security_updates::{format_security_updates_human, scan_security_updates};
use devguard_core::sensors::{format_sensors_human, scan_sensors};
use devguard_core::ssh_auth::{format_ssh_auth_human, scan_ssh_auth};
use devguard_core::units::{format_units_human, scan_units};
use devguard_core::watch::parse_watch_interval;
use devguard_core::DevGuardPaths;
use tracing_subscriber::EnvFilter;

use crate::output::{emit_human, emit_json, print_doctor_human};
use crate::watch::run_watch;

#[derive(Debug, Parser)]
#[command(
    name = "devguard",
    version,
    about = "Workstation security, backup, health, and SLM metrics toolkit",
    long_about = "DevGuard is a read-only-by-default Rust CLI for backing up, auditing, \
monitoring, and capturing developer/SLM workstation metrics.\n\n\
Privileges: ordinary user execution. Mutating commands (backup run/restore) require \
explicit configuration and confirmation.\n\n\
Dependencies (feature-detected): nvidia-smi, sensors, git, ss, systemctl, ufw, nft, last, \
journalctl, restic/rustic. \
`dev env` reports version lines for rustc, cargo, python3, node, git, and gcc. \
`dev repos scan` reads dirty, untracked, branch, upstream, and unpublished commits \
for git work trees under an explicit path or dev.repo_roots. It does not fetch, \
pull, push, or walk the home directory. \
`dev deps audit` checks local cargo-audit, Python, npm, and Maven or Gradle \
adapters. It does not contact the network or transmit a manifest unless `--online` \
is set. A missing local tool is unavailable, and that result is not clean. \
`security ssh-auth` reports SSH login counts, timestamps, and source addresses \
from `last`, the journal, and the auth log when those sources are readable. \
It does not copy credentials or full journal payloads, use sudo, or change sshd."
)]
struct Cli {
    /// Path to config.toml (default: ~/.config/devguard/config.toml)
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    /// Emit a single JSON document to stdout (progress/errors on stderr)
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Check prerequisites, tool versions, permissions, and SLM/GPU coverage
    Doctor,
    /// Show summary of most recent scans (M0: empty until collectors land)
    Status,
    /// Read-only health checks. Does not use sudo, send signals, load modules, write BIOS, or change fan curves.
    Health {
        #[command(subcommand)]
        action: HealthCommands,
    },
    /// Read-only security checks. Does not install updates, use sudo, read file contents, or change host configuration.
    Security {
        #[command(subcommand)]
        action: SecurityCommands,
    },
    /// One-shot NVIDIA GPU reading. Does not use sudo or load kernel modules.
    Gpu {
        #[command(subcommand)]
        action: GpuCommands,
    },
    /// Named downstairs WSL helpers. Off unless local config names the SSH target.
    Remote {
        #[command(subcommand)]
        action: RemoteCommands,
    },
    /// SLM host sample, energy from supplied samples, run brackets, paper export, and a paper checklist.
    /// Host reads /proc. Energy does not call nvidia-smi. Run and export do not call Ollama or bind a port.
    /// Checklist reads one stored run and does not call Ollama.
    Slm {
        #[command(subcommand)]
        action: SlmCommands,
    },
    /// Developer toolchain inventory, an opt-in git scan, and an opt-in dependency audit.
    ///
    /// `dev env` and `dev repos scan` do not use the network. `dev deps audit` does not
    /// contact the network or transmit a manifest unless `--online` is set.
    Dev {
        #[command(subcommand)]
        action: DevCommands,
    },
    /// Store and diff a workstation snapshot.
    ///
    /// `create` writes one JSON payload from the collectors already on this
    /// branch. It does not use sudo, install packages, or open a network
    /// connection. A missing collector stays in the payload as unavailable.
    /// The snapshot is partial when any collector is unavailable. `--label`
    /// is an ordinary string. `diff` lists added, removed, and changed entries
    /// in stable order. Severity is a separate field from the fact.
    Snapshot {
        #[command(subcommand)]
        action: cmd_snapshot::SnapshotCommands,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
}

#[derive(Debug, Subcommand)]
enum SlmCommands {
    #[command(flatten)]
    Energy(cmd_slm_energy::SlmCommands),
    #[command(flatten)]
    Run(cmd_slm_run::SlmCommands),
    #[command(flatten)]
    Export(cmd_slm_export::SlmCommands),
    #[command(flatten)]
    Checklist(cmd_slm_checklist::SlmCommands),
}

#[derive(Debug, Subcommand)]
enum HealthCommands {
    /// CPU count, memory, swap, disk free, uptime, and busiest process names.
    ///
    /// Reads `/proc/<pid>/stat` for the comm name only and does not collect
    /// command arguments. Does not use sudo, send a signal, load a kernel
    /// module, or write BIOS. A missing `/proc` source is unavailable, and
    /// that result is not clean.
    Scan,
    /// Observations and hypotheses for fan noise. Process names only.
    ///
    /// Does not use sudo, write a fan curve, load a kernel module, or change BIOS.
    /// Missing `sensors` or `nvidia-smi` is unavailable, never a clean result.
    Fan,
    /// Installed package names and versions, plus pending updates from local APT lists.
    ///
    /// Reads list files only. Does not run apt install, apt upgrade, or any other
    /// command that changes packages. Does not use sudo. If the APT lists are
    /// missing or unreadable, pending updates are unavailable and the result is
    /// not clean.
    Packages,
    /// Package, CPU, and board temperatures plus fan RPM from hwmon files.
    ///
    /// Does not install packages, use sudo, load a kernel module, or change a fan curve.
    /// If `sensors` is missing and no hwmon file is readable, the reading is
    /// unavailable and not clean.
    Sensors,
    /// Kernel release, boot id, and uptime from `/proc`.
    ///
    /// The hostname is stored only as a privacy-preserving hash, never the raw
    /// hostname. A missing `/proc` source is unavailable, and that result is
    /// not clean. Does not use sudo, open a port, or collect package lists.
    Os,
    /// Unit name, enabled state, active state, and whether the unit is failed.
    ///
    /// Reads one `systemctl show` listing. Does not start, stop, enable, or
    /// disable units, and does not use sudo. If `systemctl` is missing or the
    /// listing is unreadable, the result is unavailable and not clean.
    Units,
    /// Find a process at 6+ cores for 10 minutes, or holding 12+ GiB RSS.
    ///
    /// Samples CPU for one second. Prints a stop hint and does not send a signal.
    Runaway,
    /// Local listening sockets from `ss -lntup`. Process names only.
    ///
    /// Does not open a port, scan a remote host, or collect command arguments.
    /// A missing `ss` is unavailable and the result is not clean. A listening
    /// row with no process name is attribution missing, not a closed port.
    Ports,
    /// NVIDIA driver version, GPU name, and PCI bus id for upgrade diffs.
    ///
    /// Reads one `nvidia-smi` query. A missing `nvidia-smi` or a missing field
    /// is unavailable, and the result is not clean. Does not use sudo or load
    /// a kernel module.
    GpuId,
    /// Hash allowlisted config files. Reports path, byte size, mtime, and SHA-256.
    ///
    /// The allowlist is `snapshot.config_hash_allowlist`. A missing or
    /// unreadable path is unavailable, and the result is not clean. File bytes
    /// are not stored or printed.
    Files,
    /// Refresh the fan diagnostic in a terminal. Exits on Ctrl+C.
    ///
    /// The interval is bounded to 1s..300s (`5s`, `1m`, `1000ms`). This command
    /// does not start a background service or signal processes. Missing
    /// `sensors` or `nvidia-smi` stays unavailable.
    Watch {
        /// Refresh interval, for example `5s`. Bounded to 1s..300s.
        #[arg(long, value_name = "DURATION")]
        interval: String,
    },
}

#[derive(Debug, Subcommand)]
enum SecurityCommands {
    /// Mode bits for allowlisted sensitive paths.
    ///
    /// The allowlist is `security.sensitive_path_allowlist`. Owner and group
    /// names are included when the local account database provides them.
    /// A missing or unreadable path is unavailable, and the result is not
    /// clean. An empty allowlist means no paths were configured. This command
    /// does not recurse, use sudo, or read or print file contents.
    Paths,
    /// Firewall status from `ufw` and nftables, plus SSH exposure where sshd config is readable.
    ///
    /// A missing `ufw`, `nft`, or unreadable sshd config is unavailable, and that
    /// result is not clean. Does not run `ufw enable` or `ufw disable`, does not
    /// change nftables rules, and does not use sudo. nftables output is detection,
    /// not a full audit.
    Firewall,
    /// OS security-update status from update-notifier or security-pocket APT lists.
    ///
    /// Reads files already on disk. Does not run apt install, apt upgrade,
    /// apt full-upgrade, or apt update, and does not use sudo. This is not an
    /// installed-package inventory. If the security-update source is missing
    /// or unreadable, the result is unavailable and not clean.
    Updates,
    /// SSH login history and failed auth attempts where the source is readable.
    ///
    /// Reports counts, timestamps, and source addresses only. Does not copy
    /// credentials, passwords, private keys, or full journal payloads. A missing
    /// journal, missing `last`, or unreadable auth log is unavailable, and that
    /// result is not clean. Does not use sudo, start or stop sshd, or change
    /// sshd config.
    SshAuth,
    /// Findings from the firewall, path, and security-update checks.
    ///
    /// Calls those read-only checks and prints one finding per fact. The
    /// severity is `info`, `warning`, `critical`, or `unknown`, and it is a
    /// separate field from the fact. An unavailable source is `unknown`, and
    /// the scan is not clean. An unfamiliar name is not proof of malware.
    /// Does not use sudo, recurse, read file contents, change firewall rules,
    /// or run apt.
    Scan,
    /// Diff listening ports and failed units between two stored snapshots.
    ///
    /// Reads snapshot rows already stored by `devguard snapshot`. Does not
    /// rescan the host, use sudo, or open a network connection. A missing
    /// snapshot id is an error. If the port or unit collector is unavailable,
    /// the result is not clean and that gap is unknown. Each entry has a fact
    /// and a separate severity (info, warning, critical, or unknown). An
    /// unfamiliar process name is not malware proof.
    Diff {
        /// Baseline snapshot id.
        baseline_id: String,
        /// Current snapshot id.
        current_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum GpuCommands {
    /// Read nvidia-smi once. A missing tool or field is unavailable, never a clean result.
    ///
    /// Prints a hash of each GPU UUID. Does not print the raw UUID, use sudo, or load modules.
    Scan,
}

#[derive(Debug, Subcommand)]
enum DevCommands {
    /// Report version lines for rustc, cargo, python3, node, git, and gcc.
    ///
    /// A tool that is not on PATH is unavailable, and that report is not clean.
    /// This command does not install tools, use the network, or run a package audit.
    Env,
    /// Opt-in git work-tree scan. Does not fetch, pull, push, or use sudo.
    Repos {
        #[command(subcommand)]
        action: ReposCommands,
    },
    /// Opt-in dependency audit adapters. Network scans require `--online`.
    Deps {
        #[command(subcommand)]
        action: DepsCommands,
    },
}

#[derive(Debug, Subcommand)]
enum DepsCommands {
    /// Check local cargo-audit, Python, npm, and Maven or Gradle audit tools.
    ///
    /// Without `--online` the network audit is not requested, no networked tool
    /// runs, and no private manifest is transmitted. A missing local tool is
    /// unavailable, and that result is not clean. This command does not install
    /// tools and does not use sudo. `--online` runs the local tools; they may
    /// contact the network and may send dependency names. `clean` means every
    /// local adapter was found. It does not mean the tree has no advisories.
    Audit {
        /// Run the local audit tools. They may contact the network and may send dependency names.
        #[arg(long)]
        online: bool,
    },
}

#[derive(Debug, Subcommand)]
enum ReposCommands {
    /// Scan explicit paths and `dev.repo_roots` for git work trees.
    ///
    /// If the operator passes no path and config names none, the result is
    /// unavailable and not clean. A missing git binary or an unreadable path
    /// is unavailable and not clean. This command does not fetch, pull, push,
    /// use the network, or use sudo, and it does not walk the home directory.
    Scan {
        /// Opt-in directory. Repeat to scan more than one path.
        #[arg(value_name = "PATH")]
        paths: Vec<PathBuf>,
    },
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    /// Create a local config file (no backup until repository is configured)
    Init {
        /// Overwrite an existing config file
        #[arg(long)]
        force: bool,
    },
    /// Validate configuration and report missing optional paths.
    ///
    /// A negative `warn_*` threshold is rejected. Evaluating an optional
    /// threshold is a rule of thumb, not a hardware guarantee.
    Validate,
}

#[derive(Debug, Subcommand)]
enum RemoteCommands {
    /// Report host and tunnel reachability without printing the SSH target.
    Status,
    /// Open or close the Ollama SSH local-forward on 127.0.0.1.
    Tunnel {
        #[command(subcommand)]
        action: TunnelCommands,
    },
}

#[derive(Debug, Subcommand)]
enum TunnelCommands {
    /// Open the Ollama local-forward. Does not install a service.
    Up,
    /// Close the local-forward this command opened.
    Down,
}

fn main() -> StdExitCode {
    init_tracing();
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => StdExitCode::from(code.as_i32() as u8),
        Err(err) => {
            eprintln!("error: {err}");
            StdExitCode::from(err.exit_code().as_i32() as u8)
        }
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .compact()
        .init();
}

fn run(cli: Cli) -> Result<ExitCode, devguard_core::DevGuardError> {
    let config_paths = ConfigPaths::from_override(cli.config.clone())?;
    let paths = &config_paths.paths;

    match cli.command {
        Commands::Doctor => {
            let loaded = Config::load(&paths.config_file).ok();
            let report = run_doctor(paths, loaded.as_ref());
            if cli.json {
                let envelope = JsonEnvelope::success("doctor", &report);
                emit_json(&envelope)?;
            } else {
                print_doctor_human(&report, &paths.config_file);
            }
            if report.ready_for_readonly {
                Ok(ExitCode::Success)
            } else {
                Ok(ExitCode::Partial)
            }
        }
        Commands::Status => {
            #[derive(serde::Serialize)]
            struct StatusData {
                message: String,
                scans: Vec<String>,
                config_present: bool,
            }
            let data = StatusData {
                message: "No scans recorded yet. Snapshot/health/gpu collectors arrive in later milestones.".into(),
                scans: Vec::new(),
                config_present: paths.config_file.exists(),
            };
            if cli.json {
                emit_json(&JsonEnvelope::success("status", &data))?;
            } else {
                emit_human(&format!(
                    "DevGuard status\n  config: {}\n  {}\n",
                    if data.config_present {
                        paths.config_file.display().to_string()
                    } else {
                        "not initialized (run `devguard config init`)".into()
                    },
                    data.message
                ));
            }
            Ok(ExitCode::Success)
        }
        Commands::Gpu {
            action: GpuCommands::Scan,
        } => {
            let report = scan_gpu();
            let warnings = report.warnings();
            if cli.json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("gpu scan", &report)
                } else {
                    JsonEnvelope::success_with_warnings("gpu scan", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_gpu_human(&report));
            }
            Ok(report.exit_code())
        }
        Commands::Health { action } => run_health(cli.json, paths, action),
        Commands::Security { action } => run_security(cli.json, paths, action),
        Commands::Remote { action } => run_remote(cli.json, paths, action),
        Commands::Slm { action } => match action {
            SlmCommands::Energy(action) => cmd_slm_energy::run(cli.json, action),
            SlmCommands::Run(action) => cmd_slm_run::run(cli.json, paths, action),
            SlmCommands::Export(action) => cmd_slm_export::run(cli.json, paths, action),
            SlmCommands::Checklist(action) => cmd_slm_checklist::run(cli.json, paths, action),
        },
        Commands::Dev { action } => run_dev(cli.json, paths, action),
        Commands::Snapshot { action } => cmd_snapshot::run(
            cli.json,
            &config_hash_allowlist(paths)?,
            &remote_state_dir(paths)?,
            action,
        ),
        Commands::Config {
            action: ConfigCommands::Init { force },
        } => {
            let created = Config::init_file(&paths.config_file, force)?;
            // Ensure state dir exists early.
            std::fs::create_dir_all(&paths.state_dir)?;
            #[derive(serde::Serialize)]
            struct InitData {
                config_path: String,
                state_dir: String,
                schema_version: u32,
                slm_capture_gpu: bool,
            }
            let data = InitData {
                config_path: paths.config_file.display().to_string(),
                state_dir: paths.state_dir.display().to_string(),
                schema_version: created.schema_version,
                slm_capture_gpu: created.slm.capture_gpu,
            };
            if cli.json {
                emit_json(&JsonEnvelope::success("config init", &data))?;
            } else {
                emit_human(&format!(
                    "Wrote config to {}\nState directory: {}\nSLM GPU capture: {}\n\
Next: edit model_dirs / repo paths as needed, then run `devguard doctor`.\n",
                    data.config_path,
                    data.state_dir,
                    if data.slm_capture_gpu {
                        "enabled"
                    } else {
                        "disabled"
                    }
                ));
            }
            Ok(ExitCode::Success)
        }
        Commands::Config {
            action: ConfigCommands::Validate,
        } => {
            let config = Config::load(&paths.config_file)?;
            let warnings = config.validate_with_warnings()?;
            #[derive(serde::Serialize)]
            struct ValidateData {
                config_path: String,
                schema_version: u32,
                valid: bool,
                warnings: Vec<String>,
                slm: SlmValidateSummary,
            }
            #[derive(serde::Serialize)]
            struct SlmValidateSummary {
                capture_gpu: bool,
                capture_host: bool,
                model_dirs: usize,
                process_name_hints: usize,
            }
            let data = ValidateData {
                config_path: paths.config_file.display().to_string(),
                schema_version: config.schema_version,
                valid: true,
                warnings: warnings.clone(),
                slm: SlmValidateSummary {
                    capture_gpu: config.slm.capture_gpu,
                    capture_host: config.slm.capture_host,
                    model_dirs: config.slm.model_dirs.len(),
                    process_name_hints: config.slm.process_name_hints.len(),
                },
            };
            if cli.json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("config validate", &data)
                } else {
                    JsonEnvelope::success_with_warnings("config validate", &data, warnings.clone())
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format!(
                    "Config OK: {}\n  schema_version: {}\n  slm.capture_gpu: {}\n  slm.model_dirs: {}\n",
                    data.config_path,
                    data.schema_version,
                    data.slm.capture_gpu,
                    data.slm.model_dirs
                ));
                for w in &warnings {
                    eprintln!("warning: {w}");
                }
            }
            if warnings.is_empty() {
                Ok(ExitCode::Success)
            } else {
                Ok(ExitCode::Partial)
            }
        }
    }
}

fn run_dev(
    json: bool,
    locations: &DevGuardPaths,
    action: DevCommands,
) -> Result<ExitCode, devguard_core::DevGuardError> {
    match action {
        DevCommands::Env => {
            let report = scan_dev_env();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("dev env", &report)
                } else {
                    JsonEnvelope::success_with_warnings("dev env", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_dev_env_human(&report));
            }
            Ok(report.exit_code())
        }
        DevCommands::Repos {
            action: ReposCommands::Scan { paths },
        } => {
            let config = load_config_optional(&locations.config_file)?;
            let config_roots = config
                .as_ref()
                .map(|config| config.dev.repo_roots.clone())
                .unwrap_or_default();
            let report = scan_dev_repos(&git_bin()?, &paths, &config_roots);
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("dev repos scan", &report)
                } else {
                    JsonEnvelope::success_with_warnings("dev repos scan", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_dev_repos_human(&report));
            }
            Ok(report.exit_code())
        }
        DevCommands::Deps {
            action: DepsCommands::Audit { online },
        } => {
            let path = std::env::var_os("PATH").unwrap_or_default();
            let workdir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let report = scan_deps_audit(&path, online, &workdir);
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("dev deps audit", &report)
                } else {
                    JsonEnvelope::success_with_warnings("dev deps audit", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_deps_audit_human(&report));
            }
            Ok(report.exit_code())
        }
    }
}

fn run_health(
    json: bool,
    paths: &DevGuardPaths,
    action: HealthCommands,
) -> Result<ExitCode, devguard_core::DevGuardError> {
    match action {
        HealthCommands::Scan => {
            let report = scan_health();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health scan", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health scan", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_health_scan_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Fan => {
            let report = scan_fan();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health fan", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health fan", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_fan_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Packages => {
            let report = scan_packages();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health packages", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health packages", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_packages_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Sensors => {
            let report = scan_sensors();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health sensors", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health sensors", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_sensors_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Os => {
            let report = scan_os();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health os", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health os", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_os_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Units => {
            let report = scan_units();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health units", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health units", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_units_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Runaway => {
            let report = scan_runaways(&RunawayThresholds::hook_defaults())?;
            if json {
                emit_json(&JsonEnvelope::success("health runaway", &report))?;
            } else {
                emit_human(&format_runaway_human(&report));
            }
            if report.has_findings() {
                Ok(ExitCode::Findings)
            } else {
                Ok(ExitCode::Success)
            }
        }
        HealthCommands::GpuId => {
            let report = scan_gpu_id();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health gpu-id", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health gpu-id", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_gpu_id_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Ports => {
            let report = scan_ports();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health ports", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health ports", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_ports_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Files => {
            let allowlist = config_hash_allowlist(paths)?;
            let report = scan_config_files(&allowlist);
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("health files", &report)
                } else {
                    JsonEnvelope::success_with_warnings("health files", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_files_human(&report));
            }
            Ok(report.exit_code())
        }
        HealthCommands::Watch { interval } => {
            let interval = parse_watch_interval(&interval)?;
            if json {
                return Err(devguard_core::DevGuardError::Usage(
                    "health watch is a terminal display and does not emit JSON".into(),
                ));
            }
            run_watch(interval)
        }
    }
}

fn run_remote(
    json: bool,
    paths: &DevGuardPaths,
    action: RemoteCommands,
) -> Result<ExitCode, devguard_core::DevGuardError> {
    let config = load_config_optional(&paths.config_file)?;
    let target = match &config {
        Some(config) => config.remote_target()?,
        None => None,
    };
    let ssh_bin = ssh_bin()?;
    let state_dir = remote_state_dir(paths)?;
    match action {
        RemoteCommands::Status => {
            let report =
                collect_status(target.as_ref(), &ssh_bin, &state_dir).map_err(remote_err)?;
            if json {
                emit_json(&JsonEnvelope::success("remote status", &report))?;
            } else {
                emit_human(&format_remote_status(&report));
            }
            Ok(ExitCode::Success)
        }
        RemoteCommands::Tunnel { action } => {
            let Some(target) = target else {
                return Err(devguard_core::DevGuardError::Usage(
                    "remote target is not configured; set host and user in the local config".into(),
                ));
            };
            let (command, report) = match action {
                TunnelCommands::Up => (
                    "remote tunnel up",
                    tunnel_up(&target, &ssh_bin, &state_dir).map_err(remote_err)?,
                ),
                TunnelCommands::Down => (
                    "remote tunnel down",
                    tunnel_down(&target, &ssh_bin, &state_dir).map_err(remote_err)?,
                ),
            };
            if json {
                emit_json(&JsonEnvelope::success(command, &report))?;
            } else {
                emit_human(&format_tunnel(&report));
            }
            Ok(ExitCode::Success)
        }
    }
}

fn run_security(
    json: bool,
    paths: &DevGuardPaths,
    action: SecurityCommands,
) -> Result<ExitCode, devguard_core::DevGuardError> {
    match action {
        SecurityCommands::Paths => {
            let allowlist = sensitive_path_allowlist(paths)?;
            let report = scan_path_permissions(&allowlist);
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("security paths", &report)
                } else {
                    JsonEnvelope::success_with_warnings("security paths", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_path_perms_human(&report));
            }
            Ok(report.exit_code())
        }
        SecurityCommands::Firewall => {
            let report = scan_firewall();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("security firewall", &report)
                } else {
                    JsonEnvelope::success_with_warnings("security firewall", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_firewall_human(&report));
            }
            Ok(report.exit_code())
        }
        SecurityCommands::Updates => {
            let report = scan_security_updates();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("security updates", &report)
                } else {
                    JsonEnvelope::success_with_warnings("security updates", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_security_updates_human(&report));
            }
            Ok(report.exit_code())
        }
        SecurityCommands::SshAuth => {
            let report = scan_ssh_auth();
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("security ssh-auth", &report)
                } else {
                    JsonEnvelope::success_with_warnings("security ssh-auth", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_ssh_auth_human(&report));
            }
            Ok(report.exit_code())
        }
        SecurityCommands::Scan => {
            let allowlist = sensitive_path_allowlist(paths)?;
            let report = scan_security(&allowlist);
            let warnings = report.warnings();
            if json {
                let envelope = if warnings.is_empty() {
                    JsonEnvelope::success("security scan", &report)
                } else {
                    JsonEnvelope::success_with_warnings("security scan", &report, warnings)
                };
                emit_json(&envelope)?;
            } else {
                emit_human(&format_security_scan_human(&report));
            }
            Ok(report.exit_code())
        }
        SecurityCommands::Diff {
            baseline_id,
            current_id,
        } => cmd_security_diff::run(json, &remote_state_dir(paths)?, &baseline_id, &current_id),
    }
}

fn sensitive_path_allowlist(
    paths: &DevGuardPaths,
) -> Result<Vec<String>, devguard_core::DevGuardError> {
    if paths.config_file.is_file() {
        Ok(Config::load(&paths.config_file)?
            .security
            .sensitive_path_allowlist)
    } else {
        Ok(Config::default().security.sensitive_path_allowlist)
    }
}

fn config_hash_allowlist(
    paths: &DevGuardPaths,
) -> Result<Vec<String>, devguard_core::DevGuardError> {
    if paths.config_file.is_file() {
        Ok(Config::load(&paths.config_file)?
            .snapshot
            .config_hash_allowlist)
    } else {
        Ok(Config::default().snapshot.config_hash_allowlist)
    }
}

fn load_config_optional(
    path: &std::path::Path,
) -> Result<Option<Config>, devguard_core::DevGuardError> {
    match Config::load(path) {
        Ok(config) => Ok(Some(config)),
        Err(devguard_core::config::ConfigError::NotFound(_)) => Ok(None),
        Err(err) => Err(err.into()),
    }
}

fn remote_err(err: devguard_core::remote::RemoteError) -> devguard_core::DevGuardError {
    devguard_core::DevGuardError::Message(err.to_string())
}

fn git_bin() -> Result<PathBuf, devguard_core::DevGuardError> {
    match std::env::var("DEVGUARD_GIT_BIN") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(&value);
            if !path.is_absolute() {
                return Err(devguard_core::DevGuardError::Usage(
                    "DEVGUARD_GIT_BIN must be an absolute path".into(),
                ));
            }
            Ok(path)
        }
        _ => Ok(PathBuf::from("git")),
    }
}

fn ssh_bin() -> Result<PathBuf, devguard_core::DevGuardError> {
    match std::env::var("DEVGUARD_SSH_BIN") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(&value);
            if !path.is_absolute() {
                return Err(devguard_core::DevGuardError::Usage(
                    "DEVGUARD_SSH_BIN must be an absolute path".into(),
                ));
            }
            Ok(path)
        }
        _ => Ok(PathBuf::from("ssh")),
    }
}

fn remote_state_dir(paths: &DevGuardPaths) -> Result<PathBuf, devguard_core::DevGuardError> {
    match std::env::var("DEVGUARD_STATE_DIR") {
        Ok(value) if !value.is_empty() => {
            let path = PathBuf::from(&value);
            if !path.is_absolute() {
                return Err(devguard_core::DevGuardError::Usage(
                    "DEVGUARD_STATE_DIR must be an absolute path".into(),
                ));
            }
            Ok(path)
        }
        _ => Ok(paths.state_dir.clone()),
    }
}
