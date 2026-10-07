//! DevGuard CLI entrypoint.

mod output;

use std::path::PathBuf;
use std::process::ExitCode as StdExitCode;

use clap::{Parser, Subcommand};
use devguard_core::config::{Config, ConfigPaths};
use devguard_core::doctor::run_doctor;
use devguard_core::exit::ExitCode;
use devguard_core::fan::{format_fan_human, scan_fan};
use devguard_core::gpu::{format_gpu_human, scan_gpu};
use devguard_core::json::JsonEnvelope;
use tracing_subscriber::EnvFilter;

use crate::output::{emit_human, emit_json, print_doctor_human};

#[derive(Debug, Parser)]
#[command(
    name = "devguard",
    version,
    about = "Workstation security, backup, health, and SLM metrics toolkit",
    long_about = "DevGuard is a read-only-by-default Rust CLI for backing up, auditing, \
monitoring, and capturing developer/SLM workstation metrics.\n\n\
Privileges: ordinary user execution. Mutating commands (backup run/restore) require \
explicit configuration and confirmation.\n\n\
Dependencies (feature-detected): nvidia-smi, sensors, git, ss, systemctl, restic/rustic."
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
    /// Read-only health checks. Does not use sudo, load modules, write BIOS, or change fan curves.
    Health {
        #[command(subcommand)]
        action: HealthCommands,
    },
    /// One-shot NVIDIA GPU reading. Does not use sudo or load kernel modules.
    Gpu {
        #[command(subcommand)]
        action: GpuCommands,
    },
    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigCommands,
    },
}

#[derive(Debug, Subcommand)]
enum HealthCommands {
    /// Observations and hypotheses for fan noise. Process names only.
    ///
    /// Does not use sudo, write a fan curve, load a kernel module, or change BIOS.
    /// Missing `sensors` or `nvidia-smi` is unavailable, never a clean result.
    Fan,
}

#[derive(Debug, Subcommand)]
enum GpuCommands {
    /// Read nvidia-smi once. A missing tool or field is unavailable, never a clean result.
    ///
    /// Prints a hash of each GPU UUID. Does not print the raw UUID, use sudo, or load modules.
    Scan,
}

#[derive(Debug, Subcommand)]
enum ConfigCommands {
    /// Create a local config file (no backup until repository is configured)
    Init {
        /// Overwrite an existing config file
        #[arg(long)]
        force: bool,
    },
    /// Validate configuration and report missing optional paths
    Validate,
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
        Commands::Health {
            action: HealthCommands::Fan,
        } => {
            let report = scan_fan();
            let warnings = report.warnings();
            if cli.json {
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
