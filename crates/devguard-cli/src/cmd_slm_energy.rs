//! `devguard slm energy` derives GPU-rail joules from supplied power samples.
//!
//! The command does not call `nvidia-smi`. Samples come from the arguments.

use clap::Subcommand;
use devguard_core::energy::{derive_gpu_rail_energy, format_energy_human, parse_power_sample};
use devguard_core::json::JsonEnvelope;
use devguard_core::DevGuardError;
use devguard_core::ExitCode;

use crate::output::{emit_human, emit_json};

#[derive(Debug, Subcommand)]
pub enum SlmCommands {
    /// Derive GPU-rail joules from power samples. Does not call nvidia-smi.
    ///
    /// Energy is average power times the interval between the earliest and
    /// latest timestamp. A missing watt reading or a single sample is
    /// unavailable, never a made-up joule value.
    Energy {
        /// One sample as `<watts>@<rfc3339>`. Repeat for a series.
        /// `missing@<rfc3339>` records a sample with no power reading.
        #[arg(long = "sample", value_name = "WATTS@TIMESTAMP")]
        samples: Vec<String>,
        /// Output token count. Fills joules per token and tokens per joule.
        #[arg(long)]
        tokens: Option<u64>,
    },
    /// One-shot host companion sample from /proc.
    ///
    /// Reports CPU percent, RAM used and total, swap used, and disk free in
    /// bytes. The timestamp is RFC3339. A missing source is unavailable, never
    /// a healthy result. Does not use sudo.
    Host,
}

pub fn run(json: bool, action: SlmCommands) -> Result<ExitCode, DevGuardError> {
    match action {
        SlmCommands::Energy { samples, tokens } => run_energy(json, &samples, tokens),
        SlmCommands::Host => crate::cmd_slm_host::run(json),
    }
}

fn run_energy(
    json: bool,
    raw_samples: &[String],
    tokens: Option<u64>,
) -> Result<ExitCode, DevGuardError> {
    let mut samples = Vec::with_capacity(raw_samples.len());
    for raw in raw_samples {
        samples.push(parse_power_sample(raw)?);
    }
    let report = derive_gpu_rail_energy(&samples, tokens);
    let warnings = report.warnings();
    if json {
        let envelope = if warnings.is_empty() {
            JsonEnvelope::success("slm energy", &report)
        } else {
            JsonEnvelope::success_with_warnings("slm energy", &report, warnings)
        };
        emit_json(&envelope)?;
    } else {
        emit_human(&format_energy_human(&report));
    }
    Ok(report.exit_code())
}
