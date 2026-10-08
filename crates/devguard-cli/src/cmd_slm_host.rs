//! `devguard slm host`.

use devguard_core::exit::ExitCode;
use devguard_core::host_sample::{format_host_human, sample_host};
use devguard_core::json::JsonEnvelope;

use crate::output::{emit_human, emit_json};

pub fn run(json: bool) -> Result<ExitCode, devguard_core::DevGuardError> {
    let report = sample_host();
    let warnings = report.warnings();
    if json {
        let envelope = if warnings.is_empty() {
            JsonEnvelope::success("slm host", &report)
        } else {
            JsonEnvelope::success_with_warnings("slm host", &report, warnings)
        };
        emit_json(&envelope)?;
    } else {
        emit_human(&format_host_human(&report));
    }
    Ok(report.exit_code())
}
