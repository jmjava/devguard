//! Optional `warn_*` thresholds.
//!
//! Evaluation compares a supplied sample with configured thresholds and returns
//! warnings labeled rules of thumb, not hardware guarantees. A missing
//! threshold emits no warning. This module does not change fans, use sudo, or
//! signal processes.

use crate::config::HealthConfig;

/// Label attached to every threshold warning.
pub const RULES_OF_THUMB: &str = "rules of thumb, not hardware guarantees";

/// Host numbers compared with optional thresholds.
///
/// Callers supply the sample. Evaluation does not read hardware, change a fan
/// curve, use sudo, or signal a process.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThresholdSample {
    /// 1-minute CPU load.
    pub cpu_load: f64,
    /// Temperature in Celsius.
    pub temp_c: f64,
    /// Free disk bytes.
    pub disk_free_bytes: f64,
    /// Used memory as a fraction of total memory (`0.0` is empty, `1.0` is full).
    pub mem_used_fraction: f64,
}

/// One crossed optional threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct ThresholdWarning {
    pub field: &'static str,
    pub observed: f64,
    pub threshold: f64,
    pub label: &'static str,
}

impl ThresholdWarning {
    fn crossed(field: &'static str, observed: f64, threshold: f64) -> Self {
        Self {
            field,
            observed,
            threshold,
            label: RULES_OF_THUMB,
        }
    }
}

impl std::fmt::Display for ThresholdWarning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{field} {observed} crossed {threshold} ({label})",
            field = self.field,
            observed = self.observed,
            threshold = self.threshold,
            label = self.label
        )
    }
}

/// Compare `sample` with the optional thresholds on `health`.
///
/// A `None` threshold emits no warning for that field. High CPU load,
/// temperature, and memory fraction warn when the sample is above the
/// threshold. Disk free bytes warn when the sample is below the threshold.
pub fn evaluate_thresholds(
    health: &HealthConfig,
    sample: &ThresholdSample,
) -> Vec<ThresholdWarning> {
    let mut warnings = Vec::new();
    push_above(
        &mut warnings,
        "warn_cpu_load",
        health.warn_cpu_load,
        sample.cpu_load,
    );
    push_above(
        &mut warnings,
        "warn_temp_c",
        health.warn_temp_c,
        sample.temp_c,
    );
    push_below(
        &mut warnings,
        "warn_disk_free_bytes",
        health.warn_disk_free_bytes,
        sample.disk_free_bytes,
    );
    push_above(
        &mut warnings,
        "warn_mem_used_fraction",
        health.warn_mem_used_fraction,
        sample.mem_used_fraction,
    );
    warnings
}

fn push_above(
    warnings: &mut Vec<ThresholdWarning>,
    field: &'static str,
    threshold: Option<f64>,
    observed: f64,
) {
    let Some(threshold) = threshold else {
        return;
    };
    if observed > threshold {
        warnings.push(ThresholdWarning::crossed(field, observed, threshold));
    }
}

fn push_below(
    warnings: &mut Vec<ThresholdWarning>,
    field: &'static str,
    threshold: Option<f64>,
    observed: f64,
) {
    let Some(threshold) = threshold else {
        return;
    };
    if observed < threshold {
        warnings.push(ThresholdWarning::crossed(field, observed, threshold));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quiet_sample() -> ThresholdSample {
        ThresholdSample {
            cpu_load: 0.2,
            temp_c: 40.0,
            disk_free_bytes: 50_000_000_000.0,
            mem_used_fraction: 0.3,
        }
    }

    #[test]
    fn crossed_temperature_warns_as_a_rule_of_thumb() {
        let health = HealthConfig {
            warn_temp_c: Some(70.0),
            ..HealthConfig::default()
        };
        let sample = ThresholdSample {
            temp_c: 81.5,
            ..quiet_sample()
        };
        let warnings = evaluate_thresholds(&health, &sample);
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].field, "warn_temp_c");
        assert_eq!(warnings[0].label, RULES_OF_THUMB);
        assert!(warnings[0].to_string().contains(RULES_OF_THUMB));
    }

    #[test]
    fn absent_threshold_emits_no_warning() {
        let health = HealthConfig {
            warn_cpu_load: Some(8.0),
            ..HealthConfig::default()
        };
        let sample = ThresholdSample {
            cpu_load: 1.0,
            temp_c: 120.0,
            disk_free_bytes: 0.0,
            mem_used_fraction: 0.99,
        };
        assert!(evaluate_thresholds(&health, &sample).is_empty());
    }
}
