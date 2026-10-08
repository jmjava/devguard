//! GPU-rail energy from a series of power samples.
//!
//! Energy is average power times the interval from the earliest timestamp to
//! the latest. This module does not call `nvidia-smi` and does not invent a
//! joule value when power is missing or the samples have no interval.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::exit::ExitCode;
use crate::slm::MeasurementPlane;

/// One power reading. `power_w` is absent when that sample has no wattage.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PowerSample {
    pub observed_at: DateTime<Utc>,
    pub power_w: Option<f64>,
}

/// `available` or `unavailable`. A missing reading is never a joule value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnergyStatus {
    Available,
    Unavailable,
}

/// Derived GPU-rail energy. The plane is always `gpu_rail`, including when
/// the numbers are unavailable.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GpuRailEnergy {
    pub status: EnergyStatus,
    pub measurement_plane: MeasurementPlane,
    /// Always false. Derivation never invokes `nvidia-smi`.
    pub calls_nvidia_smi: bool,
    pub sample_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mean_power_w: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub energy_j: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub joules_per_token: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_per_joule: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<u64>,
    pub detail: String,
}

impl GpuRailEnergy {
    pub fn exit_code(&self) -> ExitCode {
        match self.status {
            EnergyStatus::Available => ExitCode::Success,
            EnergyStatus::Unavailable => ExitCode::Partial,
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        if self.status == EnergyStatus::Unavailable {
            vec![self.detail.clone()]
        } else {
            Vec::new()
        }
    }
}

/// Derive joules as mean power times the timestamp span.
///
/// `tokens`, when supplied and greater than zero, also fills joules per token
/// and tokens per joule. A missing watt reading, a non-finite watt reading, or
/// a single sample (no positive interval) returns [`EnergyStatus::Unavailable`]
/// with every energy field empty.
pub fn derive_gpu_rail_energy(samples: &[PowerSample], tokens: Option<u64>) -> GpuRailEnergy {
    if samples.is_empty() {
        return unavailable(0, tokens, "no power samples");
    }
    if samples.iter().any(|sample| !usable_power(sample.power_w)) {
        return unavailable(samples.len(), tokens, "missing power");
    }

    let mut ordered: Vec<&PowerSample> = samples.iter().collect();
    ordered.sort_by_key(|sample| sample.observed_at);
    let start = ordered[0].observed_at;
    let end = ordered[ordered.len() - 1].observed_at;
    let duration_s = (end - start).as_seconds_f64();
    if ordered.len() < 2 || duration_s <= 0.0 {
        return unavailable(samples.len(), tokens, "no interval");
    }

    let watts: Vec<f64> = ordered
        .iter()
        .map(|sample| sample.power_w.unwrap())
        .collect();
    let mean_power_w = watts.iter().sum::<f64>() / watts.len() as f64;
    if !mean_power_w.is_finite() {
        return unavailable(samples.len(), tokens, "missing power");
    }
    let energy_j = mean_power_w * duration_s;
    if !energy_j.is_finite() {
        return unavailable(samples.len(), tokens, "missing power");
    }

    let (joules_per_token, tokens_per_joule) = efficiency(energy_j, tokens);
    GpuRailEnergy {
        status: EnergyStatus::Available,
        measurement_plane: MeasurementPlane::GpuRail,
        calls_nvidia_smi: false,
        sample_count: samples.len(),
        mean_power_w: Some(mean_power_w),
        duration_s: Some(duration_s),
        energy_j: Some(energy_j),
        joules_per_token,
        tokens_per_joule,
        tokens,
        detail: "gpu-rail energy is average power times the sample interval".to_string(),
    }
}

pub fn format_energy_human(report: &GpuRailEnergy) -> String {
    let mut out = String::new();
    out.push_str("DevGuard SLM energy\n");
    out.push_str("  measurement_plane: gpu_rail\n");
    out.push_str("  calls nvidia-smi: no\n");
    out.push_str(&format!("  status: {}\n", status_word(report.status)));
    out.push_str(&format!("  samples: {}\n", report.sample_count));
    out.push_str(&format!(
        "  mean power: {}\n",
        watts_text(report.mean_power_w)
    ));
    out.push_str(&format!(
        "  duration: {}\n",
        seconds_text(report.duration_s)
    ));
    out.push_str(&format!("  energy: {}\n", joules_text(report.energy_j)));
    out.push_str(&format!("  tokens: {}\n", tokens_text(report.tokens)));
    out.push_str(&format!(
        "  joules per token: {}\n",
        number_text(report.joules_per_token)
    ));
    out.push_str(&format!(
        "  tokens per joule: {}\n",
        number_text(report.tokens_per_joule)
    ));
    if report.status == EnergyStatus::Unavailable {
        out.push_str(&format!("  detail: {}\n", report.detail));
    }
    out
}

fn unavailable(sample_count: usize, tokens: Option<u64>, detail: &str) -> GpuRailEnergy {
    GpuRailEnergy {
        status: EnergyStatus::Unavailable,
        measurement_plane: MeasurementPlane::GpuRail,
        calls_nvidia_smi: false,
        sample_count,
        mean_power_w: None,
        duration_s: None,
        energy_j: None,
        joules_per_token: None,
        tokens_per_joule: None,
        tokens,
        detail: detail.to_string(),
    }
}

fn usable_power(power_w: Option<f64>) -> bool {
    matches!(power_w, Some(watts) if watts.is_finite() && watts >= 0.0)
}

/// Parse one CLI sample: `<watts>@<rfc3339>`, or `missing@<rfc3339>` when power is absent.
pub fn parse_power_sample(raw: &str) -> crate::Result<PowerSample> {
    let (watts, stamp) = raw.rsplit_once('@').ok_or_else(|| {
        crate::DevGuardError::Usage(format!("sample must be <watts>@<rfc3339>, got {raw}"))
    })?;
    let observed_at = DateTime::parse_from_rfc3339(stamp)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            crate::DevGuardError::Usage(format!("sample timestamp is not RFC3339: {stamp}"))
        })?;
    let power_w = if watts.is_empty()
        || watts.eq_ignore_ascii_case("missing")
        || watts.eq_ignore_ascii_case("unavailable")
    {
        None
    } else {
        let value: f64 = watts.parse().map_err(|_| {
            crate::DevGuardError::Usage(format!("sample watts are not a number: {watts}"))
        })?;
        Some(value)
    };
    Ok(PowerSample {
        observed_at,
        power_w,
    })
}

fn efficiency(energy_j: f64, tokens: Option<u64>) -> (Option<f64>, Option<f64>) {
    let Some(tokens) = tokens.filter(|count| *count > 0) else {
        return (None, None);
    };
    let tokens_f = tokens as f64;
    let joules_per_token = energy_j / tokens_f;
    let tokens_per_joule = if energy_j > 0.0 {
        Some(tokens_f / energy_j)
    } else {
        None
    };
    (Some(joules_per_token), tokens_per_joule)
}

fn status_word(status: EnergyStatus) -> &'static str {
    match status {
        EnergyStatus::Available => "available",
        EnergyStatus::Unavailable => "unavailable",
    }
}

fn watts_text(value: Option<f64>) -> String {
    match value {
        Some(watts) => format!("{} W", fmt_num(watts)),
        None => "unavailable".to_string(),
    }
}

fn seconds_text(value: Option<f64>) -> String {
    match value {
        Some(seconds) => format!("{} s", fmt_num(seconds)),
        None => "unavailable".to_string(),
    }
}

fn joules_text(value: Option<f64>) -> String {
    match value {
        Some(joules) => format!("{} J", fmt_num(joules)),
        None => "unavailable".to_string(),
    }
}

fn tokens_text(value: Option<u64>) -> String {
    match value {
        Some(tokens) => tokens.to_string(),
        None => "unavailable".to_string(),
    }
}

fn number_text(value: Option<f64>) -> String {
    match value {
        Some(number) => fmt_num(number),
        None => "unavailable".to_string(),
    }
}

fn fmt_num(value: f64) -> String {
    if !value.is_finite() {
        return "unavailable".to_string();
    }
    if (value - value.round()).abs() < 1e-9 {
        return format!("{}", value.round() as i64);
    }
    let text = format!("{value:.6}");
    text.trim_end_matches('0').trim_end_matches('.').to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(seconds: i64, watts: impl Into<Option<f64>>) -> PowerSample {
        PowerSample {
            observed_at: DateTime::from_timestamp(1_700_000_000 + seconds, 0).expect("timestamp"),
            power_w: watts.into(),
        }
    }

    #[test]
    fn average_power_times_interval_is_joules() {
        let samples = vec![at(0, Some(60.0)), at(10, Some(100.0))];
        let report = derive_gpu_rail_energy(&samples, Some(100));
        assert_eq!(report.status, EnergyStatus::Available);
        assert_eq!(report.measurement_plane, MeasurementPlane::GpuRail);
        assert!(!report.calls_nvidia_smi);
        assert_eq!(report.mean_power_w, Some(80.0));
        assert_eq!(report.duration_s, Some(10.0));
        assert_eq!(report.energy_j, Some(800.0));
        assert_eq!(report.joules_per_token, Some(8.0));
        assert_eq!(report.tokens_per_joule, Some(0.125));
    }

    #[test]
    fn sample_order_does_not_change_the_interval() {
        let samples = vec![at(10, Some(80.0)), at(0, Some(80.0)), at(5, Some(80.0))];
        let report = derive_gpu_rail_energy(&samples, None);
        assert_eq!(report.energy_j, Some(800.0));
        assert_eq!(report.joules_per_token, None);
        assert_eq!(report.tokens_per_joule, None);
        assert_eq!(report.measurement_plane, MeasurementPlane::GpuRail);
    }

    #[test]
    fn missing_power_is_unavailable() {
        let samples = vec![at(0, Some(80.0)), at(10, None)];
        let report = derive_gpu_rail_energy(&samples, Some(100));
        assert_eq!(report.status, EnergyStatus::Unavailable);
        assert_eq!(report.detail, "missing power");
        assert_eq!(report.energy_j, None);
        assert_eq!(report.joules_per_token, None);
        assert_eq!(report.tokens_per_joule, None);
        assert_eq!(report.measurement_plane, MeasurementPlane::GpuRail);
        assert_eq!(report.exit_code(), ExitCode::Partial);
    }

    #[test]
    fn non_finite_power_is_unavailable() {
        let samples = vec![at(0, Some(f64::NAN)), at(10, Some(80.0))];
        let report = derive_gpu_rail_energy(&samples, Some(10));
        assert_eq!(report.status, EnergyStatus::Unavailable);
        assert_eq!(report.energy_j, None);
    }

    #[test]
    fn a_single_sample_has_no_interval() {
        let samples = vec![at(0, Some(80.0))];
        let report = derive_gpu_rail_energy(&samples, Some(50));
        assert_eq!(report.status, EnergyStatus::Unavailable);
        assert_eq!(report.detail, "no interval");
        assert_eq!(report.energy_j, None);
        assert_eq!(report.mean_power_w, None);
        assert_eq!(report.joules_per_token, None);
    }

    #[test]
    fn equal_timestamps_have_no_interval() {
        let samples = vec![at(4, Some(40.0)), at(4, Some(60.0))];
        let report = derive_gpu_rail_energy(&samples, None);
        assert_eq!(report.detail, "no interval");
        assert_eq!(report.energy_j, None);
    }

    #[test]
    fn no_samples_are_unavailable() {
        let report = derive_gpu_rail_energy(&[], None);
        assert_eq!(report.detail, "no power samples");
        assert_eq!(report.sample_count, 0);
        assert_eq!(report.energy_j, None);
        assert_eq!(report.measurement_plane, MeasurementPlane::GpuRail);
    }

    #[test]
    fn zero_tokens_do_not_invent_efficiency() {
        let samples = vec![at(0, Some(50.0)), at(2, Some(50.0))];
        let report = derive_gpu_rail_energy(&samples, Some(0));
        assert_eq!(report.energy_j, Some(100.0));
        assert_eq!(report.joules_per_token, None);
        assert_eq!(report.tokens_per_joule, None);
    }

    #[test]
    fn zero_power_does_not_invent_tokens_per_joule() {
        let samples = vec![at(0, Some(0.0)), at(5, Some(0.0))];
        let report = derive_gpu_rail_energy(&samples, Some(20));
        assert_eq!(report.energy_j, Some(0.0));
        assert_eq!(report.joules_per_token, Some(0.0));
        assert_eq!(report.tokens_per_joule, None);
    }

    #[test]
    fn human_text_labels_the_plane_and_stays_unavailable() {
        let report = derive_gpu_rail_energy(&[at(0, Some(15.0))], None);
        let text = format_energy_human(&report);
        assert!(text.contains("measurement_plane: gpu_rail"));
        assert!(text.contains("calls nvidia-smi: no"));
        assert!(text.contains("status: unavailable"));
        assert!(text.contains("energy: unavailable"));
        assert!(!text.to_ascii_lowercase().contains("healthy"));
    }
}
