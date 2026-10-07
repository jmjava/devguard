//! Offline CLI smoke tests for M0 acceptance commands.

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo::CommandCargoExt;
use predicates::prelude::*;
use std::process::Command;
use tempfile::tempdir;

fn devguard() -> Command {
    Command::cargo_bin("devguard").expect("binary")
}

#[test]
fn help_lists_core_commands() {
    devguard()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("doctor"))
        .stdout(predicate::str::contains("config"))
        .stdout(predicate::str::contains("status"))
        .stdout(predicate::str::contains("health"))
        .stdout(predicate::str::contains("gpu"));
}

#[test]
fn gpu_help_documents_a_missing_field_as_unavailable() {
    devguard()
        .args(["gpu", "scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("UUID"))
        .stdout(predicate::str::contains("sudo"));
}

#[test]
fn gpu_scan_json_never_prints_a_raw_uuid() {
    let output = devguard()
        .args(["--json", "gpu", "scan"])
        .output()
        .expect("gpu scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("GPU-") && !stderr.contains("GPU-"),
        "raw uuid leaked\nstdout={stdout}\nstderr={stderr}"
    );
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "gpu scan");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["loads_modules"], false);
    assert!(value["data"].get("processes").is_none());
    let nvidia = value["data"]["nvidia_smi"]["status"].as_str();
    assert!(nvidia == Some("available") || nvidia == Some("unavailable"));
    let clean = value["data"]["clean"].as_bool().expect("clean");
    if nvidia == Some("unavailable") || !clean {
        assert!(!clean);
        assert_eq!(output.status.code(), Some(3), "{stdout}");
    } else {
        assert_eq!(output.status.code(), Some(0), "{stdout}");
    }
    let gpus = value["data"]["gpus"].as_array().expect("gpus");
    if nvidia == Some("unavailable") {
        assert!(gpus.is_empty());
    }
    for gpu in gpus {
        assert!(gpu["index"].is_number());
        assert!(gpu.get("uuid").is_none());
        assert!(gpu.get("cmdline").is_none());
        assert!(gpu.get("args").is_none());
        let hash = &gpu["uuid_hash"];
        let status = hash["status"].as_str();
        assert!(status == Some("available") || status == Some("unavailable"));
        if let Some(value) = hash["value"].as_str() {
            assert_eq!(value.len(), 64);
            assert!(value.chars().all(|ch| ch.is_ascii_hexdigit()));
        }
    }
}

#[test]
fn gpu_scan_human_states_sudo_and_modules_are_off() {
    let output = devguard().args(["gpu", "scan"]).output().expect("gpu scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard GPU scan"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("loads modules: no"));
    assert!(!stdout.contains("GPU-"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
    let code = output.status.code();
    assert!(code == Some(0) || code == Some(3), "{stdout}");
}

#[test]
fn health_help_documents_the_fan_command() {
    devguard()
        .args(["health", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("fan"))
        .stdout(predicate::str::contains("fan curve"));
}

#[test]
fn health_fan_json_reports_observations_and_hypotheses() {
    let output = devguard()
        .args(["--json", "health", "fan"])
        .output()
        .expect("health fan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health fan");
    assert_eq!(value["ok"], true);
    assert!(value["data"]["observations"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(value["data"]["hypotheses"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert_eq!(value["data"]["changes_fan_curve"], false);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["loads_modules"], false);
    assert_eq!(value["data"]["writes_bios"], false);
    let sensors = value["data"]["sensors"]["status"].as_str();
    let nvidia = value["data"]["nvidia_smi"]["status"].as_str();
    let chassis = value["data"]["chassis_fan"]["status"].as_str();
    assert!(sensors == Some("available") || sensors == Some("unavailable"));
    assert!(nvidia == Some("available") || nvidia == Some("unavailable"));
    let incomplete = sensors == Some("unavailable")
        || nvidia == Some("unavailable")
        || chassis == Some("unavailable");
    if incomplete {
        assert_eq!(value["data"]["clean"], false);
        assert_eq!(output.status.code(), Some(3), "{stdout}");
    } else {
        assert_eq!(value["data"]["clean"], true);
        assert_eq!(output.status.code(), Some(0), "{stdout}");
    }
    if let Some(processes) = value["data"]["processes"].as_array() {
        for proc in processes {
            assert!(proc.get("name").is_some());
            assert!(proc.get("cmdline").is_none());
            assert!(proc.get("args").is_none());
        }
    }
}

#[test]
fn health_fan_human_separates_observations_from_hypotheses() {
    let output = devguard()
        .args(["health", "fan"])
        .output()
        .expect("health fan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Observations"));
    assert!(stdout.contains("Hypotheses"));
    assert!(stdout.contains("changes fan curve: no"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
    let code = output.status.code();
    assert!(code == Some(0) || code == Some(3), "{stdout}");
}

#[test]
fn config_init_validate_doctor_json_roundtrip() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("config.toml");

    devguard()
        .args(["--config", config.to_str().unwrap(), "config", "init"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Wrote config"));

    assert!(config.exists());

    let validate = devguard()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "config",
            "validate",
        ])
        .output()
        .expect("validate");
    // Fresh init should validate cleanly (exit 0). Exit 3 is reserved for path warnings.
    assert_eq!(
        validate.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&validate.stderr)
    );
    let validate_stdout = String::from_utf8_lossy(&validate.stdout);
    assert!(validate_stdout.contains("\"schema_version\": 1"));
    assert!(validate_stdout.contains("\"ok\": true"));
    assert!(validate_stdout.contains("\"capture_gpu\": true"));

    let output = devguard()
        .args(["--config", config.to_str().unwrap(), "--json", "doctor"])
        .output()
        .expect("doctor");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["ok"], true);
    assert!(value["data"]["checks"].is_array());
    assert!(value["data"]["ready_for_gpu_metrics"].is_boolean());
}

#[test]
fn validate_missing_config_fails() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("missing.toml");
    devguard()
        .args(["--config", config.to_str().unwrap(), "config", "validate"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
