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
        .stdout(predicate::str::contains("status"));
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
