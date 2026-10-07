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
        .stdout(predicate::str::contains("remote"));
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

#[test]
fn remote_status_is_off_without_a_target() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("config.toml");
    devguard()
        .args(["--config", config.to_str().unwrap(), "config", "init"])
        .assert()
        .success();

    let output = devguard()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "remote",
            "status",
        ])
        .output()
        .expect("remote status");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "remote status");
    assert_eq!(value["data"]["target"], "off");
    assert_eq!(value["data"]["host"], "unconfigured");
    assert_eq!(value["data"]["binds_all_interfaces"], false);
    assert_eq!(value["data"]["arbitrary_exec"], false);
    assert_eq!(value["data"]["public_tunnel"], false);
    assert_eq!(value["data"]["resident_daemon"], false);

    devguard()
        .args([
            "--config",
            config.to_str().unwrap(),
            "remote",
            "tunnel",
            "up",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not configured"));
}

#[test]
fn remote_status_reports_host_down_without_secrets() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("config.toml");
    let ssh = dir.path().join("fake-ssh");
    std::fs::write(
        &config,
        "schema_version = 1\n[remote]\nhost = \"secret-downstairs\"\nuser = \"labuser\"\nport = 2222\n",
    )
    .unwrap();
    std::fs::write(
        &ssh,
        "#!/bin/sh\necho 'ssh: connect to host secret-downstairs port 2222: No route to host' >&2\nexit 255\n",
    )
    .unwrap();
    let mut perms = std::fs::metadata(&ssh).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    std::fs::set_permissions(&ssh, perms).unwrap();

    let output = devguard()
        .env("DEVGUARD_SSH_BIN", &ssh)
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "remote",
            "status",
        ])
        .output()
        .expect("remote status");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!rendered.contains("secret-downstairs"));
    assert!(!rendered.contains("labuser"));
    assert!(!rendered.contains("2222"));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["data"]["host"], "down");
    assert_eq!(value["data"]["tags"]["state"], "unavailable");
    assert_eq!(value["data"]["gpu"]["state"], "unavailable");
    assert_eq!(value["data"]["fan"]["state"], "unavailable");
}
