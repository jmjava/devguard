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
        .stdout(predicate::str::contains("gpu"))
        .stdout(predicate::str::contains("remote"));
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
fn health_runaway_json_is_one_document() {
    let output = devguard()
        .args(["--json", "health", "runaway"])
        .output()
        .expect("health runaway");
    let code = output.status.code();
    assert!(
        code == Some(0) || code == Some(2),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health runaway");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["stops_processes"], false);
    assert!(value["data"]["processes"].is_array());
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
fn health_watch_help_documents_ctrl_c_and_interval() {
    devguard()
        .args(["health", "watch", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Ctrl+C"))
        .stdout(predicate::str::contains("--interval"))
        .stdout(predicate::str::contains("background service"))
        .stdout(predicate::str::contains("unavailable"));
}

#[test]
fn health_watch_rejects_an_interval_outside_the_bound() {
    devguard()
        .args(["health", "watch", "--interval", "0s"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("outside"));
}

#[test]
fn health_watch_rejects_json_without_opening_a_terminal() {
    devguard()
        .args(["--json", "health", "watch", "--interval", "5s"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("does not emit JSON"));
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

#[test]
fn slm_energy_help_does_not_call_nvidia_smi() {
    devguard()
        .args(["slm", "energy", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("nvidia-smi"))
        .stdout(predicate::str::contains("--sample"))
        .stdout(predicate::str::contains("--tokens"));
}

#[test]
fn slm_energy_json_derives_fixture_joules() {
    let output = devguard()
        .args([
            "--json",
            "slm",
            "energy",
            "--sample",
            "60@2026-10-07T20:00:00Z",
            "--sample",
            "100@2026-10-07T20:00:10Z",
            "--tokens",
            "100",
        ])
        .output()
        .expect("slm energy");
    assert!(output.status.success(), "{:?}", output);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "slm energy");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["status"], "available");
    assert_eq!(value["data"]["measurement_plane"], "gpu_rail");
    assert_eq!(value["data"]["calls_nvidia_smi"], false);
    assert_eq!(value["data"]["energy_j"], 800.0);
    assert_eq!(value["data"]["joules_per_token"], 8.0);
    assert_eq!(value["data"]["tokens_per_joule"], 0.125);
}

#[test]
fn slm_energy_single_sample_is_unavailable() {
    let output = devguard()
        .args([
            "--json",
            "slm",
            "energy",
            "--sample",
            "80@2026-10-07T20:00:00Z",
            "--tokens",
            "50",
        ])
        .output()
        .expect("slm energy");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["data"]["status"], "unavailable");
    assert_eq!(value["data"]["measurement_plane"], "gpu_rail");
    assert!(value["data"].get("energy_j").is_none());
    assert!(value["data"].get("joules_per_token").is_none());
    assert_eq!(value["warnings"][0], "no interval");
}

#[test]
fn slm_energy_rejects_a_malformed_sample() {
    devguard()
        .args(["slm", "energy", "--sample", "80"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("<watts>@<rfc3339>"));
}
