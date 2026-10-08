//! Offline CLI smoke tests for M0 acceptance commands.

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo::CommandCargoExt;
use predicates::prelude::*;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
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
        .stdout(predicate::str::contains("remote"))
        .stdout(predicate::str::contains("slm"))
        .stdout(predicate::str::contains("dev"));
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
fn health_scan_help_documents_unavailable_sources() {
    devguard()
        .args(["health", "scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("signal"))
        .stdout(predicate::str::contains("BIOS"))
        .stdout(predicate::str::contains("arguments"));
}

#[test]
fn health_scan_json_reports_names_only() {
    let output = devguard()
        .args(["--json", "health", "scan"])
        .output()
        .expect("health scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.to_ascii_lowercase().contains("healthy"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health scan");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["sends_signals"], false);
    assert_eq!(value["data"]["loads_modules"], false);
    assert_eq!(value["data"]["writes_bios"], false);
    assert!(value["data"].get("cmdline").is_none());
    assert!(value["data"].get("args").is_none());
    assert!(value["data"]["processes"].get("cmdline").is_none());
    assert!(value["data"]["processes"].get("args").is_none());
    let names = value["data"]["processes"]["names"]
        .as_array()
        .expect("names");
    for name in names {
        assert!(name.is_string(), "{stdout}");
    }
    for key in [
        "cpu_count",
        "memory_used_bytes",
        "memory_total_bytes",
        "swap_used_bytes",
        "disk_free_bytes",
        "uptime_seconds",
    ] {
        let status = value["data"][key]["status"].as_str();
        assert!(
            status == Some("available") || status == Some("unavailable"),
            "{key} {stdout}"
        );
    }
    let processes = value["data"]["processes"]["status"].as_str();
    assert!(processes == Some("available") || processes == Some("unavailable"));
    let clean = value["data"]["clean"].as_bool().expect("clean");
    let incomplete = !clean
        || value["data"]["cpu_count"]["status"] == "unavailable"
        || value["data"]["memory_used_bytes"]["status"] == "unavailable"
        || value["data"]["memory_total_bytes"]["status"] == "unavailable"
        || value["data"]["swap_used_bytes"]["status"] == "unavailable"
        || value["data"]["disk_free_bytes"]["status"] == "unavailable"
        || value["data"]["uptime_seconds"]["status"] == "unavailable"
        || processes == Some("unavailable");
    if incomplete {
        assert!(!clean);
        assert_eq!(output.status.code(), Some(3), "{stdout}");
    } else {
        assert_eq!(output.status.code(), Some(0), "{stdout}");
    }
}

#[test]
fn health_scan_human_states_the_safety_limits() {
    let output = devguard()
        .args(["health", "scan"])
        .output()
        .expect("health scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard health scan"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("sends signals: no"));
    assert!(stdout.contains("loads modules: no"));
    assert!(stdout.contains("writes BIOS: no"));
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
fn slm_run_help_states_it_does_not_call_ollama_or_bind_a_port() {
    devguard()
        .args(["slm", "run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("begin"))
        .stdout(predicate::str::contains("end"))
        .stdout(predicate::str::contains("Ollama"))
        .stdout(predicate::str::contains("port"));
}

#[test]
fn slm_run_begin_end_uses_a_temp_state_dir_and_does_not_invent_metrics() {
    let dir = tempdir().unwrap();
    let begin = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args(["--json", "slm", "run", "begin", "--label", "gsm8k"])
        .output()
        .expect("begin");
    assert!(
        begin.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&begin.stderr)
    );
    let opened: serde_json::Value = serde_json::from_slice(&begin.stdout).expect("begin json");
    assert_eq!(opened["command"], "slm run begin");
    assert_eq!(opened["ok"], true);
    assert_eq!(opened["data"]["calls_ollama"], false);
    assert_eq!(opened["data"]["binds_port"], false);
    assert!(opened["data"].get("latency").is_none());
    assert!(opened["data"].get("quality").is_none());
    let run_id = opened["data"]["run_id"].as_str().expect("run id");
    let record_path = dir.path().join("slm-runs").join(format!("{run_id}.json"));
    assert!(record_path.is_file());

    let end = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args(["--json", "slm", "run", "end", "--id", run_id])
        .output()
        .expect("end");
    assert!(
        end.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&end.stderr)
    );
    let closed: serde_json::Value = serde_json::from_slice(&end.stdout).expect("end json");
    assert_eq!(closed["command"], "slm run end");
    assert!(closed["data"]["duration_s"].as_f64().unwrap() >= 0.0);
    assert!(closed["data"]["ended_at"].is_string());
    assert!(closed["data"].get("latency").is_none());
    assert!(closed["data"].get("quality").is_none());
    assert_eq!(closed["data"]["calls_ollama"], false);
    assert_eq!(closed["data"]["binds_port"], false);
}

#[test]
fn slm_run_end_stores_harness_ttft_and_tokens() {
    let dir = tempdir().unwrap();
    let harness = dir.path().join("harness.json");
    std::fs::write(
        &harness,
        r#"{"ttft_ms": 42.0, "ttft_p99_ms": 80.0, "tokens": 16, "backend": "llama.cpp"}"#,
    )
    .unwrap();
    let begin = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args(["--json", "slm", "run", "begin"])
        .output()
        .expect("begin");
    assert!(begin.status.success());
    let opened: serde_json::Value = serde_json::from_slice(&begin.stdout).unwrap();
    let run_id = opened["data"]["run_id"].as_str().unwrap();

    let end = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--json",
            "slm",
            "run",
            "end",
            "--id",
            run_id,
            "--harness",
            harness.to_str().unwrap(),
        ])
        .output()
        .expect("end");
    assert!(
        end.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&end.stderr)
    );
    let closed: serde_json::Value = serde_json::from_slice(&end.stdout).unwrap();
    assert_eq!(closed["data"]["latency"]["ttft_ms"], 42.0);
    assert_eq!(closed["data"]["latency"]["ttft_p99_ms"], 80.0);
    assert!(
        closed["data"]["latency"].get("tpot_ms").is_none()
            || closed["data"]["latency"]["tpot_ms"].is_null()
    );
    assert_eq!(closed["data"]["experiment"]["output_tokens"], 16);
    assert_eq!(closed["data"]["experiment"]["backend"], "llama.cpp");
    assert!(closed["data"].get("quality").is_none());
    assert_eq!(closed["data"]["calls_ollama"], false);
    assert_eq!(closed["data"]["binds_port"], false);
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
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let mut body = value.clone();
    if let Some(obj) = body.as_object_mut() {
        obj.remove("observed_at");
    }
    let rendered = format!("{}{}", body, String::from_utf8_lossy(&output.stderr));
    assert!(!rendered.contains("secret-downstairs"), "{rendered}");
    assert!(!rendered.contains("labuser"), "{rendered}");
    assert!(!rendered.contains("2222"), "{rendered}");
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

#[test]
fn slm_host_help_says_a_missing_source_is_unavailable() {
    devguard()
        .args(["slm", "host", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"));
}

#[test]
fn slm_host_json_reports_fields_and_never_says_healthy() {
    let output = devguard()
        .args(["--json", "slm", "host"])
        .output()
        .expect("slm host");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.to_ascii_lowercase().contains("healthy"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "slm host");
    assert_eq!(value["ok"], true);
    let stamp = value["data"]["observed_at"].as_str().expect("timestamp");
    assert!(stamp.contains('T'), "{stamp}");
    for key in [
        "cpu_percent",
        "memory_used_bytes",
        "memory_total_bytes",
        "swap_used_bytes",
        "disk_free_bytes",
    ] {
        let status = value["data"][key]["status"].as_str();
        assert!(
            status == Some("available") || status == Some("unavailable"),
            "{key} {stdout}"
        );
    }
    let clean = value["data"]["clean"].as_bool().expect("clean");
    if clean {
        assert_eq!(output.status.code(), Some(0), "{stdout}");
    } else {
        assert_eq!(output.status.code(), Some(3), "{stdout}");
    }
}

#[test]
fn health_sensors_help_documents_hwmon_and_no_fan_curve_change() {
    devguard()
        .args(["health", "sensors", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("hwmon"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("fan curve"))
        .stdout(predicate::str::contains("sudo"));
}

#[test]
fn health_sensors_json_uses_a_fixture_tree() {
    let dir = tempdir().expect("tempdir");
    let core = dir.path().join("hwmon4");
    std::fs::create_dir_all(&core).unwrap();
    std::fs::write(core.join("name"), "coretemp\n").unwrap();
    std::fs::write(core.join("temp1_input"), "54000\n").unwrap();
    std::fs::write(core.join("temp1_label"), "Package id 0\n").unwrap();
    std::fs::write(core.join("temp2_input"), "45000\n").unwrap();
    std::fs::write(core.join("temp2_label"), "Core 0\n").unwrap();
    let board = dir.path().join("hwmon0");
    std::fs::create_dir_all(&board).unwrap();
    std::fs::write(board.join("name"), "acpitz\n").unwrap();
    std::fs::write(board.join("temp1_input"), "27800\n").unwrap();
    let fan = dir.path().join("hwmon3");
    std::fs::create_dir_all(&fan).unwrap();
    std::fs::write(fan.join("name"), "nct6798\n").unwrap();
    std::fs::write(fan.join("fan1_input"), "820\n").unwrap();
    std::fs::write(fan.join("fan1_label"), "cpu_fan\n").unwrap();

    let output = devguard()
        .env("DEVGUARD_HWMON_ROOT", dir.path())
        .env("DEVGUARD_SENSORS_BIN", dir.path().join("missing-sensors"))
        .args(["--json", "health", "sensors"])
        .output()
        .expect("health sensors");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health sensors");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["status"], "available");
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["loads_modules"], false);
    assert_eq!(value["data"]["changes_fan_curve"], false);
    assert_eq!(value["data"]["sensors"]["status"], "unavailable");
    assert_eq!(value["data"]["package"][0]["label"], "Package id 0");
    assert_eq!(value["data"]["package"][0]["celsius"], 54.0);
    assert_eq!(value["data"]["cpu"][0]["label"], "Core 0");
    assert_eq!(value["data"]["cpu"][0]["celsius"], 45.0);
    assert_eq!(value["data"]["board"][0]["chip"], "acpitz");
    assert_eq!(value["data"]["board"][0]["celsius"], 27.8);
    assert_eq!(value["data"]["fans"][0]["label"], "cpu_fan");
    assert_eq!(value["data"]["fans"][0]["rpm"], 820);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn health_sensors_without_hwmon_files_is_unavailable() {
    let dir = tempdir().expect("tempdir");
    let output = devguard()
        .env("DEVGUARD_HWMON_ROOT", dir.path())
        .env("DEVGUARD_SENSORS_BIN", dir.path().join("missing-sensors"))
        .args(["--json", "health", "sensors"])
        .output()
        .expect("health sensors");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "health sensors");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["status"], "unavailable");
    assert_eq!(value["data"]["sensors"]["status"], "unavailable");
    assert_eq!(value["data"]["hwmon"]["status"], "unavailable");
    assert!(value["data"]["package"].as_array().unwrap().is_empty());
    assert!(value["data"]["fans"].as_array().unwrap().is_empty());
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("hwmon")));
}

#[test]
fn health_os_help_documents_hash_and_safety_limits() {
    devguard()
        .args(["health", "os", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("boot id"))
        .stdout(predicate::str::contains("privacy-preserving"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("port"))
        .stdout(predicate::str::contains("package"));
}

fn write_proc_fixture(root: &std::path::Path) {
    let random = root.join("sys/kernel/random");
    std::fs::create_dir_all(&random).expect("proc dirs");
    std::fs::write(root.join("sys/kernel/osrelease"), "7.0.0-38-generic\n").expect("osrelease");
    std::fs::write(
        root.join("sys/kernel/hostname"),
        "secret-workstation-name\n",
    )
    .expect("hostname");
    std::fs::write(
        root.join("sys/kernel/random/boot_id"),
        "01234567-89ab-cdef-0123-456789abcdef\n",
    )
    .expect("boot_id");
    std::fs::write(root.join("uptime"), "12345.67 890.12\n").expect("uptime");
}

#[test]
fn health_os_json_uses_a_proc_fixture_and_hides_the_hostname() {
    let dir = tempdir().expect("tempdir");
    write_proc_fixture(dir.path());
    let output = devguard()
        .env("DEVGUARD_PROC_ROOT", dir.path())
        .args(["--json", "health", "os"])
        .output()
        .expect("health os");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("secret-workstation-name"), "{stdout}");
    assert!(!stdout.to_ascii_lowercase().contains("healthy"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health os");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["opens_port"], false);
    assert_eq!(value["data"]["collects_packages"], false);
    assert_eq!(value["data"]["kernel_release"]["value"], "7.0.0-38-generic");
    assert_eq!(
        value["data"]["boot_id"]["value"],
        "01234567-89ab-cdef-0123-456789abcdef"
    );
    assert_eq!(value["data"]["uptime_seconds"]["value"], 12345.67);
    assert_eq!(
        value["data"]["hostname_hash"]["value"],
        "hn-9e2595de8ac1de6d"
    );
    assert!(value["data"].get("hostname").is_none());
}

#[test]
fn health_os_missing_proc_source_is_unavailable() {
    let dir = tempdir().expect("tempdir");
    write_proc_fixture(dir.path());
    std::fs::remove_file(dir.path().join("uptime")).expect("remove uptime");
    let output = devguard()
        .env("DEVGUARD_PROC_ROOT", dir.path())
        .args(["--json", "health", "os"])
        .output()
        .expect("health os");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("secret-workstation-name"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "health os");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["uptime_seconds"]["status"], "unavailable");
    assert_eq!(value["data"]["kernel_release"]["value"], "7.0.0-38-generic");
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("uptime")));
}

#[test]
fn health_os_human_states_the_safety_limits() {
    let dir = tempdir().expect("tempdir");
    write_proc_fixture(dir.path());
    let output = devguard()
        .env("DEVGUARD_PROC_ROOT", dir.path())
        .args(["health", "os"])
        .output()
        .expect("health os");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard health os"));
    assert!(stdout.contains("kernel: 7.0.0-38-generic"));
    assert!(stdout.contains("hostname hash: hn-9e2595de8ac1de6d"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("opens a port: no"));
    assert!(stdout.contains("collects packages: no"));
    assert!(stdout.contains("clean: yes"));
    assert!(!stdout.contains("secret-workstation-name"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn health_fan_help_remains() {
    devguard()
        .args(["health", "fan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("fan curve"))
        .stdout(predicate::str::contains("unavailable"));
}

#[test]
fn health_gpu_id_help_documents_identity_and_limits() {
    devguard()
        .args(["health", "gpu-id", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("driver"))
        .stdout(predicate::str::contains("PCI"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("kernel module"));
}

#[test]
fn health_gpu_id_json_parses_a_fixture_query() {
    let dir = tempdir().unwrap();
    let program = dir.path().join("query");
    std::fs::write(
        &program,
        "#!/bin/sh\ncat <<'EOF'\nNVIDIA Example GPU B, 550.90.07, 00000000:02:00.0\nNVIDIA Example, Laptop GPU, 550.54.14, 00000000:01:00.0\nEOF\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&program).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&program, perms).unwrap();

    let output = devguard()
        .env("DEVGUARD_NVIDIA_SMI_BIN", &program)
        .args(["--json", "health", "gpu-id"])
        .output()
        .expect("health gpu-id");
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("GPU-"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health gpu-id");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["loads_modules"], false);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["nvidia_smi"]["status"], "available");
    let gpus = value["data"]["gpus"].as_array().expect("gpus");
    assert_eq!(gpus.len(), 2);
    assert_eq!(gpus[0]["name"]["value"], "NVIDIA Example, Laptop GPU");
    assert_eq!(gpus[0]["driver_version"]["value"], "550.54.14");
    assert_eq!(gpus[0]["pci_bus_id"]["value"], "00000000:01:00.0");
    assert_eq!(gpus[1]["pci_bus_id"]["value"], "00000000:02:00.0");
    assert!(gpus[0].get("uuid").is_none());
    assert!(gpus[0].get("cmdline").is_none());
}

#[test]
fn health_gpu_id_missing_field_is_not_clean() {
    let dir = tempdir().unwrap();
    let program = dir.path().join("query");
    std::fs::write(
        &program,
        "#!/bin/sh\nprintf '%s\n' 'NVIDIA Example GPU A, [N/A], 00000000:01:00.0'\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&program).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&program, perms).unwrap();

    let output = devguard()
        .env("DEVGUARD_NVIDIA_SMI_BIN", &program)
        .args(["--json", "health", "gpu-id"])
        .output()
        .expect("health gpu-id");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "health gpu-id");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(
        value["data"]["gpus"][0]["driver_version"]["status"],
        "unavailable"
    );
    assert!(value["data"]["gpus"][0]["driver_version"]
        .get("value")
        .is_none());
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["loads_modules"], false);
}

#[test]
fn health_gpu_id_missing_tool_is_unavailable_not_clean() {
    let output = devguard()
        .env("DEVGUARD_NVIDIA_SMI_BIN", "/no/such/devguard-nvidia-smi")
        .args(["--json", "health", "gpu-id"])
        .output()
        .expect("health gpu-id");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "health gpu-id");
    assert_eq!(value["data"]["nvidia_smi"]["status"], "unavailable");
    assert_eq!(value["data"]["clean"], false);
    assert!(value["data"]["gpus"].as_array().unwrap().is_empty());
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["loads_modules"], false);
}

#[test]
fn health_ports_help_documents_attribution_and_limits() {
    devguard()
        .args(["health", "ports", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ss -lntup"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("attribution missing"))
        .stdout(predicate::str::contains("closed port"))
        .stdout(predicate::str::contains("command arguments"));
}

#[test]
fn health_ports_json_parses_a_fixture_listing() {
    let dir = tempdir().unwrap();
    let program = dir.path().join("ss");
    std::fs::write(
        &program,
        "#!/bin/sh\ncat <<'EOF'\ntcp LISTEN 0 128 127.0.0.1:9 0.0.0.0:* users:((\"fixture\",pid=4,fd=1))\ntcp LISTEN 0 128 127.0.0.1:10 0.0.0.0:*\nEOF\n",
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&program).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&program, perms).unwrap();

    let output = devguard()
        .env("DEVGUARD_SS_BIN", &program)
        .args(["--json", "health", "ports"])
        .output()
        .expect("health ports");
    assert_eq!(output.status.code(), Some(3), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("pid="), "{stdout}");
    assert!(!stdout.contains("http.server"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health ports");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["opens_port"], false);
    assert_eq!(value["data"]["scans_remote"], false);
    assert_eq!(value["data"]["collects_arguments"], false);
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["ss"]["status"], "available");
    let sockets = value["data"]["sockets"].as_array().expect("sockets");
    assert_eq!(sockets.len(), 2);
    assert_eq!(sockets[0]["protocol"], "tcp");
    assert_eq!(sockets[0]["address"], "127.0.0.1");
    assert_eq!(sockets[0]["port"], 9);
    assert_eq!(sockets[0]["process"], "fixture");
    assert_eq!(sockets[0]["attribution"], "present");
    assert_eq!(sockets[1]["port"], 10);
    assert_eq!(sockets[1]["attribution"], "missing");
    assert!(sockets[1]["process"].is_null());
    assert!(sockets[1].get("cmdline").is_none());
    assert!(sockets[1].get("args").is_none());
}

#[test]
fn health_ports_missing_ss_is_unavailable_not_clean() {
    let output = devguard()
        .env("DEVGUARD_SS_BIN", "/no/such/devguard-ss")
        .args(["--json", "health", "ports"])
        .output()
        .expect("health ports");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "health ports");
    assert_eq!(value["data"]["ss"]["status"], "unavailable");
    assert_eq!(value["data"]["clean"], false);
    assert!(value["data"]["sockets"].as_array().unwrap().is_empty());
    assert_eq!(value["data"]["opens_port"], false);
    assert_eq!(value["data"]["scans_remote"], false);
}

#[test]
fn dev_env_help_documents_a_missing_tool_as_unavailable() {
    devguard()
        .args(["dev", "env", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("PATH"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("network"))
        .stdout(predicate::str::contains("package audit"))
        .stdout(predicate::str::contains("install"));
}

fn write_version_tool(dir: &std::path::Path, name: &str, line: &str) {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\nprintf '%s\\n' '{line}'\n")).expect("fixture");
    let mut perms = std::fs::metadata(&path).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
}

#[test]
fn dev_env_json_reads_fixture_versions_from_path() {
    let dir = tempdir().expect("tempdir");
    let lines = [
        ("rustc", "rustc 1.85.0 (fixture)"),
        ("cargo", "cargo 1.85.0 (fixture)"),
        ("python3", "Python 3.12.3"),
        ("node", "v20.18.0"),
        ("git", "git version 2.43.0"),
        ("gcc", "gcc (Ubuntu 13.2.0-23ubuntu4) 13.2.0"),
    ];
    for (name, line) in lines {
        write_version_tool(dir.path(), name, line);
    }
    let output = devguard()
        .env("PATH", dir.path())
        .args(["--json", "dev", "env"])
        .output()
        .expect("dev env");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "dev env");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["installs_tools"], false);
    assert_eq!(value["data"]["uses_network"], false);
    assert_eq!(value["data"]["runs_package_audit"], false);
    let tools = value["data"]["tools"].as_array().expect("tools");
    assert_eq!(tools.len(), lines.len());
    for (tool, (name, line)) in tools.iter().zip(lines) {
        assert_eq!(tool["name"], name);
        assert_eq!(tool["status"], "available");
        assert_eq!(tool["version_line"], line);
    }
}

#[test]
fn dev_env_missing_tool_on_fixture_path_is_not_clean() {
    let dir = tempdir().expect("tempdir");
    write_version_tool(dir.path(), "git", "git version 2.43.0");
    let output = devguard()
        .env("PATH", dir.path())
        .args(["--json", "dev", "env"])
        .output()
        .expect("dev env");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(3), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "dev env");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["installs_tools"], false);
    assert_eq!(value["data"]["uses_network"], false);
    assert_eq!(value["data"]["runs_package_audit"], false);
    let gcc = value["data"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .find(|tool| tool["name"] == "gcc")
        .expect("gcc");
    assert_eq!(gcc["status"], "unavailable");
    assert!(gcc.get("version_line").is_none());
    assert!(gcc["detail"].as_str().unwrap_or("").contains("not on PATH"));
    let human = devguard()
        .env("PATH", dir.path())
        .args(["dev", "env"])
        .output()
        .expect("human");
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("DevGuard dev env"));
    assert!(text.contains("clean: no"));
    assert!(text.contains("runs package audit: no"));
    assert!(!text.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn health_files_help_documents_the_allowlist() {
    devguard()
        .args(["health", "files", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("config_hash_allowlist"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("SHA-256"))
        .stdout(predicate::str::contains("not stored"));
}

#[test]
fn health_files_json_hashes_fixtures_and_omits_token_text() {
    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.toml");
    let secret = dir.path().join("secret.env");
    let token = "token=ghp_SuperSecretTokenValue";
    std::fs::write(&plain, b"listen = 1\n").unwrap();
    std::fs::write(&secret, token.as_bytes()).unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "schema_version = 1\n\n[snapshot]\nconfig_hash_allowlist = [{plain:?}, {secret:?}]\n",
            plain = plain.display().to_string(),
            secret = secret.display().to_string(),
        ),
    )
    .unwrap();

    let output = devguard()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "health",
            "files",
        ])
        .output()
        .expect("health files");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(token), "{stdout}");
    assert!(!stdout.contains("SuperSecret"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "health files");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["persists_contents"], false);
    assert_eq!(value["data"]["prints_contents"], false);
    assert_eq!(value["data"]["hash_algorithm"], "sha256");
    let files = value["data"]["files"].as_array().expect("files");
    assert_eq!(files.len(), 2);
    assert_eq!(files[0]["status"], "available");
    assert_eq!(files[0]["path"], plain.display().to_string());
    assert_eq!(files[0]["size_bytes"], 11);
    assert!(files[0]["mtime_unix"].as_i64().unwrap() > 0);
    assert_eq!(files[0]["hash"].as_str().unwrap().len(), 64);
    assert_eq!(files[1]["size_bytes"], token.len() as i64);
    let hash = files[1]["hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|ch| ch.is_ascii_hexdigit()));
    assert!(value["data"].get("contents").is_none());
}

#[test]
fn health_files_missing_path_is_unavailable_and_not_clean() {
    let dir = tempdir().unwrap();
    let secret = dir.path().join("secret.env");
    let missing = dir.path().join("absent.toml");
    let token = "token=ghp_SuperSecretTokenValue";
    std::fs::write(&secret, token.as_bytes()).unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "schema_version = 1\n\n[snapshot]\nconfig_hash_allowlist = [{secret:?}, {missing:?}]\n",
            secret = secret.display().to_string(),
            missing = missing.display().to_string(),
        ),
    )
    .unwrap();

    let output = devguard()
        .args(["--config", config.to_str().unwrap(), "health", "files"])
        .output()
        .expect("health files");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard health files"));
    assert!(stdout.contains("unavailable (missing)"));
    assert!(stdout.contains("clean: no"));
    assert!(stdout.contains("sha256="));
    assert!(!stdout.contains(token), "{stdout}");
    assert!(!stdout.contains("SuperSecret"), "{stdout}");
}

#[test]
fn slm_host_human_prints_the_sample_header() {
    let output = devguard().args(["slm", "host"]).output().expect("slm host");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard SLM host"));
    assert!(stdout.contains("observed_at:"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
    let code = output.status.code();
    assert!(code == Some(0) || code == Some(3), "{stdout}");
}

#[test]
fn slm_export_help_does_not_call_ollama_or_nvidia_smi() {
    devguard()
        .args(["slm", "export", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("csv"))
        .stdout(predicate::str::contains("json"))
        .stdout(predicate::str::contains("empty"))
        .stdout(predicate::str::contains("Ollama"))
        .stdout(predicate::str::contains("port"))
        .stdout(predicate::str::contains("nvidia-smi"));
}

#[test]
fn slm_help_keeps_host_energy_and_run() {
    devguard()
        .args(["slm", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("host"))
        .stdout(predicate::str::contains("energy"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("export"))
        .stdout(predicate::str::contains("checklist"));
}

#[test]
fn slm_export_writes_csv_and_json_without_inventing_metrics() {
    let state = tempdir().unwrap();
    let out = tempdir().unwrap();
    let runs = state.path().join("slm-runs");
    std::fs::create_dir_all(&runs).unwrap();
    std::fs::write(
        runs.join("filled.json"),
        r#"{
          "schema_version": 1,
          "run_id": "run-filled",
          "started_at": "2026-10-07T20:00:00Z",
          "measurement_plane": "gpu_rail",
          "experiment": {
            "model_id": "llama-3.2-1b",
            "quantization": "Q4_K_M",
            "backend": "llama.cpp",
            "batch_size": 1,
            "prompt_tokens": 32,
            "output_tokens": 128
          },
          "latency": { "ttft_ms": 120.5, "tokens_per_second": 55.0 },
          "quality": { "task_name": "gsm8k", "task_score": 0.42 },
          "energy": { "mean_gpu_power_w": 80.0, "joules_per_token": 6.25 },
          "system": {
            "status": "partial",
            "gpus": [{
              "index": 0,
              "name": "NVIDIA GeForce RTX 3060",
              "memory_used_bytes": 4096,
              "temperature_c": 43.0,
              "power_draw_w": 999.0
            }]
          }
        }"#,
    )
    .unwrap();
    std::fs::write(
        runs.join("bare.json"),
        r#"{
          "schema_version": 1,
          "run_id": "run-bare",
          "started_at": "2026-10-07T21:00:00Z",
          "measurement_plane": "gpu_rail",
          "duration_s": 10.0,
          "system": {
            "status": "unavailable",
            "gpus": [{ "index": 0, "power_draw_w": 80.0 }]
          }
        }"#,
    )
    .unwrap();

    let output = devguard()
        .env("DEVGUARD_STATE_DIR", state.path())
        .args([
            "--json",
            "slm",
            "export",
            "--out",
            out.path().to_str().unwrap(),
        ])
        .output()
        .expect("slm export");
    assert!(
        output.status.success(),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope["command"], "slm export");
    assert_eq!(envelope["data"]["rows"], 2);
    assert_eq!(envelope["data"]["calls_ollama"], false);
    assert_eq!(envelope["data"]["binds_port"], false);
    assert_eq!(envelope["data"]["calls_nvidia_smi"], false);

    let csv = std::fs::read_to_string(out.path().join("slm-export.csv")).unwrap();
    let table: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(out.path().join("slm-export.json")).unwrap())
            .unwrap();
    assert!(csv.starts_with(
        "model,quantization,backend,hardware,prompt length,generation length,batch,TTFT,TPOT,tokens/s,peak VRAM,mean GPU power,J/token,temperature,task score,benchmark name,timestamp\n"
    ));
    let filled = &table["rows"][0];
    assert_eq!(filled["model"], "llama-3.2-1b");
    assert_eq!(filled["quantization"], "Q4_K_M");
    assert_eq!(filled["backend"], "llama.cpp");
    assert_eq!(filled["hardware"], "NVIDIA GeForce RTX 3060");
    assert_eq!(filled["prompt length"], "32");
    assert_eq!(filled["generation length"], "128");
    assert_eq!(filled["batch"], "1");
    assert_eq!(filled["TTFT"], "120.5");
    assert_eq!(filled["TPOT"], "");
    assert_eq!(filled["tokens/s"], "55");
    assert_eq!(filled["peak VRAM"], "4096");
    assert_eq!(filled["mean GPU power"], "80");
    assert_eq!(filled["J/token"], "6.25");
    assert_eq!(filled["temperature"], "43");
    assert_eq!(filled["task score"], "0.42");
    assert_eq!(filled["benchmark name"], "gsm8k");
    assert!(filled["timestamp"]
        .as_str()
        .unwrap()
        .contains("2026-10-07T20:00:00"));

    let bare = &table["rows"][1];
    for key in [
        "model",
        "quantization",
        "backend",
        "hardware",
        "prompt length",
        "generation length",
        "batch",
        "TTFT",
        "TPOT",
        "tokens/s",
        "peak VRAM",
        "mean GPU power",
        "J/token",
        "temperature",
        "task score",
        "benchmark name",
    ] {
        assert_eq!(bare[key], "", "{key}");
    }
    assert!(bare["timestamp"]
        .as_str()
        .unwrap()
        .contains("2026-10-07T21:00:00"));
    assert!(csv.contains("llama-3.2-1b,Q4_K_M,llama.cpp"));
    assert!(!csv.contains("999"));
}

#[test]
fn slm_checklist_prints_a_fixture_run_as_text_and_json() {
    let dir = tempdir().expect("temp state");
    let run_dir = dir.path().join("slm-runs");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(run_dir.join("fixture-run.json"), FIXTURE_RUN).unwrap();

    let json = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args(["--json", "slm", "checklist", "--id", "fixture-run"])
        .output()
        .expect("slm checklist json");
    assert!(json.status.success(), "{:?}", json);
    let value: serde_json::Value = serde_json::from_slice(&json.stdout).expect("json");
    assert_eq!(value["command"], "slm checklist");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["calls_ollama"], false);
    let fields = value["data"]["fields"].as_array().expect("fields");
    assert_eq!(fields.len(), 10);
    assert_eq!(fields[0]["name"], "model");
    assert_eq!(fields[0]["model_id"], "llama-3.2-1b");
    assert_eq!(fields[0]["status"], "available");
    assert_eq!(fields[4]["tokens_per_second"], 55.0);
    assert_eq!(fields[6]["joules_per_token"], 8.0);
    assert_eq!(fields[8]["task_score"], 0.5);
    assert_eq!(fields[8]["task_name"], "gsm8k");
    assert!(fields[3].get("ttft_p50_ms").is_none());

    let human = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args(["slm", "checklist", "--id", "fixture-run"])
        .output()
        .expect("slm checklist text");
    assert!(human.status.success(), "{:?}", human);
    let stdout = String::from_utf8_lossy(&human.stdout);
    assert!(stdout.contains("DevGuard slm checklist"));
    assert!(stdout.contains("calls Ollama: no"));
    assert!(stdout.contains("llama-3.2-1b"));
    assert!(stdout.contains("batch 1"));
    assert!(stdout.contains("ttft 120.5 ms"));
    assert!(stdout.contains("55 tok/s"));
    assert!(stdout.contains("8 J/token"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn health_units_help_documents_a_read_only_listing() {
    devguard()
        .args(["health", "units", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("enabled"))
        .stdout(predicate::str::contains("active"))
        .stdout(predicate::str::contains("failed"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("start"))
        .stdout(predicate::str::contains("stop"))
        .stdout(predicate::str::contains("enable"))
        .stdout(predicate::str::contains("disable"));
}

#[test]
fn health_units_json_parses_a_fixture_listing() {
    let listing = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../devguard-core/fixtures/systemctl-show.txt");
    let missing = tempdir().expect("tempdir");
    let output = devguard()
        .env("DEVGUARD_SYSTEMCTL_LISTING", &listing)
        .env(
            "DEVGUARD_SYSTEMCTL_BIN",
            missing.path().join("missing-systemctl"),
        )
        .env_remove("PATH")
        .args(["--json", "health", "units"])
        .output()
        .expect("health units");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health units");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["status"], "available");
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["starts_units"], false);
    assert_eq!(value["data"]["stops_units"], false);
    assert_eq!(value["data"]["enables_units"], false);
    assert_eq!(value["data"]["disables_units"], false);
    let units = value["data"]["units"].as_array().expect("units");
    let fixture = units
        .iter()
        .find(|unit| unit["name"] == "devguard-fixture.service")
        .expect("fixture unit");
    assert_eq!(fixture["enabled"], "static");
    assert_eq!(fixture["active"], "inactive");
    assert_eq!(fixture["failed"], false);
    let apport = units
        .iter()
        .find(|unit| unit["name"] == "apport.service")
        .expect("apport");
    assert_eq!(apport["enabled"], "enabled");
    assert_eq!(apport["active"], "failed");
    assert_eq!(apport["failed"], true);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn slm_checklist_missing_field_is_unavailable() {
    let dir = tempdir().expect("temp state");
    let run_dir = dir.path().join("slm-runs");
    std::fs::create_dir_all(&run_dir).unwrap();
    std::fs::write(
        run_dir.join("sparse-run.json"),
        r#"{
          "schema_version": 1,
          "run_id": "sparse-run",
          "started_at": "2026-10-07T20:00:00Z",
          "measurement_plane": "gpu_rail",
          "system": { "status": "unavailable" }
        }"#,
    )
    .unwrap();

    let output = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args(["--json", "slm", "checklist", "--id", "sparse-run"])
        .output()
        .expect("sparse checklist");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    let fields = value["data"]["fields"].as_array().expect("fields");
    assert_eq!(fields.len(), 10);
    let model = fields
        .iter()
        .find(|field| field["name"] == "model")
        .unwrap();
    assert_eq!(model["status"], "unavailable");
    assert_eq!(model["value"], "");
    assert!(model.get("model_id").is_none());
    assert!(model.get("joules_per_token").is_none());
    let task = fields
        .iter()
        .find(|field| field["name"] == "task_score_and_benchmark")
        .unwrap();
    assert_eq!(task["status"], "unavailable");
    assert!(task.get("task_score").is_none());
    let timestamp = fields
        .iter()
        .find(|field| field["name"] == "timestamp")
        .unwrap();
    assert_eq!(timestamp["status"], "available");
    assert_eq!(value["data"]["calls_ollama"], false);
}

const FIXTURE_RUN: &str = r#"{
  "schema_version": 1,
  "run_id": "fixture-run",
  "started_at": "2026-10-07T20:00:00Z",
  "ended_at": "2026-10-07T20:00:10Z",
  "measurement_plane": "gpu_rail",
  "experiment": {
    "model_id": "llama-3.2-1b",
    "parameter_count": 1000000000,
    "quantization": "Q4_K_M",
    "backend": "llama.cpp",
    "batch_size": 1,
    "context_length": null,
    "prompt_tokens": 32,
    "output_tokens": 128,
    "git_commit": "abc123",
    "notes": "cool-down 10s"
  },
  "latency": {
    "ttft_ms": 120.5,
    "ttft_p50_ms": null,
    "ttft_p99_ms": 240.0,
    "tpot_ms": 18.0,
    "tpot_p50_ms": null,
    "tpot_p99_ms": 40.0,
    "e2e_latency_ms": null,
    "tokens_per_second": 55.0,
    "throughput_kind": "decode"
  },
  "quality": {
    "task_name": "gsm8k",
    "task_metric": "exact_match",
    "task_score": 0.5,
    "higher_is_better": null
  },
  "energy": {
    "mean_gpu_power_w": 80.0,
    "energy_gpu_approx_j": null,
    "energy_wall_j": 900.0,
    "joules_per_token": 8.0,
    "tokens_per_joule": null,
    "throughput_per_watt": null
  },
  "system": {
    "status": "partial",
    "host": {
      "cpu_percent": null,
      "memory_used_bytes": 8000000000,
      "memory_total_bytes": 16000000000,
      "swap_used_bytes": null
    },
    "gpus": [
      {
        "index": 0,
        "name": "NVIDIA GeForce RTX 3060",
        "driver_version": "555.42",
        "utilization_percent": null,
        "memory_used_bytes": 5000000000,
        "memory_total_bytes": null,
        "temperature_c": 72.0,
        "power_draw_w": null,
        "power_limit_w": null
      }
    ]
  }
}"#;

#[test]
fn health_units_unreadable_listing_is_not_clean() {
    let dir = tempdir().expect("tempdir");
    let listing = dir.path().join("listing.txt");
    std::fs::write(&listing, "UNIT LOAD ACTIVE SUB DESCRIPTION\n").unwrap();
    let output = devguard()
        .env("DEVGUARD_SYSTEMCTL_LISTING", &listing)
        .env(
            "DEVGUARD_SYSTEMCTL_BIN",
            dir.path().join("missing-systemctl"),
        )
        .args(["--json", "health", "units"])
        .output()
        .expect("health units");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "health units");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["status"], "unavailable");
    assert!(value["data"]["units"].as_array().unwrap().is_empty());
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("unreadable")));
}

#[test]
fn health_units_missing_systemctl_is_not_clean() {
    let dir = tempdir().expect("tempdir");
    let output = devguard()
        .env_remove("DEVGUARD_SYSTEMCTL_LISTING")
        .env(
            "DEVGUARD_SYSTEMCTL_BIN",
            dir.path().join("missing-systemctl"),
        )
        .args(["health", "units"])
        .output()
        .expect("health units");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard health units"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("starts units: no"));
    assert!(stdout.contains("clean: no"));
    assert!(stdout.contains("not on PATH"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn health_packages_help_documents_read_only_lists() {
    devguard()
        .args(["health", "packages", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("apt install"))
        .stdout(predicate::str::contains("upgrade"));
}

#[test]
fn health_packages_json_parses_fixture_lists() {
    let dir = tempdir().expect("tempdir");
    let status = dir.path().join("status");
    let lists = dir.path().join("lists");
    std::fs::create_dir_all(&lists).unwrap();
    std::fs::write(
        &status,
        "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu4\n",
    )
    .unwrap();
    std::fs::write(
        lists.join("dist_main_binary-amd64_Packages"),
        "Package: bash\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu5\n\nPackage: bash\nArchitecture: i386\nVersion: 99.0\n",
    )
    .unwrap();

    let output = devguard()
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", &lists)
        .args(["--json", "health", "packages"])
        .output()
        .expect("health packages");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "health packages");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["changes_packages"], false);
    assert_eq!(value["data"]["packages"][0]["name"], "bash");
    assert_eq!(value["data"]["packages"][0]["version"], "5.2.21-2ubuntu4");
    assert_eq!(value["data"]["packages"][0]["architecture"], "amd64");
    assert_eq!(value["data"]["pending"][0]["installed"], "5.2.21-2ubuntu4");
    assert_eq!(value["data"]["pending"][0]["available"], "5.2.21-2ubuntu5");
    assert_eq!(value["data"]["pending"].as_array().unwrap().len(), 1);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn health_packages_missing_lists_are_not_clean() {
    let dir = tempdir().expect("tempdir");
    let status = dir.path().join("status");
    std::fs::write(
        &status,
        "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n",
    )
    .unwrap();
    let output = devguard()
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", dir.path().join("missing-lists"))
        .args(["--json", "health", "packages"])
        .output()
        .expect("health packages");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "health packages");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["status"], "unavailable");
    assert_eq!(value["data"]["installed"]["status"], "available");
    assert_eq!(value["data"]["updates"]["status"], "unavailable");
    assert_eq!(value["data"]["packages"][0]["name"], "bash");
    assert_eq!(value["data"]["packages"][0]["version"], "1.0");
    assert!(value["data"]["pending"].as_array().unwrap().is_empty());
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("updates")));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn health_packages_human_states_the_safety_limits() {
    let dir = tempdir().expect("tempdir");
    let status = dir.path().join("status");
    let lists = dir.path().join("lists");
    std::fs::create_dir_all(&lists).unwrap();
    std::fs::write(
        &status,
        "Package: coreutils\nStatus: install ok installed\nArchitecture: amd64\nVersion: 9.4-3\n",
    )
    .unwrap();
    std::fs::write(
        lists.join("dist_main_binary-amd64_Packages"),
        "Package: coreutils\nArchitecture: amd64\nVersion: 9.4-3\n",
    )
    .unwrap();
    let output = devguard()
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", &lists)
        .args(["health", "packages"])
        .output()
        .expect("health packages");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard health packages"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("changes packages: no"));
    assert!(stdout.contains("- coreutils 9.4-3 amd64"));
    assert!(stdout.contains("Pending updates\n  none\n"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}
