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
        .stdout(predicate::str::contains("dev"))
        .stdout(predicate::str::contains("security"))
        .stdout(predicate::str::contains("snapshot"))
        .stdout(predicate::str::contains("schedule"));
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

fn write_empty_dev_config(dir: &std::path::Path, roots: &[&str]) -> std::path::PathBuf {
    let config = dir.join("config.toml");
    let listed = roots
        .iter()
        .map(|root| format!("{root:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        &config,
        format!("schema_version = 1\n\n[dev]\nrepo_roots = [{listed}]\n"),
    )
    .expect("config");
    config
}

fn git_in(dir: &std::path::Path, args: &[&str]) {
    let text = dir.to_string_lossy();
    assert!(
        !text.starts_with("/home/ubuntu"),
        "test path must stay off the home directory: {text}"
    );
    let output = Command::new("git")
        .current_dir(dir)
        .args([
            "-c",
            "user.name=DevGuard",
            "-c",
            "user.email=devguard@example.com",
        ])
        .args(args)
        .env("GIT_AUTHOR_NAME", "DevGuard")
        .env("GIT_AUTHOR_EMAIL", "devguard@example.com")
        .env("GIT_COMMITTER_NAME", "DevGuard")
        .env("GIT_COMMITTER_EMAIL", "devguard@example.com")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .expect("git");
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_temp_repo(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).expect("repo dir");
    git_in(dir, &["init", "-b", "main"]);
    std::fs::write(dir.join("README"), "hello\n").expect("readme");
    git_in(dir, &["add", "README"]);
    git_in(dir, &["commit", "-m", "init"]);
}

#[test]
fn dev_repos_scan_help_documents_unavailable_without_network() {
    devguard()
        .args(["dev", "repos", "scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("repo_roots"))
        .stdout(predicate::str::contains("fetch"))
        .stdout(predicate::str::contains("push"))
        .stdout(predicate::str::contains("network"))
        .stdout(predicate::str::contains("sudo"));
}

#[test]
fn dev_repos_scan_with_no_path_is_unavailable() {
    let dir = tempdir().expect("tempdir");
    let config = write_empty_dev_config(dir.path(), &[]);
    let output = devguard()
        .args([
            "--config",
            config.to_str().expect("utf8"),
            "--json",
            "dev",
            "repos",
            "scan",
        ])
        .output()
        .expect("dev repos scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("/home/ubuntu"), "{stdout}");
    assert_eq!(output.status.code(), Some(3), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "dev repos scan");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["status"], "unavailable");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["uses_network"], false);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["fetches"], false);
    assert_eq!(value["data"]["pulls"], false);
    assert_eq!(value["data"]["pushes"], false);
    assert!(value["data"]["repos"].as_array().unwrap().is_empty());
    assert!(value["data"]["detail"]
        .as_str()
        .unwrap_or("")
        .contains("opt-in"));
}

#[test]
fn dev_repos_scan_json_reads_a_temp_work_tree() {
    let dir = tempdir().expect("tempdir");
    let config = write_empty_dev_config(dir.path(), &[]);
    let repo = dir.path().join("repo");
    init_temp_repo(&repo);
    std::fs::write(repo.join("README"), "changed\n").expect("edit");
    std::fs::write(repo.join("extra.txt"), "new\n").expect("untracked");
    let output = devguard()
        .args([
            "--config",
            config.to_str().expect("utf8"),
            "--json",
            "dev",
            "repos",
            "scan",
            repo.to_str().expect("utf8"),
        ])
        .output()
        .expect("dev repos scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "dev repos scan");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["status"], "available");
    assert_eq!(value["data"]["uses_network"], false);
    assert_eq!(value["data"]["uses_sudo"], false);
    let repos = value["data"]["repos"].as_array().expect("repos");
    assert_eq!(repos.len(), 1);
    assert_eq!(repos[0]["branch"], "main");
    assert_eq!(repos[0]["dirty"], true);
    assert_eq!(repos[0]["untracked"], true);
    assert!(repos[0].get("upstream").is_none());
    assert!(repos[0].get("unpublished").is_none());
    let human = devguard()
        .args([
            "--config",
            config.to_str().expect("utf8"),
            "dev",
            "repos",
            "scan",
            repo.to_str().expect("utf8"),
        ])
        .output()
        .expect("human");
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("DevGuard dev repos"));
    assert!(text.contains("branch main"));
    assert!(text.contains("dirty yes"));
    assert!(text.contains("untracked yes"));
    assert!(text.contains("uses network: no"));
    assert!(text.contains("uses sudo: no"));
    assert!(!text.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn dev_repos_scan_uses_config_roots_when_no_path_is_passed() {
    let dir = tempdir().expect("tempdir");
    let scan_root = dir.path().join("scan");
    let repo = scan_root.join("from-config");
    init_temp_repo(&repo);
    let config = write_empty_dev_config(dir.path(), &[scan_root.to_str().expect("utf8")]);
    let output = devguard()
        .args([
            "--config",
            config.to_str().expect("utf8"),
            "--json",
            "dev",
            "repos",
            "scan",
        ])
        .output()
        .expect("dev repos scan");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("/home/ubuntu"), "{stdout}");
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    let repos = value["data"]["repos"].as_array().expect("repos");
    assert_eq!(repos.len(), 1);
    assert!(repos[0]["path"]
        .as_str()
        .unwrap_or("")
        .ends_with("from-config"));
    assert_eq!(repos[0]["status"], "available");
}

#[test]
fn dev_repos_scan_missing_git_or_unreadable_path_is_not_clean() {
    let dir = tempdir().expect("tempdir");
    let config = write_empty_dev_config(dir.path(), &[]);
    let repo = dir.path().join("repo");
    init_temp_repo(&repo);
    let missing_git = devguard()
        .env("DEVGUARD_GIT_BIN", "/no/such/devguard-git")
        .args([
            "--config",
            config.to_str().expect("utf8"),
            "--json",
            "dev",
            "repos",
            "scan",
            repo.to_str().expect("utf8"),
        ])
        .output()
        .expect("missing git");
    let stdout = String::from_utf8_lossy(&missing_git.stdout);
    assert_eq!(missing_git.status.code(), Some(3), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["status"], "unavailable");
    assert!(value["data"]["repos"].as_array().unwrap().is_empty());

    let missing = dir.path().join("missing");
    let unreadable = devguard()
        .args([
            "--config",
            config.to_str().expect("utf8"),
            "--json",
            "dev",
            "repos",
            "scan",
            missing.to_str().expect("utf8"),
        ])
        .output()
        .expect("unreadable");
    let stdout = String::from_utf8_lossy(&unreadable.stdout);
    assert_eq!(unreadable.status.code(), Some(3), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["status"], "unavailable");
    assert!(value["data"]["repos"].as_array().unwrap().is_empty());
    assert_eq!(value["data"]["roots"][0]["status"], "unavailable");
}

fn write_audit_tool(dir: &std::path::Path, name: &str) {
    let path = dir.join(name);
    std::fs::write(
        &path,
        "#!/bin/sh\n: > ran-marker\nprintf '%s\\n' 'token=ghp_SuperSecretTokenValue ghp_BareTokenValue99'\n",
    )
    .expect("fixture");
    let mut perms = std::fs::metadata(&path).expect("meta").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).expect("chmod");
}

fn fill_audit_tools(dir: &std::path::Path) {
    for name in ["cargo-audit", "pip-audit", "npm", "mvn"] {
        write_audit_tool(dir, name);
    }
}

fn assert_token_hidden(text: &str) {
    assert!(!text.contains("SuperSecret"), "{text}");
    assert!(!text.contains("BareToken"), "{text}");
    assert!(!text.contains("ghp_"), "{text}");
}

#[test]
fn dev_deps_audit_help_documents_online_and_unavailable() {
    devguard()
        .args(["dev", "deps", "audit", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("online"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("network"))
        .stdout(predicate::str::contains("manifest"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("install"));
}

#[test]
fn dev_deps_audit_without_online_does_not_run_tools_or_print_a_manifest() {
    let dir = tempdir().expect("tempdir");
    fill_audit_tools(dir.path());
    let secret = "token=ghp_SuperSecretTokenValue";
    std::fs::write(dir.path().join("package.json"), secret).expect("manifest");
    std::fs::write(dir.path().join("Cargo.toml"), secret).expect("manifest");
    let output = devguard()
        .current_dir(dir.path())
        .env("PATH", dir.path())
        .args(["--json", "dev", "deps", "audit"])
        .output()
        .expect("dev deps audit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert_token_hidden(&stdout);
    assert_token_hidden(&stderr);
    assert!(!dir.path().join("ran-marker").exists());
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "dev deps audit");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["online"], false);
    assert_eq!(value["data"]["uses_network"], false);
    assert_eq!(value["data"]["transmits_manifest"], false);
    assert_eq!(value["data"]["installs_tools"], false);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["network_audit"], "not_requested");
    let adapters = value["data"]["adapters"].as_array().expect("adapters");
    assert_eq!(adapters.len(), 4);
    for adapter in adapters {
        assert_eq!(adapter["status"], "available");
        assert_eq!(adapter["detail"], "network audit was not requested");
        assert!(adapter.get("summary").is_none());
    }
}

#[test]
fn dev_deps_audit_missing_tool_is_not_clean() {
    let dir = tempdir().expect("tempdir");
    write_audit_tool(dir.path(), "npm");
    let output = devguard()
        .current_dir(dir.path())
        .env("PATH", dir.path())
        .args(["--json", "dev", "deps", "audit"])
        .output()
        .expect("dev deps audit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status.code(), Some(3), "{stdout}");
    assert!(!dir.path().join("ran-marker").exists());
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "dev deps audit");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["network_audit"], "not_requested");
    assert_eq!(value["data"]["uses_network"], false);
    assert_eq!(value["data"]["transmits_manifest"], false);
    let cargo = value["data"]["adapters"]
        .as_array()
        .expect("adapters")
        .iter()
        .find(|adapter| adapter["name"] == "cargo-audit")
        .expect("cargo-audit");
    assert_eq!(cargo["status"], "unavailable");
    assert!(cargo.get("summary").is_none());
    let human = devguard()
        .env("PATH", dir.path())
        .args(["dev", "deps", "audit"])
        .output()
        .expect("human");
    let text = String::from_utf8_lossy(&human.stdout);
    assert_eq!(human.status.code(), Some(3), "{text}");
    assert!(text.contains("DevGuard dev deps"));
    assert!(text.contains("clean: no"));
    assert!(text.contains("network audit: not requested"));
    assert!(text.contains("uses network: no"));
    assert!(text.contains("`cargo-audit` is not on PATH"));
    assert_token_hidden(&text);
}

#[test]
fn dev_deps_audit_online_redacts_fixture_output() {
    let dir = tempdir().expect("tempdir");
    fill_audit_tools(dir.path());
    std::fs::write(
        dir.path().join("package.json"),
        "token=ghp_SuperSecretTokenValue",
    )
    .expect("manifest");
    let output = devguard()
        .current_dir(dir.path())
        .env("PATH", dir.path())
        .args(["--json", "dev", "deps", "audit", "--online"])
        .output()
        .expect("dev deps audit");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(dir.path().join("ran-marker").exists());
    assert_token_hidden(&stdout);
    assert_token_hidden(&stderr);
    assert!(stdout.contains("[REDACTED]"));
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "dev deps audit");
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["online"], true);
    assert_eq!(value["data"]["uses_network"], true);
    assert_eq!(value["data"]["transmits_manifest"], true);
    assert_eq!(value["data"]["network_audit"], "ran");
    let adapters = value["data"]["adapters"].as_array().expect("adapters");
    assert!(adapters
        .iter()
        .all(|adapter| adapter["status"] == "available"));
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
fn security_paths_help_documents_the_allowlist() {
    devguard()
        .args(["security", "paths", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sensitive_path_allowlist"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("recurse"))
        .stdout(predicate::str::contains("contents"));
}

#[test]
fn security_paths_json_reports_mode_and_omits_token_text() {
    let dir = tempdir().unwrap();
    let plain = dir.path().join("plain.toml");
    let token = "token=ghp_SuperSecretTokenValue";
    std::fs::write(&plain, token.as_bytes()).unwrap();
    let mut perms = std::fs::metadata(&plain).unwrap().permissions();
    perms.set_mode(0o640);
    std::fs::set_permissions(&plain, perms).unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "schema_version = 1\n\n[security]\nsensitive_path_allowlist = [{plain:?}]\n",
            plain = plain.display().to_string(),
        ),
    )
    .unwrap();

    let output = devguard()
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "security",
            "paths",
        ])
        .output()
        .expect("security paths");
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(token), "{stdout}");
    assert!(!stdout.contains("SuperSecret"), "{stdout}");
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "security paths");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["reads_contents"], false);
    assert_eq!(value["data"]["prints_contents"], false);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["recursive"], false);
    let paths = value["data"]["paths"].as_array().expect("paths");
    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0]["status"], "available");
    assert_eq!(paths[0]["path"], plain.display().to_string());
    assert_eq!(paths[0]["mode"], "0640");
    assert!(paths[0]["owner"].as_str().is_some());
    assert!(value["data"].get("contents").is_none());
}

#[test]
fn security_paths_missing_path_is_unavailable_and_not_clean() {
    let dir = tempdir().unwrap();
    let secret = dir.path().join("secret.env");
    let missing = dir.path().join("absent.toml");
    let token = "token=ghp_SuperSecretTokenValue";
    std::fs::write(&secret, token.as_bytes()).unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        format!(
            "schema_version = 1\n\n[security]\nsensitive_path_allowlist = [{secret:?}, {missing:?}]\n",
            secret = secret.display().to_string(),
            missing = missing.display().to_string(),
        ),
    )
    .unwrap();

    let output = devguard()
        .args(["--config", config.to_str().unwrap(), "security", "paths"])
        .output()
        .expect("security paths");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard security paths"));
    assert!(stdout.contains("unavailable (missing)"));
    assert!(stdout.contains("clean: no"));
    assert!(stdout.contains("mode="));
    assert!(!stdout.contains(token), "{stdout}");
    assert!(!stdout.contains("SuperSecret"), "{stdout}");
}

#[test]
fn security_paths_empty_allowlist_is_not_a_clean_disk_scan() {
    let dir = tempdir().unwrap();
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "schema_version = 1\n").unwrap();
    let output = devguard()
        .args(["--config", config.to_str().unwrap(), "security", "paths"])
        .output()
        .expect("security paths");
    assert_eq!(output.status.code(), Some(3), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("No paths were configured."));
    assert!(stdout.contains("clean: no"));
    assert!(stdout.contains("recursive scan: no"));
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
fn security_ssh_auth_help_documents_unavailable_sources() {
    devguard()
        .args(["security", "ssh-auth", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("sshd"))
        .stdout(predicate::str::contains("credentials"))
        .stdout(predicate::str::contains("journal"));
}

#[test]
fn security_ssh_auth_json_parses_fixtures_without_the_host_journal() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../devguard-core/fixtures");
    let output = devguard()
        .env("DEVGUARD_LAST_FILE", fixtures.join("last.txt"))
        .env("DEVGUARD_JOURNAL_FILE", fixtures.join("journal-ssh.txt"))
        .env("DEVGUARD_AUTH_LOG", fixtures.join("auth-ssh.log"))
        .env_remove("DEVGUARD_LAST_BIN")
        .env_remove("DEVGUARD_JOURNALCTL_BIN")
        .args(["--json", "security", "ssh-auth"])
        .output()
        .expect("security ssh-auth");
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lower = stdout.to_ascii_lowercase();
    for needle in [
        "alice",
        "hunter2",
        "sudo-secret",
        "begin openssh",
        "private key",
        "sha256:",
        "password",
    ] {
        assert!(!lower.contains(needle), "{needle} leaked in {stdout}");
    }
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "security ssh-auth");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["starts_sshd"], false);
    assert_eq!(value["data"]["stops_sshd"], false);
    assert_eq!(value["data"]["changes_sshd_config"], false);
    assert_eq!(value["data"]["copies_credentials"], false);
    assert_eq!(value["data"]["copies_journal"], false);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["last"]["status"], "available");
    assert_eq!(value["data"]["journal"]["status"], "available");
    assert_eq!(value["data"]["auth_log"]["status"], "available");
    assert_eq!(value["data"]["login_count"], 5);
    assert_eq!(value["data"]["failure_count"], 5);
    assert_eq!(value["data"]["logins"][0]["source_address"], "203.0.113.10");
    assert_eq!(value["data"]["logins"][4]["source_address"], "2001:db8::10");
    assert!(value["data"]["logins"][2]["source_address"].is_null());
    assert!(value["warnings"].is_null() || value["warnings"].as_array().unwrap().is_empty());
}

#[test]
fn security_ssh_auth_missing_sources_are_partial() {
    let output = devguard()
        .env("DEVGUARD_LAST_BIN", "/no/such/devguard-last")
        .env("DEVGUARD_JOURNAL_FILE", "/no/such/devguard-journal")
        .env("DEVGUARD_AUTH_LOG", "/no/such/devguard-auth.log")
        .env_remove("DEVGUARD_LAST_FILE")
        .env_remove("DEVGUARD_JOURNALCTL_BIN")
        .args(["--json", "security", "ssh-auth"])
        .output()
        .expect("security ssh-auth");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "security ssh-auth");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["last"]["status"], "unavailable");
    assert_eq!(value["data"]["journal"]["status"], "unavailable");
    assert_eq!(value["data"]["auth_log"]["status"], "unavailable");
    assert_eq!(value["data"]["login_count"], 0);
    assert_eq!(value["data"]["failure_count"], 0);
    assert!(value["data"]["logins"].as_array().unwrap().is_empty());
    assert!(value["data"]["failures"].as_array().unwrap().is_empty());
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["starts_sshd"], false);
    assert_eq!(value["data"]["stops_sshd"], false);
}

#[test]
fn security_ssh_auth_human_states_the_safety_limits() {
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../devguard-core/fixtures");
    let output = devguard()
        .env("DEVGUARD_LAST_FILE", fixtures.join("last.txt"))
        .env("DEVGUARD_JOURNAL_FILE", fixtures.join("journal-ssh.txt"))
        .env("DEVGUARD_AUTH_LOG", fixtures.join("auth-ssh.log"))
        .env_remove("DEVGUARD_LAST_BIN")
        .env_remove("DEVGUARD_JOURNALCTL_BIN")
        .args(["security", "ssh-auth"])
        .output()
        .expect("security ssh-auth");
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard security ssh-auth"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("starts sshd: no"));
    assert!(stdout.contains("stops sshd: no"));
    assert!(stdout.contains("changes sshd config: no"));
    assert!(stdout.contains("copies credentials: no"));
    assert!(stdout.contains("copies journal payloads: no"));
    assert!(stdout.contains("clean: yes"));
    assert!(stdout.contains("203.0.113.10"));
    assert!(!stdout.to_ascii_lowercase().contains("hunter2"));
    assert!(!stdout.to_ascii_lowercase().contains("password"));
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

fn firewall_fixtures() -> (PathBuf, PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../devguard-core/fixtures");
    (
        root.join("ufw-status-verbose.txt"),
        root.join("nft-ruleset.txt"),
        root.join("sshd/sshd_config"),
    )
}

#[test]
fn security_firewall_help_documents_a_read_only_check() {
    devguard()
        .args(["security", "firewall", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("ufw enable"))
        .stdout(predicate::str::contains("ufw disable"))
        .stdout(predicate::str::contains("nftables"));
}

#[test]
fn security_firewall_json_parses_fixtures_without_running_binaries() {
    let dir = tempdir().expect("tempdir");
    let marker = dir.path().join("firewall-touched");
    let script = dir.path().join("must-not-run");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\nexit 99\n", marker.display()),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).unwrap();

    let (ufw, nft, ssh) = firewall_fixtures();
    let output = devguard()
        .env("DEVGUARD_UFW_STATUS", &ufw)
        .env("DEVGUARD_NFT_RULESET", &nft)
        .env("DEVGUARD_SSHD_CONFIG", &ssh)
        .env("DEVGUARD_UFW_BIN", &script)
        .env("DEVGUARD_NFT_BIN", &script)
        .args(["--json", "security", "firewall"])
        .output()
        .expect("security firewall");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "fixture mode ran a firewall binary");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "security firewall");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["status"], "available");
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["enables_firewall"], false);
    assert_eq!(value["data"]["disables_firewall"], false);
    assert_eq!(value["data"]["changes_nftables"], false);
    assert_eq!(value["data"]["claims_full_audit"], false);
    assert_eq!(value["data"]["ufw_status"]["state"], "active");
    assert_eq!(value["data"]["ufw_status"]["rules"][0]["to"], "22/tcp");
    assert_eq!(
        value["data"]["ufw_status"]["rules"][0]["action"],
        "ALLOW IN"
    );
    assert_eq!(value["data"]["nft_tables"][0]["family"], "inet");
    assert_eq!(
        value["data"]["nft_tables"][0]["chains"][0]["policy"],
        "drop"
    );
    assert_eq!(
        value["data"]["ssh_config"]["listen_addresses"][0],
        "127.0.0.1"
    );
    assert_eq!(value["data"]["ssh_config"]["beyond_localhost"], false);
    assert_eq!(value["data"]["ssh_config"]["password_authentication"], "no");
    assert_eq!(
        value["data"]["ssh_config"]["permit_root_login"],
        "prohibit-password"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("sk-fixture-token-do-not-print"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn security_firewall_bins_receive_only_readonly_args() {
    let dir = tempdir().expect("tempdir");
    let log = dir.path().join("argv.txt");
    let (ufw, nft, ssh) = firewall_fixtures();
    let script = dir.path().join("probe");
    let body = format!(
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{}'\nif [ \"$1\" = status ] && [ \"$2\" = verbose ] && [ \"$#\" -eq 2 ]; then\n  cat '{}'\n  exit 0\nfi\nif [ \"$1\" = list ] && [ \"$2\" = ruleset ] && [ \"$#\" -eq 2 ]; then\n  cat '{}'\n  exit 0\nfi\nprintf '%s\\n' \"refused $*\" >> '{}'\nexit 99\n",
        log.display(),
        ufw.display(),
        nft.display(),
        log.display()
    );
    std::fs::write(&script, body).unwrap();
    let mut perms = std::fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).unwrap();

    let output = devguard()
        .env_remove("DEVGUARD_UFW_STATUS")
        .env_remove("DEVGUARD_NFT_RULESET")
        .env("DEVGUARD_UFW_BIN", &script)
        .env("DEVGUARD_NFT_BIN", &script)
        .env("DEVGUARD_SSHD_CONFIG", &ssh)
        .args(["security", "firewall"])
        .output()
        .expect("security firewall");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let argv = std::fs::read_to_string(&log).unwrap();
    assert_eq!(argv, "status verbose\nlist ruleset\n");
    assert!(!argv.contains("enable"));
    assert!(!argv.contains("disable"));
    assert!(!argv.contains("flush"));
    assert!(!argv.contains("sudo"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard security firewall"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("enables firewall: no"));
    assert!(stdout.contains("disables firewall: no"));
    assert!(stdout.contains("changes nftables: no"));
    assert!(stdout.contains("clean: yes"));
    assert!(stdout.contains("beyond localhost: no"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn security_firewall_missing_ufw_is_not_clean() {
    let dir = tempdir().expect("tempdir");
    let (_ufw, nft, ssh) = firewall_fixtures();
    let output = devguard()
        .env_remove("DEVGUARD_UFW_STATUS")
        .env("DEVGUARD_UFW_BIN", dir.path().join("missing-ufw"))
        .env("DEVGUARD_NFT_RULESET", &nft)
        .env("DEVGUARD_SSHD_CONFIG", &ssh)
        .args(["--json", "security", "firewall"])
        .output()
        .expect("security firewall");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "security firewall");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["status"], "unavailable");
    assert_eq!(value["data"]["ufw"]["status"], "unavailable");
    assert_eq!(value["data"]["nftables"]["status"], "available");
    assert_eq!(value["data"]["ssh"]["status"], "available");
    assert!(value["data"]["ufw_status"].is_null());
    assert_eq!(value["data"]["enables_firewall"], false);
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("ufw unavailable")));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn security_firewall_unreadable_sshd_is_not_clean() {
    let dir = tempdir().expect("tempdir");
    let (ufw, nft, _ssh) = firewall_fixtures();
    let output = devguard()
        .env("DEVGUARD_UFW_STATUS", &ufw)
        .env("DEVGUARD_NFT_RULESET", &nft)
        .env(
            "DEVGUARD_SSHD_CONFIG",
            dir.path().join("missing-sshd_config"),
        )
        .args(["security", "firewall"])
        .output()
        .expect("security firewall");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard security firewall"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("changes nftables: no"));
    assert!(stdout.contains("clean: no"));
    assert!(stdout.contains("unreadable"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

fn home_devguard_db() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
        .join(".local/state/devguard/devguard.db")
}

fn db_stamp(path: &std::path::Path) -> Option<(u64, std::time::SystemTime)> {
    let meta = std::fs::metadata(path).ok()?;
    Some((meta.len(), meta.modified().unwrap_or(std::time::UNIX_EPOCH)))
}

#[test]
fn snapshot_help_documents_unavailable_collectors_and_ordinary_labels() {
    devguard()
        .args(["snapshot", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("create"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("diff"))
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("label"));
    devguard()
        .args(["snapshot", "diff", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Severity"))
        .stdout(predicate::str::contains("fact"));
}

#[test]
fn snapshot_create_list_diff_uses_a_temp_database() {
    let dir = tempdir().expect("tempdir");
    let config = dir.path().join("missing-config.toml");
    let home_db = home_devguard_db();
    let before = db_stamp(&home_db);

    let created = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "snapshot",
            "create",
            "--label",
            "pre-upgrade",
        ])
        .output()
        .expect("snapshot create");
    let stdout = String::from_utf8_lossy(&created.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("create json");
    assert_eq!(value["command"], "snapshot create");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["label"], "pre-upgrade");
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["installs_packages"], false);
    assert_eq!(value["data"]["opens_network"], false);
    let collectors = value["data"]["collectors"].as_array().expect("collectors");
    let names: Vec<_> = collectors
        .iter()
        .map(|row| row["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        vec!["os", "packages", "units", "ports", "gpu_id", "dev_env", "files", "health"]
    );
    let any_unavailable = collectors.iter().any(|row| row["status"] == "unavailable");
    let clean = value["data"]["clean"].as_bool().expect("clean");
    if any_unavailable {
        assert!(!clean);
    }
    assert_eq!(
        created.status.code(),
        Some(if clean { 0 } else { 3 }),
        "{stdout}"
    );
    let files = collectors
        .iter()
        .find(|row| row["name"] == "files")
        .expect("files");
    assert_eq!(files["status"], "unavailable");
    assert!(!clean);

    let db_path = dir.path().join("devguard.db");
    assert!(db_path.is_file(), "temp database was not created");
    assert_eq!(db_stamp(&home_db), before, "home devguard.db changed");

    let store = devguard_store::Store::open(&db_path).expect("open temp db");
    let id = value["data"]["id"].as_str().expect("id").to_string();
    let row = store.get_snapshot(&id).expect("get").expect("row");
    assert_eq!(row.label.as_deref(), Some("pre-upgrade"));
    let payload: serde_json::Value = serde_json::from_str(&row.payload).expect("payload");
    assert_eq!(payload["label"], "pre-upgrade");
    assert_eq!(payload["uses_sudo"], false);
    assert_eq!(payload["installs_packages"], false);
    assert_eq!(payload["opens_network"], false);
    assert_eq!(payload["collectors"]["files"]["status"], "unavailable");
    assert!(payload["collectors"]["files"]["report"].is_object());
    assert!(payload["collectors"]["os"]["report"].is_object());
    assert!(payload["collectors"]["packages"]["report"].is_object());
    assert!(payload["collectors"]["units"]["report"].is_object());
    assert!(payload["collectors"]["ports"]["report"].is_object());
    assert!(payload["collectors"]["gpu_id"]["report"].is_object());
    assert!(payload["collectors"]["dev_env"]["report"].is_object());
    assert!(payload["collectors"]["health"]["report"].is_object());
    drop(store);

    let listed = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "snapshot",
            "list",
        ])
        .output()
        .expect("snapshot list");
    assert!(listed.status.success());
    let list: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("list json");
    assert_eq!(list["command"], "snapshot list");
    assert_eq!(list["data"]["snapshots"][0]["id"], id);
    assert_eq!(list["data"]["snapshots"][0]["label"], "pre-upgrade");

    let second = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "snapshot",
            "create",
            "--label",
            "post-upgrade",
        ])
        .output()
        .expect("second create");
    let second_json: serde_json::Value =
        serde_json::from_slice(&second.stdout).expect("second json");
    let second_id = second_json["data"]["id"].as_str().expect("id");
    assert_eq!(second_json["data"]["label"], "post-upgrade");

    let diff = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "snapshot",
            "diff",
            &id,
            second_id,
        ])
        .output()
        .expect("diff");
    let diff_stdout = String::from_utf8_lossy(&diff.stdout);
    let diff_json: serde_json::Value = serde_json::from_str(&diff_stdout).expect("diff json");
    assert_eq!(diff_json["command"], "snapshot diff");
    assert_eq!(diff_json["data"]["baseline_label"], "pre-upgrade");
    assert_eq!(diff_json["data"]["current_label"], "post-upgrade");
    for bucket in ["added", "removed", "changed"] {
        let entries = diff_json["data"][bucket].as_array().expect(bucket);
        let keys: Vec<_> = entries
            .iter()
            .map(|entry| entry["key"].as_str().unwrap().to_string())
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        for entry in entries {
            let fact = entry["fact"].as_str().expect("fact");
            let severity = entry["severity"].as_str().expect("severity");
            assert!(matches!(
                severity,
                "info" | "warning" | "critical" | "unknown"
            ));
            assert_ne!(fact, severity);
            assert!(!matches!(fact, "info" | "warning" | "critical" | "unknown"));
        }
    }
    let baseline_clean = value["data"]["clean"].as_bool().unwrap();
    let current_clean = second_json["data"]["clean"].as_bool().unwrap();
    let expect = if baseline_clean && current_clean {
        0
    } else {
        3
    };
    assert_eq!(diff.status.code(), Some(expect), "{diff_stdout}");
    assert_eq!(db_stamp(&home_db), before, "home devguard.db changed");

    let missing = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "snapshot",
            "diff",
            "missing-baseline",
            "missing-current",
        ])
        .output()
        .expect("missing");
    assert_eq!(missing.status.code(), Some(1));
    assert_eq!(db_stamp(&home_db), before, "home devguard.db changed");
}

const UPGRADE_PRE: &str = include_str!("../../devguard-core/fixtures/snapshots/pre-upgrade.json");
const UPGRADE_POST: &str = include_str!("../../devguard-core/fixtures/snapshots/post-upgrade.json");
const UPGRADE_PARTIAL: &str =
    include_str!("../../devguard-core/fixtures/snapshots/partial-coverage.json");

#[test]
fn upgrade_fixtures_diff_uses_a_temp_database() {
    let dir = tempdir().expect("tempdir");
    let config = dir.path().join("missing-config.toml");
    let db_path = dir.path().join("devguard.db");
    let store = devguard_store::Store::open(&db_path).expect("open temp db");
    insert_fixture(
        &store,
        "baseline-pre",
        "2026-10-01T00:00:00.000Z",
        "pre-upgrade",
        UPGRADE_PRE,
    );
    insert_fixture(
        &store,
        "current-post",
        "2026-10-02T00:00:00.000Z",
        "post-upgrade",
        UPGRADE_POST,
    );
    insert_fixture(
        &store,
        "current-partial",
        "2026-10-03T00:00:00.000Z",
        "post-upgrade",
        UPGRADE_PARTIAL,
    );
    drop(store);

    let clean_diff = snapshot_diff(&dir, &config, "baseline-pre", "current-post");
    assert_eq!(clean_diff.status.code(), Some(0));
    let clean_json: serde_json::Value =
        serde_json::from_slice(&clean_diff.stdout).expect("clean diff json");
    assert_eq!(clean_json["command"], "snapshot diff");
    assert_eq!(clean_json["data"]["baseline_clean"], true);
    assert_eq!(clean_json["data"]["current_clean"], true);
    assert_upgrade_facts(&clean_json);
    assert!(
        clean_json.get("warnings").is_none()
            || clean_json["warnings"].as_array().unwrap().is_empty()
    );

    let partial_diff = snapshot_diff(&dir, &config, "baseline-pre", "current-partial");
    assert_eq!(partial_diff.status.code(), Some(3));
    let partial_stdout = String::from_utf8_lossy(&partial_diff.stdout);
    let partial_json: serde_json::Value =
        serde_json::from_str(&partial_stdout).expect("partial diff json");
    assert_eq!(partial_json["data"]["baseline_clean"], true);
    assert_eq!(partial_json["data"]["current_clean"], false);
    assert_upgrade_facts(&partial_json);
    let warnings = partial_json["warnings"].as_array().expect("warnings");
    assert!(warnings
        .iter()
        .any(|warning| warning == "current current-partial is partial"));
    assert!(warnings
        .iter()
        .all(|warning| warning != "current current-partial is clean"));

    let human = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "snapshot",
            "diff",
            "baseline-pre",
            "current-partial",
        ])
        .output()
        .expect("human diff");
    assert_eq!(human.status.code(), Some(3));
    let human_stdout = String::from_utf8_lossy(&human.stdout);
    assert!(human_stdout.contains("current clean: no"));
    assert!(!human_stdout.contains("current clean: yes"));
    assert!(human_stdout.contains("fact: 6.8.0-45-generic -> 7.0.0-38-generic"));
    assert!(human_stdout.contains("severity: warning"));
    assert!(!human_stdout.contains("fact: warning"));

    let listed = devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "snapshot",
            "list",
        ])
        .output()
        .expect("list");
    assert!(listed.status.success());
    let list: serde_json::Value = serde_json::from_slice(&listed.stdout).expect("list json");
    let rows = list["data"]["snapshots"].as_array().expect("rows");
    let partial = rows
        .iter()
        .find(|row| row["id"] == "current-partial")
        .expect("partial row");
    assert_eq!(partial["clean"], false);
    let post = rows
        .iter()
        .find(|row| row["id"] == "current-post")
        .expect("post row");
    assert_eq!(post["clean"], true);
}

fn insert_fixture(
    store: &devguard_store::Store,
    id: &str,
    created_at: &str,
    label: &str,
    payload: &str,
) {
    store
        .insert_snapshot(&devguard_store::Snapshot {
            id: id.into(),
            created_at: created_at.into(),
            label: Some(label.into()),
            run_id: None,
            payload: payload.into(),
        })
        .expect("insert fixture");
}

fn snapshot_diff(
    dir: &tempfile::TempDir,
    config: &std::path::Path,
    baseline: &str,
    current: &str,
) -> std::process::Output {
    devguard()
        .env("DEVGUARD_STATE_DIR", dir.path())
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "snapshot",
            "diff",
            baseline,
            current,
        ])
        .output()
        .expect("snapshot diff")
}

fn assert_upgrade_facts(value: &serde_json::Value) {
    let changed = value["data"]["changed"].as_array().expect("changed");
    let added = value["data"]["added"].as_array().expect("added");
    let kernel = fact_named(changed, "os:kernel_release");
    assert_eq!(kernel.0, "6.8.0-45-generic -> 7.0.0-38-generic");
    assert_eq!(kernel.1, "warning");
    let driver = fact_named(changed, "gpu:00000000:01:00.0:driver_version");
    assert_eq!(driver.0, "550.90.07 -> 580.95.05");
    assert_eq!(driver.1, "warning");
    let package = fact_named(changed, "package:linux-image-generic:amd64");
    assert_eq!(package.0, "6.8.0-45.45 -> 7.0.0-38.38");
    assert_eq!(package.1, "info");
    let port = fact_named(added, "port:tcp:127.0.0.1:11434");
    assert_eq!(port.0, "process=ollama");
    assert_eq!(port.1, "warning");
    for entries in [changed, added] {
        for entry in entries {
            let fact = entry["fact"].as_str().expect("fact");
            let severity = entry["severity"].as_str().expect("severity");
            assert_ne!(fact, severity);
            assert!(!matches!(fact, "info" | "warning" | "critical" | "unknown"));
        }
    }
}

fn fact_named(entries: &[serde_json::Value], key: &str) -> (String, String) {
    let entry = entries
        .iter()
        .find(|entry| entry["key"] == key)
        .unwrap_or_else(|| panic!("missing {key}"));
    (
        entry["fact"].as_str().expect("fact").to_string(),
        entry["severity"].as_str().expect("severity").to_string(),
    )
}

#[test]
fn security_updates_help_documents_read_only_sources() {
    devguard()
        .args(["security", "updates", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unavailable"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("apt install"))
        .stdout(predicate::str::contains("apt update"))
        .stdout(predicate::str::contains("full-upgrade"));
}

#[test]
fn security_updates_json_uses_notifier_or_security_lists() {
    let dir = tempdir().expect("tempdir");
    let notifier = dir.path().join("updates-available");
    let status = dir.path().join("status");
    let lists = dir.path().join("lists");
    std::fs::write(
        &notifier,
        "2 updates can be applied immediately.\n1 of these updates is a standard security update.\n",
    )
    .unwrap();
    std::fs::write(
        &status,
        "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu4\n\nPackage: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.39-0ubuntu8\n",
    )
    .unwrap();
    std::fs::create_dir_all(&lists).unwrap();
    std::fs::write(
        lists.join("archive.ubuntu.com_ubuntu_dists_resolute_main_binary-amd64_Packages"),
        "Package: libc6\nArchitecture: amd64\nVersion: 2.39-0ubuntu9\n",
    )
    .unwrap();
    std::fs::write(
        lists.join("security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages"),
        "Package: bash\nArchitecture: amd64\nVersion: 5.2.21-2ubuntu5\n",
    )
    .unwrap();

    let output = devguard()
        .env("DEVGUARD_UPDATE_NOTIFIER", &notifier)
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", &lists)
        .args(["--json", "security", "updates"])
        .output()
        .expect("security updates");
    assert_eq!(output.status.code(), Some(0));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "security updates");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["status"], "available");
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["runs_apt"], false);
    assert_eq!(value["data"]["changes_packages"], false);
    assert_eq!(value["data"]["notifier"]["standard_security_updates"], 1);
    assert_eq!(value["data"]["pending"].as_array().unwrap().len(), 1);
    assert_eq!(value["data"]["pending"][0]["name"], "bash");
    assert_eq!(value["data"]["pending"][0]["installed"], "5.2.21-2ubuntu4");
    assert_eq!(value["data"]["pending"][0]["available"], "5.2.21-2ubuntu5");
    assert_eq!(value["data"]["pending"][0]["pocket"], "standard");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("libc6"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn security_updates_missing_source_is_not_clean() {
    let dir = tempdir().expect("tempdir");
    let output = devguard()
        .env(
            "DEVGUARD_UPDATE_NOTIFIER",
            dir.path().join("missing-notifier"),
        )
        .env("DEVGUARD_DPKG_STATUS", dir.path().join("missing-status"))
        .env("DEVGUARD_APT_LISTS", dir.path().join("missing-lists"))
        .args(["--json", "security", "updates"])
        .output()
        .expect("security updates");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "security updates");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["status"], "unavailable");
    assert_eq!(value["data"]["update_notifier"]["status"], "unavailable");
    assert_eq!(value["data"]["security_lists"]["status"], "unavailable");
    assert!(value["data"]["pending"].as_array().unwrap().is_empty());
    assert!(value["data"]["notifier"].is_null());
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("security updates")));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn security_updates_human_states_the_safety_limits() {
    let dir = tempdir().expect("tempdir");
    let notifier = dir.path().join("updates-available");
    let status = dir.path().join("status");
    let lists = dir.path().join("lists");
    std::fs::write(&notifier, "0 updates can be applied immediately.\n").unwrap();
    std::fs::write(
        &status,
        "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n",
    )
    .unwrap();
    std::fs::create_dir_all(&lists).unwrap();
    std::fs::write(
        lists.join("security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages"),
        "Package: bash\nArchitecture: amd64\nVersion: 1.0\n",
    )
    .unwrap();
    let output = devguard()
        .env("DEVGUARD_UPDATE_NOTIFIER", &notifier)
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", &lists)
        .args(["security", "updates"])
        .output()
        .expect("security updates");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard security updates"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("runs apt: no"));
    assert!(stdout.contains("changes packages: no"));
    assert!(stdout.contains("clean: yes"));
    assert!(stdout.contains("Security package updates\n  none\n"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

fn write_quiet_updates(dir: &std::path::Path) -> (PathBuf, PathBuf, PathBuf) {
    let notifier = dir.join("updates-available");
    let status = dir.join("status");
    let lists = dir.join("lists");
    std::fs::write(&notifier, "0 updates can be applied immediately.\n").unwrap();
    std::fs::write(
        &status,
        "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n",
    )
    .unwrap();
    std::fs::create_dir_all(&lists).unwrap();
    std::fs::write(
        lists.join("security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages"),
        "Package: bash\nArchitecture: amd64\nVersion: 1.0\n",
    )
    .unwrap();
    (notifier, status, lists)
}

fn allowlist_config(dir: &std::path::Path, paths: &[String]) -> PathBuf {
    let config = dir.join("config.toml");
    let listed = paths
        .iter()
        .map(|path| format!("{path:?}"))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        &config,
        format!("schema_version = 1\n\n[security]\nsensitive_path_allowlist = [{listed}]\n"),
    )
    .unwrap();
    config
}

#[test]
fn security_scan_help_documents_findings_and_read_only_checks() {
    devguard()
        .args(["security", "scan", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("unknown"))
        .stdout(predicate::str::contains("severity"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("malware"))
        .stdout(predicate::str::contains("recurse"))
        .stdout(predicate::str::contains("apt"));
}

#[test]
fn security_scan_json_prints_findings_from_fixtures() {
    let dir = tempdir().expect("tempdir");
    let marker = dir.path().join("scan-touched");
    let script = dir.path().join("must-not-run");
    std::fs::write(
        &script,
        format!("#!/bin/sh\ntouch '{}'\nexit 99\n", marker.display()),
    )
    .unwrap();
    let mut perms = std::fs::metadata(&script).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&script, perms).unwrap();

    let plain = dir.path().join("plain.toml");
    let token = "token=ghp_SuperSecretTokenValue";
    std::fs::write(&plain, token.as_bytes()).unwrap();
    let mut file_perms = std::fs::metadata(&plain).unwrap().permissions();
    file_perms.set_mode(0o640);
    std::fs::set_permissions(&plain, file_perms).unwrap();
    let config = allowlist_config(dir.path(), &[plain.display().to_string()]);
    let (ufw, nft, ssh) = firewall_fixtures();
    let (notifier, status, lists) = write_quiet_updates(dir.path());

    let output = devguard()
        .env("DEVGUARD_UFW_STATUS", &ufw)
        .env("DEVGUARD_NFT_RULESET", &nft)
        .env("DEVGUARD_SSHD_CONFIG", &ssh)
        .env("DEVGUARD_UFW_BIN", &script)
        .env("DEVGUARD_NFT_BIN", &script)
        .env("DEVGUARD_UPDATE_NOTIFIER", &notifier)
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", &lists)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "security",
            "scan",
        ])
        .output()
        .expect("security scan");
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "fixture mode ran a firewall binary");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "security scan");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["reads_contents"], false);
    assert_eq!(value["data"]["prints_contents"], false);
    assert_eq!(value["data"]["recursive"], false);
    assert_eq!(value["data"]["enables_firewall"], false);
    assert_eq!(value["data"]["disables_firewall"], false);
    assert_eq!(value["data"]["changes_nftables"], false);
    assert_eq!(value["data"]["runs_apt"], false);
    assert_eq!(value["data"]["changes_packages"], false);
    assert_eq!(value["data"]["unfamiliar_name_is_malware"], false);
    let findings = value["data"]["findings"].as_array().expect("findings");
    let ufw = findings
        .iter()
        .find(|item| {
            item["fact"]
                .as_str()
                .unwrap_or("")
                .contains("ufw status is active")
        })
        .expect("ufw finding");
    assert_eq!(ufw["source"], "firewall");
    assert_eq!(ufw["severity"], "info");
    assert_ne!(ufw["fact"], ufw["severity"]);
    let nat = findings
        .iter()
        .find(|item| {
            item["fact"]
                .as_str()
                .unwrap_or("")
                .contains("nftables ip nat")
        })
        .expect("nat finding");
    assert_eq!(nat["severity"], "info");
    assert!(!nat["fact"]
        .as_str()
        .unwrap_or("")
        .to_ascii_lowercase()
        .contains("malware"));
    let path = findings
        .iter()
        .find(|item| item["source"] == "paths")
        .expect("path finding");
    assert_eq!(path["severity"], "info");
    assert!(path["fact"].as_str().unwrap_or("").contains("mode=0640"));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains(token));
    assert!(!stdout.contains("sk-fixture-token-do-not-print"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn security_scan_missing_path_is_unknown_and_not_clean() {
    let dir = tempdir().expect("tempdir");
    let missing = dir.path().join("absent.toml");
    let config = allowlist_config(dir.path(), &[missing.display().to_string()]);
    let (ufw, nft, ssh) = firewall_fixtures();
    let (notifier, status, lists) = write_quiet_updates(dir.path());
    let output = devguard()
        .env("DEVGUARD_UFW_STATUS", &ufw)
        .env("DEVGUARD_NFT_RULESET", &nft)
        .env("DEVGUARD_SSHD_CONFIG", &ssh)
        .env("DEVGUARD_UPDATE_NOTIFIER", &notifier)
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", &lists)
        .args(["--config", config.to_str().unwrap(), "security", "scan"])
        .output()
        .expect("security scan");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard security scan"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("reads file contents: no"));
    assert!(stdout.contains("recursive scan: no"));
    assert!(stdout.contains("runs apt: no"));
    assert!(stdout.contains("unfamiliar name is malware: no"));
    assert!(stdout.contains("clean: no"));
    assert!(stdout.contains("[unknown] paths:"));
    assert!(stdout.contains("unavailable (missing)"));
    assert!(!stdout.to_ascii_lowercase().contains("healthy"));
}

#[test]
fn security_scan_pending_update_exits_with_findings() {
    let dir = tempdir().expect("tempdir");
    let plain = dir.path().join("plain.toml");
    std::fs::write(&plain, b"mode-only\n").unwrap();
    let mut perms = std::fs::metadata(&plain).unwrap().permissions();
    perms.set_mode(0o640);
    std::fs::set_permissions(&plain, perms).unwrap();
    let config = allowlist_config(dir.path(), &[plain.display().to_string()]);
    let (ufw, nft, ssh) = firewall_fixtures();
    let notifier = dir.path().join("updates-available");
    let status = dir.path().join("status");
    let lists = dir.path().join("lists");
    std::fs::write(&notifier, "0 updates can be applied immediately.\n").unwrap();
    std::fs::write(
        &status,
        "Package: bash\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0\n",
    )
    .unwrap();
    std::fs::create_dir_all(&lists).unwrap();
    std::fs::write(
        lists.join("security.ubuntu.com_ubuntu_dists_resolute-security_main_binary-amd64_Packages"),
        "Package: bash\nArchitecture: amd64\nVersion: 1.1\n",
    )
    .unwrap();
    let output = devguard()
        .env("DEVGUARD_UFW_STATUS", &ufw)
        .env("DEVGUARD_NFT_RULESET", &nft)
        .env("DEVGUARD_SSHD_CONFIG", &ssh)
        .env("DEVGUARD_UPDATE_NOTIFIER", &notifier)
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", &lists)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "security",
            "scan",
        ])
        .output()
        .expect("security scan");
    assert_eq!(
        output.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["data"]["clean"], true);
    let package = value["data"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| {
            item["fact"]
                .as_str()
                .unwrap_or("")
                .contains("bash 1.0 -> 1.1")
        })
        .expect("package finding");
    assert_eq!(package["source"], "updates");
    assert_eq!(package["severity"], "warning");
    assert!(!package["fact"].as_str().unwrap_or("").contains("warning"));
}

#[test]
fn security_scan_missing_ufw_is_unknown() {
    let dir = tempdir().expect("tempdir");
    let plain = dir.path().join("plain.toml");
    std::fs::write(&plain, b"mode-only\n").unwrap();
    let config = allowlist_config(dir.path(), &[plain.display().to_string()]);
    let (_ufw, nft, ssh) = firewall_fixtures();
    let (notifier, status, lists) = write_quiet_updates(dir.path());
    let output = devguard()
        .env_remove("DEVGUARD_UFW_STATUS")
        .env("DEVGUARD_UFW_BIN", dir.path().join("missing-ufw"))
        .env("DEVGUARD_NFT_RULESET", &nft)
        .env("DEVGUARD_SSHD_CONFIG", &ssh)
        .env("DEVGUARD_UPDATE_NOTIFIER", &notifier)
        .env("DEVGUARD_DPKG_STATUS", &status)
        .env("DEVGUARD_APT_LISTS", &lists)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "security",
            "scan",
        ])
        .output()
        .expect("security scan");
    assert_eq!(output.status.code(), Some(3));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("json");
    assert_eq!(value["command"], "security scan");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["enables_firewall"], false);
    let ufw = value["data"]["findings"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["fact"].as_str().unwrap_or("").contains("ufw"))
        .expect("ufw finding");
    assert_eq!(ufw["severity"], "unknown");
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("firewall unavailable")));
}

const DAILY_UNIT: &str = "\
# devguard-scan.service
# Dry-run only. This text is not written and the timer is not enabled.
[Unit]
Description=DevGuard scheduled scan

[Service]
Type=oneshot
ExecStart=devguard health scan

# devguard-scan.timer
# Dry-run only. This text is not written and the timer is not enabled.
[Unit]
Description=DevGuard scheduled scan timer

[Timer]
OnCalendar=daily
Persistent=true
Unit=devguard-scan.service

[Install]
WantedBy=timers.target
";

fn write_marker_script(path: &std::path::Path, marker: &std::path::Path) {
    let script = format!("#!/bin/sh\nprintf ran >> '{}'\n", marker.display());
    std::fs::write(path, script).unwrap();
    let mut perms = std::fs::metadata(path).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).unwrap();
}

fn assert_no_unit_files(home: &std::path::Path, xdg_config: &std::path::Path) {
    for root in [home.join(".config"), xdg_config.to_path_buf()] {
        assert!(
            !root.join("systemd/user/devguard-scan.service").exists(),
            "service unit was written under {}",
            root.display()
        );
        assert!(
            !root.join("systemd/user/devguard-scan.timer").exists(),
            "timer unit was written under {}",
            root.display()
        );
    }
}

#[test]
fn schedule_dry_run_help_documents_the_opt_in_limit() {
    devguard()
        .args(["schedule", "dry-run", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("not requested"))
        .stdout(predicate::str::contains("sudo"))
        .stdout(predicate::str::contains("systemctl"))
        .stdout(predicate::str::contains("enable"));
}

#[test]
fn schedule_dry_run_without_opt_in_is_not_clean_and_writes_nothing() {
    let dir = tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let xdg = home.join(".config");
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&xdg).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let systemctl_marker = dir.path().join("systemctl-ran");
    let sudo_marker = dir.path().join("sudo-ran");
    write_marker_script(&bin.join("systemctl"), &systemctl_marker);
    write_marker_script(&bin.join("sudo"), &sudo_marker);
    let config = dir.path().join("config.toml");
    std::fs::write(&config, "schema_version = 1\n").unwrap();

    let output = devguard()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "schedule",
            "dry-run",
        ])
        .output()
        .expect("schedule dry-run");
    assert_eq!(output.status.code(), Some(3));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["command"], "schedule dry-run");
    assert_eq!(value["ok"], true);
    assert_eq!(value["data"]["timer"], "not_requested");
    assert_eq!(value["data"]["status"], "unavailable");
    assert_eq!(value["data"]["clean"], false);
    assert_eq!(value["data"]["writes_unit_files"], false);
    assert_eq!(value["data"]["runs_systemctl"], false);
    assert_eq!(value["data"]["enables_timer"], false);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert!(value["data"]["unit_text"].is_null());
    assert!(value["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item.as_str().unwrap_or("").contains("not requested")));
    assert!(!stdout.contains("ExecStart"));
    assert_no_unit_files(&home, &xdg);
    assert!(!systemctl_marker.exists());
    assert!(!sudo_marker.exists());
}

#[test]
fn schedule_dry_run_prints_the_unit_and_writes_nothing() {
    let dir = tempdir().expect("tempdir");
    let home = dir.path().join("home");
    let xdg = home.join(".config");
    let bin = dir.path().join("bin");
    std::fs::create_dir_all(&xdg).unwrap();
    std::fs::create_dir_all(&bin).unwrap();
    let systemctl_marker = dir.path().join("systemctl-ran");
    let sudo_marker = dir.path().join("sudo-ran");
    write_marker_script(&bin.join("systemctl"), &systemctl_marker);
    write_marker_script(&bin.join("sudo"), &sudo_marker);
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "\
schema_version = 1

[schedule]
enabled = true
on_calendar = \"daily\"

[slm]
workspace_label = \"ghp_SCHEDULEFIXTURETOKEN password=hunter2\"
",
    )
    .unwrap();

    let output = devguard()
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &xdg)
        .env("XDG_STATE_HOME", dir.path().join("state"))
        .env("PATH", &bin)
        .args([
            "--config",
            config.to_str().unwrap(),
            "--json",
            "schedule",
            "dry-run",
        ])
        .output()
        .expect("schedule dry-run");
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("json");
    assert_eq!(value["command"], "schedule dry-run");
    assert_eq!(value["data"]["timer"], "opted_in");
    assert_eq!(value["data"]["status"], "available");
    assert_eq!(value["data"]["clean"], true);
    assert_eq!(value["data"]["writes_unit_files"], false);
    assert_eq!(value["data"]["runs_systemctl"], false);
    assert_eq!(value["data"]["enables_timer"], false);
    assert_eq!(value["data"]["uses_sudo"], false);
    assert_eq!(value["data"]["unit_text"], DAILY_UNIT);
    let combined = format!("{stdout}{stderr}");
    assert!(!combined.contains("ghp_SCHEDULEFIXTURETOKEN"));
    assert!(!combined.contains("hunter2"));
    assert_no_unit_files(&home, &xdg);
    assert!(!systemctl_marker.exists());
    assert!(!sudo_marker.exists());
    assert!(!xdg.join("systemd").exists());
}

#[test]
fn schedule_dry_run_human_prints_the_unit_text() {
    let dir = tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n\n[schedule]\nenabled = true\non_calendar = \"weekly\"\n",
    )
    .unwrap();
    let output = devguard()
        .env("HOME", dir.path().join("home"))
        .env("XDG_CONFIG_HOME", dir.path().join("xdg"))
        .args(["--config", config.to_str().unwrap(), "schedule", "dry-run"])
        .output()
        .expect("schedule dry-run");
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("DevGuard schedule dry-run"));
    assert!(stdout.contains("writes unit files: no"));
    assert!(stdout.contains("runs systemctl: no"));
    assert!(stdout.contains("enables timer: no"));
    assert!(stdout.contains("uses sudo: no"));
    assert!(stdout.contains("timer: opted in"));
    assert!(stdout.contains("status: available"));
    assert!(stdout.contains("clean: yes"));
    assert!(stdout.contains("OnCalendar=weekly"));
    assert!(stdout.contains("ExecStart=devguard health scan"));
    assert!(!dir.path().join("xdg/systemd").exists());
    assert!(!dir.path().join("home/.config/systemd").exists());
}

#[test]
fn schedule_dry_run_rejects_a_secret_calendar_without_printing_it() {
    let dir = tempdir().expect("tempdir");
    let config = dir.path().join("config.toml");
    std::fs::write(
        &config,
        "schema_version = 1\n\n[schedule]\nenabled = true\non_calendar = \"daily ghp_SCHEDULEFIXTURETOKEN\"\n",
    )
    .unwrap();
    let output = devguard()
        .args(["--config", config.to_str().unwrap(), "schedule", "dry-run"])
        .output()
        .expect("schedule dry-run");
    assert_eq!(output.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let combined = format!("{stdout}{stderr}");
    assert!(!combined.contains("ghp_SCHEDULEFIXTURETOKEN"));
    assert!(stderr.contains("schedule.on_calendar"));
}
