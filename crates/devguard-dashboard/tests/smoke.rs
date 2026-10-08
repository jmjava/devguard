//! `--smoke` must print the snapshot and exit without a display.

use assert_cmd::assert::OutputAssertExt;
use assert_cmd::cargo::CommandCargoExt;
use predicates::prelude::*;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn smoke_prints_snapshot_without_a_display() {
    let home = tempdir().expect("temp home");
    let mut command = Command::cargo_bin("devguard-dashboard").expect("binary");
    command
        .arg("--smoke")
        .env("HOME", home.path())
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    command
        .assert()
        .success()
        .stdout(predicate::str::contains("DevGuard dashboard"))
        .stdout(predicate::str::contains("DevGuard doctor"))
        .stdout(predicate::str::contains("DevGuard status"))
        .stdout(predicate::str::contains("recorded scans: 0"));
}
