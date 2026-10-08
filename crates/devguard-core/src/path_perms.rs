//! Allowlisted path permission checks for `devguard security paths`.
//!
//! The allowlist comes from `security.sensitive_path_allowlist`. Each entry is
//! one path: this command does not walk directories, follow symlinks, or scan
//! the disk. It reads mode bits with `lstat` and, when the local account
//! database answers without extra privileges, the owner and group names.
//! File contents are never opened or printed.
//!
//! A missing or unreadable path is unavailable, and the result is not clean.
//! An empty allowlist means no paths were configured. That is not a clean scan.

use std::ffi::CStr;
use std::fs;

use serde::{Deserialize, Serialize};

use crate::config::Config;
use crate::exit::ExitCode;

const NAME_BUF_START: usize = 4096;
const NAME_BUF_LIMIT: usize = 65_536;

/// `available` or `unavailable`. A missing or unreadable path is never clean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PathCoverage {
    Available,
    Unavailable,
}

/// One allowlisted path. Contents are not a field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathPermission {
    pub path: String,
    pub status: PathCoverage,
    /// Permission bits as four octal digits (`0640`), including setuid/setgid/sticky.
    pub mode: Option<String>,
    /// Account name from the local user database. Absent when that lookup has no name.
    pub owner: Option<String>,
    /// Group name from the local group database. Absent when that lookup has no name.
    pub group: Option<String>,
    pub detail: String,
}

/// Human and JSON body for `devguard security paths`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathPermsReport {
    /// Always false. This command does not open file bytes.
    pub reads_contents: bool,
    /// Always false. This command does not print file bytes.
    pub prints_contents: bool,
    /// Always false. Name lookup uses the local account database only.
    pub uses_sudo: bool,
    /// Always false. Directories are not walked.
    pub recursive: bool,
    /// False when the allowlist is empty or any path is missing or unreadable.
    /// A readable mode is coverage, not a judgment that the mode is tight.
    pub clean: bool,
    pub paths: Vec<PathPermission>,
}

impl PathPermsReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.paths
            .iter()
            .filter(|entry| entry.status == PathCoverage::Unavailable)
            .map(|entry| format!("{} unavailable: {}", entry.path, entry.detail))
            .collect()
    }
}

/// Check each allowlisted path. `~` is expanded. Order follows the allowlist.
pub fn scan_path_permissions(allowlist: &[String]) -> PathPermsReport {
    let paths = allowlist
        .iter()
        .map(|raw| inspect_allowlist_entry(raw))
        .collect();
    finish(paths)
}

pub fn format_path_perms_human(report: &PathPermsReport) -> String {
    let mut out = format!(
        "\
DevGuard security paths
  reads file contents: no
  prints file contents: no
  uses sudo: no
  recursive scan: no
  clean: {clean}
",
        clean = if report.clean { "yes" } else { "no" },
    );
    if report.paths.is_empty() {
        out.push_str("\nNo paths were configured.\n");
        return out;
    }
    out.push_str("\nPaths\n");
    for entry in &report.paths {
        match entry.status {
            PathCoverage::Available => {
                out.push_str(&format!(
                    "- {path} mode={mode} owner={owner} group={group} ({detail})\n",
                    path = entry.path,
                    mode = entry.mode.as_deref().unwrap_or("unavailable"),
                    owner = entry.owner.as_deref().unwrap_or("unavailable"),
                    group = entry.group.as_deref().unwrap_or("unavailable"),
                    detail = entry.detail,
                ));
            }
            PathCoverage::Unavailable => {
                out.push_str(&format!(
                    "- {} unavailable ({})\n",
                    entry.path, entry.detail
                ));
            }
        }
    }
    out
}

fn finish(paths: Vec<PathPermission>) -> PathPermsReport {
    // An empty allowlist checked nothing. Vacuous success would look like a
    // clean permission scan of the whole disk.
    let clean = !paths.is_empty()
        && paths
            .iter()
            .all(|entry| entry.status == PathCoverage::Available);
    PathPermsReport {
        reads_contents: false,
        prints_contents: false,
        uses_sudo: false,
        recursive: false,
        clean,
        paths,
    }
}

fn inspect_allowlist_entry(raw: &str) -> PathPermission {
    let raw = raw.trim();
    if raw.is_empty() {
        return unavailable(raw, "path is empty");
    }
    let expanded = match Config::expand_user_path(raw) {
        Ok(path) => path,
        Err(_) => return unavailable(raw, "unable to expand path"),
    };
    let path_text = expanded.display().to_string();
    match fs::symlink_metadata(&expanded) {
        Ok(meta) => available(&path_text, &meta),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => unavailable(path_text, "missing"),
        Err(_) => unavailable(path_text, "unreadable"),
    }
}

fn available(path: &str, meta: &fs::Metadata) -> PathPermission {
    use std::os::unix::fs::MetadataExt;
    PathPermission {
        path: path.to_string(),
        status: PathCoverage::Available,
        mode: Some(mode_octal(meta.mode())),
        owner: user_name(meta.uid()),
        group: group_name(meta.gid()),
        detail: kind_detail(meta).to_string(),
    }
}

fn kind_detail(meta: &fs::Metadata) -> &'static str {
    let file_type = meta.file_type();
    if file_type.is_symlink() {
        "symlink"
    } else if file_type.is_dir() {
        "directory"
    } else if file_type.is_file() {
        "regular file"
    } else {
        "other"
    }
}

fn mode_octal(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

fn user_name(uid: u32) -> Option<String> {
    let mut buf = vec![0u8; NAME_BUF_START];
    loop {
        let mut pwd = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: `pwd` and `result` are valid writable locations for this call.
        // `buf` is writable for `buf.len()` bytes. On success `pw_name` aliases
        // `buf`, and the name is copied before `buf` is reused or dropped.
        let rc = unsafe {
            libc::getpwuid_r(
                uid,
                pwd.as_mut_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            let next = buf.len().saturating_mul(2);
            if next > NAME_BUF_LIMIT || next <= buf.len() {
                return None;
            }
            buf.resize(next, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: a zero return and a non-null result means `getpwuid_r` wrote
        // a passwd record whose `pw_name` points into `buf`.
        let name_ptr = unsafe { (*result).pw_name };
        return copy_c_name(name_ptr);
    }
}

fn group_name(gid: u32) -> Option<String> {
    let mut buf = vec![0u8; NAME_BUF_START];
    loop {
        let mut grp = std::mem::MaybeUninit::<libc::group>::uninit();
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: `grp` and `result` are valid writable locations for this call.
        // `buf` is writable for `buf.len()` bytes. On success `gr_name` aliases
        // `buf`, and the name is copied before `buf` is reused or dropped.
        let rc = unsafe {
            libc::getgrgid_r(
                gid,
                grp.as_mut_ptr(),
                buf.as_mut_ptr().cast::<libc::c_char>(),
                buf.len(),
                &mut result,
            )
        };
        if rc == libc::ERANGE {
            let next = buf.len().saturating_mul(2);
            if next > NAME_BUF_LIMIT || next <= buf.len() {
                return None;
            }
            buf.resize(next, 0);
            continue;
        }
        if rc != 0 || result.is_null() {
            return None;
        }
        // SAFETY: a zero return and a non-null result means `getgrgid_r` wrote
        // a group record whose `gr_name` points into `buf`.
        let name_ptr = unsafe { (*result).gr_name };
        return copy_c_name(name_ptr);
    }
}

fn copy_c_name(name_ptr: *const libc::c_char) -> Option<String> {
    if name_ptr.is_null() {
        return None;
    }
    // SAFETY: the caller only passes a NUL-terminated name written into the
    // lookup buffer by getpwuid_r or getgrgid_r, and that buffer is still live.
    let name = unsafe { CStr::from_ptr(name_ptr) };
    name.to_str().ok().map(str::to_owned)
}

fn unavailable(path: impl Into<String>, detail: impl Into<String>) -> PathPermission {
    PathPermission {
        path: path.into(),
        status: PathCoverage::Unavailable,
        mode: None,
        owner: None,
        group: None,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    const TOKEN: &str = "token=ghp_SuperSecretTokenValue";

    fn restore_mode(path: &Path, mode: u32) {
        let mut perms = fs::symlink_metadata(path).expect("metadata").permissions();
        perms.set_mode(mode);
        fs::set_permissions(path, perms).expect("restore mode");
    }

    #[test]
    fn fixture_reports_mode_owner_and_group_without_token_text() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.toml");
        std::fs::write(&plain, TOKEN.as_bytes()).unwrap();
        restore_mode(&plain, 0o640);

        let report = scan_path_permissions(&[plain.display().to_string()]);
        assert!(!report.reads_contents);
        assert!(!report.prints_contents);
        assert!(!report.uses_sudo);
        assert!(!report.recursive);
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert_eq!(report.paths.len(), 1);

        let meta = fs::symlink_metadata(&plain).unwrap();
        let entry = &report.paths[0];
        assert_eq!(entry.status, PathCoverage::Available);
        assert_eq!(entry.path, plain.display().to_string());
        assert_eq!(entry.mode.as_deref(), Some("0640"));
        assert_eq!(
            entry.mode.as_deref(),
            Some(mode_octal(meta.mode()).as_str())
        );
        assert_eq!(entry.owner, user_name(meta.uid()));
        assert_eq!(entry.group, group_name(meta.gid()));
        assert_eq!(entry.detail, "regular file");
        assert!(entry.owner.is_some());

        let human = format_path_perms_human(&report);
        let json = serde_json::to_string(&report).unwrap();
        assert!(human.contains("mode=0640"));
        assert!(human.contains("regular file"));
        assert!(json.contains("0640"));
        assert!(!human.contains(TOKEN));
        assert!(!json.contains(TOKEN));
        assert!(!human.contains("SuperSecret"));
        assert!(!json.contains("SuperSecret"));
        assert!(human.contains("reads file contents: no"));
        assert!(human.contains("uses sudo: no"));
        assert!(human.contains("recursive scan: no"));
    }

    #[test]
    fn missing_path_is_unavailable_and_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.toml");
        let report = scan_path_permissions(&[missing.display().to_string()]);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.paths.len(), 1);
        assert_eq!(report.paths[0].status, PathCoverage::Unavailable);
        assert_eq!(report.paths[0].detail, "missing");
        assert!(report.paths[0].mode.is_none());
        assert!(report.paths[0].owner.is_none());
        let human = format_path_perms_human(&report);
        assert!(human.contains("unavailable (missing)"));
        assert!(human.contains("clean: no"));
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("missing")));
    }

    #[test]
    fn directory_mode_is_reported_without_listing_children() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("SuperSecretChildName");
        std::fs::write(&nested, TOKEN.as_bytes()).unwrap();
        restore_mode(dir.path(), 0o750);

        let report = scan_path_permissions(&[dir.path().display().to_string()]);
        assert!(report.clean);
        assert_eq!(report.paths[0].status, PathCoverage::Available);
        assert_eq!(report.paths[0].mode.as_deref(), Some("0750"));
        assert_eq!(report.paths[0].detail, "directory");
        let human = format_path_perms_human(&report);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!human.contains("SuperSecretChildName"));
        assert!(!json.contains("SuperSecretChildName"));
        assert!(!human.contains(TOKEN));
        assert!(!json.contains(TOKEN));
    }

    #[test]
    fn mode_without_read_permission_is_still_available() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.env");
        std::fs::write(&path, TOKEN.as_bytes()).unwrap();
        restore_mode(&path, 0o000);

        let report = scan_path_permissions(&[path.display().to_string()]);
        assert!(report.clean);
        assert_eq!(report.paths[0].status, PathCoverage::Available);
        assert_eq!(report.paths[0].mode.as_deref(), Some("0000"));
        let human = format_path_perms_human(&report);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!human.contains(TOKEN));
        assert!(!json.contains(TOKEN));
        assert!(!json.contains("SuperSecret"));

        restore_mode(&path, 0o600);
    }

    #[test]
    fn unreadable_path_is_unavailable_and_not_clean() {
        // SAFETY: geteuid takes no pointers and only reports the effective user id.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked-dir");
        std::fs::create_dir(&locked).unwrap();
        let path = locked.join("secret.env");
        std::fs::write(&path, TOKEN.as_bytes()).unwrap();
        restore_mode(&locked, 0o000);

        let report = scan_path_permissions(&[path.display().to_string()]);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.paths[0].status, PathCoverage::Unavailable);
        assert_eq!(report.paths[0].detail, "unreadable");
        assert!(report.paths[0].mode.is_none());
        let human = format_path_perms_human(&report);
        let json = serde_json::to_string(&report).unwrap();
        assert!(human.contains("unavailable (unreadable)"));
        assert!(!human.contains(TOKEN));
        assert!(!json.contains(TOKEN));

        restore_mode(&locked, 0o700);
    }

    #[test]
    fn one_missing_path_keeps_the_readable_mode() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.toml");
        std::fs::write(&plain, b"ok = true\n").unwrap();
        restore_mode(&plain, 0o600);
        let missing = dir.path().join("gone.toml");
        let report =
            scan_path_permissions(&[plain.display().to_string(), missing.display().to_string()]);
        assert!(!report.clean);
        assert_eq!(report.paths[0].status, PathCoverage::Available);
        assert_eq!(report.paths[0].mode.as_deref(), Some("0600"));
        assert_eq!(report.paths[1].detail, "missing");
    }

    #[test]
    fn empty_allowlist_reports_that_no_paths_were_configured() {
        let report = scan_path_permissions(&[]);
        assert!(!report.clean);
        assert!(report.paths.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let human = format_path_perms_human(&report);
        assert!(human.contains("No paths were configured."));
        assert!(human.contains("clean: no"));
        assert!(human.contains("recursive scan: no"));
    }

    #[test]
    fn symlink_is_not_followed_and_does_not_print_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("secret.env");
        std::fs::write(&target, TOKEN.as_bytes()).unwrap();
        restore_mode(&target, 0o600);
        let link = dir.path().join("link.env");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let report = scan_path_permissions(&[link.display().to_string()]);
        assert!(report.clean);
        assert_eq!(report.paths[0].status, PathCoverage::Available);
        assert_eq!(report.paths[0].detail, "symlink");
        assert_eq!(report.paths[0].mode.as_deref(), Some("0777"));
        assert_eq!(report.paths[0].path, link.display().to_string());
        let human = format_path_perms_human(&report);
        let json = serde_json::to_string(&report).unwrap();
        let target_path = target.display().to_string();
        assert!(!human.contains(TOKEN));
        assert!(!json.contains(TOKEN));
        assert!(!json.contains("SuperSecret"));
        assert!(!human.contains(&target_path));
        assert!(!json.contains(&target_path));
    }

    #[test]
    fn empty_path_is_unavailable() {
        let report = scan_path_permissions(&["  ".into()]);
        assert!(!report.clean);
        assert_eq!(report.paths[0].detail, "path is empty");
    }
}
