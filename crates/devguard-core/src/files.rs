//! Allowlisted config-file hashes for `devguard health files`.
//!
//! The allowlist comes from `snapshot.config_hash_allowlist`. A regular file
//! contributes its path, byte size, mtime, and a SHA-256 of the contents.
//! A missing or unreadable path is unavailable, and the result is not clean.
//! File bytes are hashed in a fixed buffer and are never stored or printed.

use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::Config;
use crate::exit::ExitCode;

const READ_CHUNK: usize = 8192;

/// `available` or `unavailable`. A missing or unreadable file is never clean.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FileCoverage {
    Available,
    Unavailable,
}

/// One allowlisted path. `hash` is SHA-256 hex. Contents are not a field.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HashedFile {
    pub path: String,
    pub status: FileCoverage,
    pub size_bytes: Option<u64>,
    pub mtime_unix: Option<i64>,
    pub hash: Option<String>,
    pub detail: String,
}

/// Human and JSON body for `devguard health files`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FilesReport {
    /// Always false. This command does not write file bytes anywhere.
    pub persists_contents: bool,
    /// Always false. This command does not print file bytes.
    pub prints_contents: bool,
    /// Content hash algorithm. Always `sha256`.
    pub hash_algorithm: String,
    /// False when any allowlisted path is missing, unreadable, or not a regular file.
    pub clean: bool,
    pub files: Vec<HashedFile>,
}

impl FilesReport {
    pub fn exit_code(&self) -> ExitCode {
        if self.clean {
            ExitCode::Success
        } else {
            ExitCode::Partial
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        self.files
            .iter()
            .filter(|file| file.status == FileCoverage::Unavailable)
            .map(|file| format!("{} unavailable: {}", file.path, file.detail))
            .collect()
    }
}

/// Hash each allowlisted path. `~` is expanded. Order follows the allowlist.
pub fn scan_config_files(allowlist: &[String]) -> FilesReport {
    let files = allowlist
        .iter()
        .map(|raw| hash_allowlist_entry(raw))
        .collect();
    finish(files)
}

pub fn format_files_human(report: &FilesReport) -> String {
    let mut out = format!(
        "\
DevGuard health files
  persists file contents: no
  prints file contents: no
  hash: {algorithm}
  clean: {clean}
",
        algorithm = report.hash_algorithm,
        clean = if report.clean { "yes" } else { "no" },
    );
    if report.files.is_empty() {
        out.push_str("\nAllowlist is empty.\n");
        return out;
    }
    out.push_str("\nFiles\n");
    for file in &report.files {
        match file.status {
            FileCoverage::Available => {
                out.push_str(&format!(
                    "- {path} size={size} mtime={mtime} sha256={hash}\n",
                    path = file.path,
                    size = file.size_bytes.unwrap_or(0),
                    mtime = file.mtime_unix.unwrap_or(0),
                    hash = file.hash.as_deref().unwrap_or(""),
                ));
            }
            FileCoverage::Unavailable => {
                out.push_str(&format!("- {} unavailable ({})\n", file.path, file.detail));
            }
        }
    }
    out
}

fn finish(files: Vec<HashedFile>) -> FilesReport {
    // An empty allowlist hashed nothing. Vacuous success would look like a
    // clean hash of every file on disk.
    let clean = !files.is_empty()
        && files
            .iter()
            .all(|file| file.status == FileCoverage::Available);
    FilesReport {
        persists_contents: false,
        prints_contents: false,
        hash_algorithm: "sha256".into(),
        clean,
        files,
    }
}

fn hash_allowlist_entry(raw: &str) -> HashedFile {
    let raw = raw.trim();
    if raw.is_empty() {
        return unavailable(raw, "path is empty");
    }
    let expanded = match Config::expand_user_path(raw) {
        Ok(path) => path,
        Err(_) => return unavailable(raw, "unable to expand path"),
    };
    let path_text = expanded.display().to_string();
    match read_regular_file(&expanded) {
        Ok(hashed) => HashedFile {
            path: path_text,
            status: FileCoverage::Available,
            size_bytes: Some(hashed.size_bytes),
            mtime_unix: Some(hashed.mtime_unix),
            hash: Some(hashed.hash),
            detail: "regular file".into(),
        },
        Err(detail) => unavailable(path_text, detail),
    }
}

struct HashedBytes {
    size_bytes: u64,
    mtime_unix: i64,
    hash: String,
}

fn read_regular_file(path: &Path) -> Result<HashedBytes, &'static str> {
    // `symlink_metadata` does not follow links, so a symlink cannot pull in
    // bytes from a path that is not itself on the allowlist.
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => return Err("not a regular file"),
        Ok(meta) if meta.is_file() => meta,
        Ok(_) => return Err("not a regular file"),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Err("missing"),
        Err(_) => return Err("unreadable"),
    };
    let mtime_unix = mtime_unix(&meta)?;
    let mut file = File::open(path).map_err(|_| "unreadable")?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; READ_CHUNK];
    loop {
        let read = match file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => {
                buf.fill(0);
                return Err("unreadable");
            }
        };
        hasher.update(&buf[..read]);
        buf[..read].fill(0);
    }
    Ok(HashedBytes {
        size_bytes: meta.len(),
        mtime_unix,
        hash: format!("{:x}", hasher.finalize()),
    })
}

fn mtime_unix(meta: &fs::Metadata) -> Result<i64, &'static str> {
    let modified = meta.modified().map_err(|_| "unreadable")?;
    let secs = modified
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "unreadable")?
        .as_secs();
    i64::try_from(secs).map_err(|_| "unreadable")
}

fn unavailable(path: impl Into<String>, detail: impl Into<String>) -> HashedFile {
    HashedFile {
        path: path.into(),
        status: FileCoverage::Unavailable,
        size_bytes: None,
        mtime_unix: None,
        hash: None,
        detail: detail.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sha256_hex(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        format!("{:x}", hasher.finalize())
    }

    fn file_mtime_unix(path: &Path) -> i64 {
        let modified = fs::metadata(path)
            .and_then(|meta| meta.modified())
            .unwrap_or(SystemTime::UNIX_EPOCH);
        modified
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_secs()).ok())
            .unwrap_or(0)
    }

    const TOKEN: &str = "token=ghp_SuperSecretTokenValue";

    #[test]
    fn fixture_reports_size_mtime_and_hash_without_token_text() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.toml");
        let secret = dir.path().join("secret.env");
        let plain_bytes = b"listen = 1\n";
        std::fs::write(&plain, plain_bytes).unwrap();
        std::fs::write(&secret, TOKEN.as_bytes()).unwrap();

        let report =
            scan_config_files(&[plain.display().to_string(), secret.display().to_string()]);
        assert!(!report.persists_contents);
        assert!(!report.prints_contents);
        assert_eq!(report.hash_algorithm, "sha256");
        assert!(report.clean);
        assert_eq!(report.exit_code(), ExitCode::Success);
        assert!(report.warnings().is_empty());
        assert_eq!(report.files.len(), 2);

        assert_eq!(report.files[0].status, FileCoverage::Available);
        assert_eq!(report.files[0].path, plain.display().to_string());
        assert_eq!(report.files[0].size_bytes, Some(plain_bytes.len() as u64));
        assert_eq!(report.files[0].mtime_unix, Some(file_mtime_unix(&plain)));
        assert_eq!(
            report.files[0].hash.as_deref(),
            Some(sha256_hex(plain_bytes).as_str())
        );

        assert_eq!(report.files[1].size_bytes, Some(TOKEN.len() as u64));
        assert_eq!(report.files[1].mtime_unix, Some(file_mtime_unix(&secret)));
        let secret_hash = sha256_hex(TOKEN.as_bytes());
        assert_eq!(report.files[1].hash.as_deref(), Some(secret_hash.as_str()));

        let human = format_files_human(&report);
        let json = serde_json::to_string(&report).unwrap();
        assert!(human.contains(&secret_hash));
        assert!(json.contains(&secret_hash));
        assert!(!human.contains(TOKEN));
        assert!(!json.contains(TOKEN));
        assert!(!human.contains("SuperSecret"));
        assert!(!json.contains("SuperSecret"));
        assert!(human.contains("persists file contents: no"));
        assert!(human.contains("prints file contents: no"));
        let names = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn missing_path_is_unavailable_and_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.toml");
        let report = scan_config_files(&[missing.display().to_string()]);
        assert!(!report.clean);
        assert_eq!(report.exit_code(), ExitCode::Partial);
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].status, FileCoverage::Unavailable);
        assert_eq!(report.files[0].detail, "missing");
        assert!(report.files[0].hash.is_none());
        assert!(report.files[0].size_bytes.is_none());
        assert!(report.files[0].mtime_unix.is_none());
        let human = format_files_human(&report);
        assert!(human.contains("unavailable (missing)"));
        assert!(human.contains("clean: no"));
        assert!(report
            .warnings()
            .iter()
            .any(|warning| warning.contains("missing")));
    }

    #[test]
    fn directory_is_unavailable_and_not_clean() {
        let dir = tempfile::tempdir().unwrap();
        let report = scan_config_files(&[dir.path().display().to_string()]);
        assert!(!report.clean);
        assert_eq!(report.files[0].status, FileCoverage::Unavailable);
        assert_eq!(report.files[0].detail, "not a regular file");
        assert!(report.files[0].hash.is_none());
    }

    #[test]
    fn unreadable_file_is_unavailable_and_not_clean() {
        // SAFETY: geteuid takes no pointers and only reports the effective user id.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.env");
        std::fs::write(&path, TOKEN.as_bytes()).unwrap();
        let mut perms = std::fs::metadata(&path).unwrap().permissions();
        perms.set_mode(0o000);
        std::fs::set_permissions(&path, perms).unwrap();

        let report = scan_config_files(&[path.display().to_string()]);
        assert!(!report.clean);
        assert_eq!(report.files[0].status, FileCoverage::Unavailable);
        assert_eq!(report.files[0].detail, "unreadable");
        assert!(report.files[0].hash.is_none());
        let human = format_files_human(&report);
        let json = serde_json::to_string(&report).unwrap();
        assert!(human.contains("unavailable (unreadable)"));
        assert!(!human.contains(TOKEN));
        assert!(!json.contains(TOKEN));
        assert!(!json.contains("SuperSecret"));

        let mut restore = std::fs::metadata(&path).unwrap().permissions();
        restore.set_mode(0o600);
        std::fs::set_permissions(&path, restore).unwrap();
    }

    #[test]
    fn one_missing_file_keeps_the_readable_hash() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.toml");
        let bytes = b"ok = true\n";
        std::fs::write(&plain, bytes).unwrap();
        let missing = dir.path().join("gone.toml");
        let report =
            scan_config_files(&[plain.display().to_string(), missing.display().to_string()]);
        assert!(!report.clean);
        assert_eq!(report.files[0].status, FileCoverage::Available);
        assert_eq!(
            report.files[0].hash.as_deref(),
            Some(sha256_hex(bytes).as_str())
        );
        assert_eq!(report.files[1].detail, "missing");
    }

    #[test]
    fn empty_allowlist_is_not_a_clean_disk_hash() {
        let report = scan_config_files(&[]);
        assert!(!report.clean);
        assert!(report.files.is_empty());
        assert_eq!(report.exit_code(), ExitCode::Partial);
        let human = format_files_human(&report);
        assert!(human.contains("Allowlist is empty."));
        assert!(human.contains("clean: no"));
    }

    #[test]
    fn symlink_is_unavailable_and_does_not_hash_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("secret.env");
        std::fs::write(&target, TOKEN.as_bytes()).unwrap();
        let link = dir.path().join("link.env");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let report = scan_config_files(&[link.display().to_string()]);
        assert!(!report.clean);
        assert_eq!(report.files[0].status, FileCoverage::Unavailable);
        assert_eq!(report.files[0].detail, "not a regular file");
        assert!(report.files[0].hash.is_none());
        assert_eq!(report.files[0].path, link.display().to_string());
        let human = format_files_human(&report);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!human.contains(TOKEN));
        assert!(!json.contains(TOKEN));
        assert!(!json.contains("SuperSecret"));
    }

    #[test]
    fn empty_path_is_unavailable() {
        let report = scan_config_files(&["  ".into()]);
        assert!(!report.clean);
        assert_eq!(report.files[0].detail, "path is empty");
    }
}
