//! XDG config and state paths for DevGuard.

use directories::{BaseDirs, ProjectDirs};
use std::path::PathBuf;

use crate::error::{DevGuardError, Result};

/// Resolved filesystem locations used by DevGuard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevGuardPaths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub state_dir: PathBuf,
    pub database_file: PathBuf,
}

impl DevGuardPaths {
    /// Resolve default XDG locations (`~/.config/devguard`, `~/.local/state/devguard`).
    pub fn default_locations() -> Result<Self> {
        let project = ProjectDirs::from("dev", "DevGuard", "devguard").ok_or_else(|| {
            DevGuardError::Message("unable to resolve XDG project directories".into())
        })?;

        // Prefer explicit state dir under XDG; fall back to data_local when needed.
        let state_dir = BaseDirs::new()
            .map(|base| base.home_dir().join(".local/state/devguard"))
            .unwrap_or_else(|| project.data_local_dir().to_path_buf());

        let config_dir = project.config_dir().to_path_buf();
        Ok(Self {
            config_file: config_dir.join("config.toml"),
            config_dir,
            database_file: state_dir.join("devguard.db"),
            state_dir,
        })
    }

    /// Override only the config file path (CLI `--config`).
    pub fn with_config_file(mut self, config_file: PathBuf) -> Self {
        if let Some(parent) = config_file.parent() {
            self.config_dir = parent.to_path_buf();
        }
        self.config_file = config_file;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_paths_include_config_and_state() {
        let paths = DevGuardPaths::default_locations().expect("paths");
        assert!(paths.config_file.ends_with("config.toml"));
        assert!(paths
            .config_dir
            .components()
            .any(|c| c.as_os_str() == "devguard"));
        assert!(
            paths.state_dir.ends_with("devguard")
                || paths.state_dir.to_string_lossy().contains("devguard")
        );
        assert!(paths.database_file.ends_with("devguard.db"));
    }
}
