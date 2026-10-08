//! SQLite store for DevGuard runs, observations, and snapshots.
//!
//! The database file is `devguard.db` under the DevGuard state directory
//! (`~/.local/state/devguard/` by default). [`Store::open`] creates missing
//! parent directories and applies migrations. Callers pass the rows they
//! want stored. This crate does not collect OS inventory, packages, or
//! sockets, and it does not listen on a network port.

mod error;
mod migrate;

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

pub use error::{Result, StoreError};
pub use migrate::SCHEMA_VERSION;

/// File name of the SQLite database inside the DevGuard state directory.
pub const DATABASE_FILE_NAME: &str = "devguard.db";

/// Outcome stored on a [`Run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStatus {
    Complete,
    Partial,
    Failed,
}

impl RunStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Failed => "failed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "complete" => Ok(Self::Complete),
            "partial" => Ok(Self::Partial),
            "failed" => Ok(Self::Failed),
            other => Err(StoreError::Message(format!("unknown run status {other}"))),
        }
    }
}

/// Coverage stored on an [`Observation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObservationStatus {
    Complete,
    Partial,
    Unavailable,
}

impl ObservationStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
            Self::Unavailable => "unavailable",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "complete" => Ok(Self::Complete),
            "partial" => Ok(Self::Partial),
            "unavailable" => Ok(Self::Unavailable),
            other => Err(StoreError::Message(format!(
                "unknown observation status {other}"
            ))),
        }
    }
}

/// One DevGuard run row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub id: String,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub status: RunStatus,
    pub label: Option<String>,
}

/// One collector observation attached to a run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub id: i64,
    pub run_id: String,
    pub observed_at: String,
    pub provider: String,
    pub status: ObservationStatus,
    pub payload: String,
}

/// One snapshot row. `payload` is caller-supplied text, usually JSON.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub id: String,
    pub created_at: String,
    pub label: Option<String>,
    pub run_id: Option<String>,
    pub payload: String,
}

/// Fields required to insert an observation. The store assigns `id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewObservation {
    pub run_id: String,
    pub observed_at: String,
    pub provider: String,
    pub status: ObservationStatus,
    pub payload: String,
}

/// Open SQLite database under a DevGuard state directory or an explicit path.
#[derive(Debug)]
pub struct Store {
    conn: Connection,
    path: PathBuf,
}

impl Store {
    /// Open `state_dir/devguard.db`, create the directory when needed, and migrate.
    pub fn open_state_dir(state_dir: &Path) -> Result<Self> {
        Self::open(&database_path(state_dir))
    }

    /// Open a SQLite file and apply migrations.
    ///
    /// `path` is a file. Tests pass a temporary file. A second open of the
    /// same file is a no-op migration.
    pub fn open(path: &Path) -> Result<Self> {
        if path.is_dir() {
            return Err(StoreError::Message(format!(
                "database path {} is a directory",
                path.display()
            )));
        }
        ensure_parent(path)?;
        let conn = Connection::open(path)?;
        // foreign_keys is per connection and defaults to off. It is not stored
        // in the database file, so every open enables it before writes.
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        migrate::migrate(&conn)?;
        restrict_user_only(path, false)?;
        Ok(Self {
            conn,
            path: path.to_path_buf(),
        })
    }

    /// Path of the open database file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Applied schema version (`PRAGMA user_version`).
    pub fn schema_version(&self) -> Result<i64> {
        let version = self
            .conn
            .pragma_query_value(None, "user_version", |row| row.get(0))?;
        Ok(version)
    }

    /// Application tables in the open database, in name order.
    ///
    /// SQLite internal tables such as `sqlite_sequence` are omitted.
    pub fn table_names(&self) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT name FROM sqlite_master
             WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )?;
        let rows = stmt.query_map([], |row| row.get(0))?;
        let mut names = Vec::new();
        for row in rows {
            names.push(row?);
        }
        Ok(names)
    }

    /// Insert a run. `id` must be new.
    pub fn insert_run(&self, run: &Run) -> Result<()> {
        require_token(&run.id, "run id")?;
        require_token(&run.started_at, "run started_at")?;
        if let Some(ended_at) = &run.ended_at {
            require_token(ended_at, "run ended_at")?;
        }
        let label = blank_to_none(run.label.clone());
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO runs (id, started_at, ended_at, status, label)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                run.id,
                run.started_at,
                run.ended_at,
                run.status.as_str(),
                label
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Load one run by id.
    pub fn get_run(&self, id: &str) -> Result<Option<Run>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, started_at, ended_at, status, label FROM runs WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((id, started_at, ended_at, status, label)) => Ok(Some(Run {
                id,
                started_at,
                ended_at,
                status: RunStatus::parse(&status)?,
                label,
            })),
        }
    }

    /// Insert an observation for an existing run and return its id.
    pub fn insert_observation(&self, observation: &NewObservation) -> Result<i64> {
        require_token(&observation.run_id, "observation run_id")?;
        require_token(&observation.observed_at, "observation observed_at")?;
        require_token(&observation.provider, "observation provider")?;
        require_payload(&observation.payload)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO observations (run_id, observed_at, provider, status, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                observation.run_id,
                observation.observed_at,
                observation.provider,
                observation.status.as_str(),
                observation.payload
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(id)
    }

    /// Load one observation by id.
    pub fn get_observation(&self, id: i64) -> Result<Option<Observation>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, run_id, observed_at, provider, status, payload
                 FROM observations WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((id, run_id, observed_at, provider, status, payload)) => Ok(Some(Observation {
                id,
                run_id,
                observed_at,
                provider,
                status: ObservationStatus::parse(&status)?,
                payload,
            })),
        }
    }

    /// Insert a snapshot. `id` must be new.
    pub fn insert_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        require_token(&snapshot.id, "snapshot id")?;
        require_token(&snapshot.created_at, "snapshot created_at")?;
        if let Some(run_id) = &snapshot.run_id {
            require_token(run_id, "snapshot run_id")?;
        }
        require_payload(&snapshot.payload)?;
        let label = blank_to_none(snapshot.label.clone());
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO snapshots (id, created_at, label, run_id, payload)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                snapshot.id,
                snapshot.created_at,
                label,
                snapshot.run_id,
                snapshot.payload
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Load one snapshot by id.
    pub fn get_snapshot(&self, id: &str) -> Result<Option<Snapshot>> {
        let row = self
            .conn
            .query_row(
                "SELECT id, created_at, label, run_id, payload FROM snapshots WHERE id = ?1",
                params![id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, Option<String>>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                },
            )
            .optional()?;
        match row {
            None => Ok(None),
            Some((id, created_at, label, run_id, payload)) => Ok(Some(Snapshot {
                id,
                created_at,
                label,
                run_id,
                payload,
            })),
        }
    }

    /// List snapshots in stable order: `created_at` ascending, then `id`.
    ///
    /// The order does not depend on insertion sequence when timestamps tie.
    pub fn list_snapshots(&self) -> Result<Vec<Snapshot>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, created_at, label, run_id, payload FROM snapshots
             ORDER BY created_at ASC, id ASC",
        )?;
        let rows = stmt.query_map([], snapshot_from_row)?;
        let mut snapshots = Vec::new();
        for row in rows {
            snapshots.push(row?);
        }
        Ok(snapshots)
    }
}

fn snapshot_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<Snapshot> {
    Ok(Snapshot {
        id: row.get(0)?,
        created_at: row.get(1)?,
        label: row.get(2)?,
        run_id: row.get(3)?,
        payload: row.get(4)?,
    })
}

/// `state_dir/devguard.db`.
pub fn database_path(state_dir: &Path) -> PathBuf {
    state_dir.join(DATABASE_FILE_NAME)
}

fn ensure_parent(path: &Path) -> Result<()> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    if parent.exists() {
        return Ok(());
    }
    fs::create_dir_all(parent)?;
    restrict_user_only(parent, true)?;
    Ok(())
}

fn restrict_user_only(path: &Path, dir: bool) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = if dir { 0o700 } else { 0o600 };
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (path, dir);
    }
    Ok(())
}

fn require_token(value: &str, what: &str) -> Result<()> {
    let ok = !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_whitespace);
    if ok {
        Ok(())
    } else {
        Err(StoreError::Message(format!("invalid {what}")))
    }
}

fn require_payload(payload: &str) -> Result<()> {
    if payload.is_empty() {
        Err(StoreError::Message("payload must not be empty".into()))
    } else {
        Ok(())
    }
}

fn blank_to_none(value: Option<String>) -> Option<String> {
    value.and_then(|text| {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn sample_run() -> Run {
        Run {
            id: "run-1".into(),
            started_at: "2026-10-08T00:00:00Z".into(),
            ended_at: None,
            status: RunStatus::Partial,
            label: Some("pre-upgrade".into()),
        }
    }

    #[test]
    fn open_migrates_temp_file() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let store = Store::open(file.path()).expect("open");
        assert_eq!(store.path(), file.path());
        assert_eq!(store.schema_version().expect("version"), SCHEMA_VERSION);
        assert_eq!(
            store.table_names().expect("tables"),
            vec!["observations", "runs", "snapshots"]
        );
        let mode = fs::metadata(file.path())
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);

        drop(store);
        let again = Store::open(file.path()).expect("reopen");
        assert_eq!(again.schema_version().expect("version"), SCHEMA_VERSION);
        assert_eq!(
            again.table_names().expect("tables"),
            vec!["observations", "runs", "snapshots"]
        );
    }

    #[test]
    fn open_state_dir_uses_devguard_db() {
        let dir = tempfile::tempdir().expect("temp dir");
        let state_dir = dir.path().join("state");
        let store = Store::open_state_dir(&state_dir).expect("open state");
        assert_eq!(store.path(), database_path(&state_dir));
        assert!(store.path().ends_with("devguard.db"));
        assert_eq!(
            store.table_names().expect("tables"),
            vec!["observations", "runs", "snapshots"]
        );
        let dir_mode = fs::metadata(&state_dir)
            .expect("state metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700);
    }

    #[test]
    fn round_trip_rows_survive_reopen() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let store = Store::open(file.path()).expect("open");
        let run = sample_run();
        store.insert_run(&run).expect("insert run");
        let observation_id = store
            .insert_observation(&NewObservation {
                run_id: run.id.clone(),
                observed_at: "2026-10-08T00:00:01Z".into(),
                provider: "caller".into(),
                status: ObservationStatus::Unavailable,
                payload: r#"{"note":"synthetic"}"#.into(),
            })
            .expect("insert observation");
        store
            .insert_snapshot(&Snapshot {
                id: "snap-1".into(),
                created_at: "2026-10-08T00:00:02Z".into(),
                label: Some(" pre-upgrade ".into()),
                run_id: Some(run.id.clone()),
                payload: "{}".into(),
            })
            .expect("insert snapshot");
        drop(store);

        let store = Store::open(file.path()).expect("reopen");
        let loaded = store.get_run("run-1").expect("get run").expect("row");
        assert_eq!(loaded, run);
        let observation = store
            .get_observation(observation_id)
            .expect("get observation")
            .expect("row");
        assert_eq!(observation.run_id, "run-1");
        assert_eq!(observation.status, ObservationStatus::Unavailable);
        assert_eq!(observation.payload, r#"{"note":"synthetic"}"#);
        let snapshot = store
            .get_snapshot("snap-1")
            .expect("get snapshot")
            .expect("row");
        assert_eq!(snapshot.label.as_deref(), Some("pre-upgrade"));
        assert_eq!(snapshot.payload, "{}");
        assert!(store.get_run("missing").expect("missing").is_none());
    }

    #[test]
    fn list_snapshots_is_ordered_by_created_at_then_id() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let store = Store::open(file.path()).expect("open");
        assert!(store.list_snapshots().expect("empty").is_empty());
        for (id, created_at) in [
            ("snap-b", "2026-10-08T00:00:02Z"),
            ("snap-z", "2026-10-08T00:00:01Z"),
            ("snap-a", "2026-10-08T00:00:01Z"),
        ] {
            store
                .insert_snapshot(&Snapshot {
                    id: id.into(),
                    created_at: created_at.into(),
                    label: Some("pre-upgrade".into()),
                    run_id: None,
                    payload: "{}".into(),
                })
                .expect("insert");
        }
        let ids: Vec<_> = store
            .list_snapshots()
            .expect("list")
            .into_iter()
            .map(|row| row.id)
            .collect();
        assert_eq!(ids, vec!["snap-a", "snap-z", "snap-b"]);
    }

    #[test]
    fn observation_requires_an_existing_run() {
        let file = tempfile::NamedTempFile::new().expect("temp file");
        let store = Store::open(file.path()).expect("open");
        let err = store
            .insert_observation(&NewObservation {
                run_id: "missing-run".into(),
                observed_at: "2026-10-08T00:00:01Z".into(),
                provider: "caller".into(),
                status: ObservationStatus::Complete,
                payload: "{}".into(),
            })
            .expect_err("foreign key");
        match err {
            StoreError::Sqlite(rusqlite::Error::SqliteFailure(code, _)) => {
                assert_eq!(
                    code.extended_code,
                    rusqlite::ffi::SQLITE_CONSTRAINT_FOREIGNKEY
                );
            }
            other => panic!("expected a foreign-key error, got {other}"),
        }
    }
}
