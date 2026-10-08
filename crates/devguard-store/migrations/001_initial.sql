-- Schema version 1. Applied once; user_version is bumped by the store.
-- Findings and backup tables are intentionally absent.

CREATE TABLE runs (
    id TEXT PRIMARY KEY NOT NULL,
    started_at TEXT NOT NULL,
    ended_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('complete', 'partial', 'failed')),
    label TEXT
);

CREATE TABLE observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL REFERENCES runs (id),
    observed_at TEXT NOT NULL,
    provider TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('complete', 'partial', 'unavailable')),
    payload TEXT NOT NULL
);

CREATE INDEX observations_run_id_idx ON observations (run_id);

CREATE TABLE snapshots (
    id TEXT PRIMARY KEY NOT NULL,
    created_at TEXT NOT NULL,
    label TEXT,
    run_id TEXT REFERENCES runs (id),
    payload TEXT NOT NULL
);

CREATE INDEX snapshots_run_id_idx ON snapshots (run_id);
