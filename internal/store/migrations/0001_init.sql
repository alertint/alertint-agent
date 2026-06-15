-- 0001_init.sql
-- Initial schema for the AlertINT agent (v1).
--
-- All tables use STRICT mode so type mismatches surface as errors rather
-- than silent coercions. Timestamps are stored as RFC3339 strings; SQLite
-- sorts them lexicographically and they remain human-readable in dumps.
--
-- Note: schema_migrations is created by the store's migration runner
-- before any embedded file is applied, so it does not appear here.

-- Raw alerts as received from Alertmanager. Dedupe is by fingerprint
-- (latest wins): repeated POSTs for the same fingerprint update in place.
CREATE TABLE alerts (
    id               TEXT NOT NULL PRIMARY KEY,
    fingerprint      TEXT NOT NULL UNIQUE,
    status           TEXT NOT NULL CHECK (status IN ('firing','resolved')),
    labels_json      TEXT NOT NULL,
    annotations_json TEXT NOT NULL,
    starts_at        TEXT NOT NULL,
    ends_at          TEXT,
    received_at      TEXT NOT NULL
) STRICT;

CREATE INDEX alerts_received_at_idx ON alerts(received_at);
CREATE INDEX alerts_status_idx      ON alerts(status);

-- Correlation incidents. status transitions: collecting -> ready ->
-- processing -> analyzed (or failed). ready_at is the dispatch deadline
-- per Slice 05's fixed-window semantics.
CREATE TABLE incidents (
    id              TEXT    NOT NULL PRIMARY KEY,
    group_key       TEXT    NOT NULL,
    status          TEXT    NOT NULL CHECK (status IN ('collecting','ready','processing','analyzed','failed')),
    first_alert_at  TEXT    NOT NULL,
    last_alert_at   TEXT    NOT NULL,
    ready_at        TEXT    NOT NULL,
    alert_count     INTEGER NOT NULL DEFAULT 0,
    summary         TEXT,
    root_cause      TEXT,
    confidence      REAL,
    output_json     TEXT,
    created_at      TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL,
    CHECK (alert_count >= 0),
    CHECK (confidence IS NULL OR (confidence >= 0.0 AND confidence <= 1.0))
) STRICT;

CREATE INDEX incidents_status_idx           ON incidents(status);
CREATE INDEX incidents_group_key_status_idx ON incidents(group_key, status);
CREATE INDEX incidents_ready_at_idx         ON incidents(ready_at);

-- Membership: which alerts belong to which incident, plus the role the
-- analyzing skill assigned (e.g. "primary", "downstream").
CREATE TABLE incident_alerts (
    incident_id TEXT NOT NULL,
    alert_id    TEXT NOT NULL,
    role        TEXT,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (incident_id, alert_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id)    REFERENCES alerts(id)    ON DELETE CASCADE
) STRICT;

CREATE INDEX incident_alerts_alert_id_idx ON incident_alerts(alert_id);

-- Hash-chained audit log. seq is autoincrement; prev_hash references the
-- prior row's hash. The Slice 03 audit package owns Append/Verify; this
-- table just provides the storage shape.
CREATE TABLE audit_log (
    seq          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    actor        TEXT NOT NULL,
    kind         TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    prev_hash    TEXT,
    hash         TEXT NOT NULL
) STRICT;

CREATE INDEX audit_log_kind_idx ON audit_log(kind);
CREATE INDEX audit_log_ts_idx   ON audit_log(ts);
