-- 0002_incidents_add_resolved_status.sql
-- Recreate `incidents` so the status CHECK constraint accepts 'resolved'.
--
-- 0001_init.sql defined the constraint as
--   CHECK (status IN ('collecting','ready','processing','analyzed','failed'))
-- which silently rejected MarkIncidentResolved()'s UPDATE to 'resolved'
-- with a CHECK-constraint violation. The correlator swallowed that error,
-- so fully-resolved incidents never logged nor notified.
--
-- The migration runner wraps each migration in BEGIN/COMMIT, so the
-- canonical 12-step ALTER TABLE (which requires PRAGMA foreign_keys=OFF
-- outside a transaction) is unavailable. Dropping `incidents` while
-- foreign_keys=ON would cascade-delete every row in `incident_alerts`
-- (its FK uses ON DELETE CASCADE).
--
-- Workaround: drop the child table first so no FK points into `incidents`
-- when it is dropped (the implicit DELETE on DROP then has no rows to
-- cascade to). Both tables are recreated inside the same transaction and
-- their data is preserved via a no-FK temp table.

-- 1. Snapshot incident_alerts into a constraint-free table.
CREATE TABLE incident_alerts_backup_0002 (
    incident_id TEXT NOT NULL,
    alert_id    TEXT NOT NULL,
    role        TEXT,
    created_at  TEXT NOT NULL
);
INSERT INTO incident_alerts_backup_0002 (incident_id, alert_id, role, created_at)
    SELECT incident_id, alert_id, role, created_at FROM incident_alerts;

-- 2. Drop the child first. No FK now references `incidents`, so dropping
--    `incidents` next will not trigger ON DELETE CASCADE.
DROP TABLE incident_alerts;

-- 3. Build the new `incidents` shape with 'resolved' added.
CREATE TABLE incidents_new_0002 (
    id              TEXT    NOT NULL PRIMARY KEY,
    group_key       TEXT    NOT NULL,
    status          TEXT    NOT NULL CHECK (status IN ('collecting','ready','processing','analyzed','failed','resolved')),
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

INSERT INTO incidents_new_0002
    SELECT id, group_key, status, first_alert_at, last_alert_at, ready_at,
           alert_count, summary, root_cause, confidence, output_json,
           created_at, updated_at
    FROM incidents;

DROP TABLE incidents;
ALTER TABLE incidents_new_0002 RENAME TO incidents;

CREATE INDEX incidents_status_idx           ON incidents(status);
CREATE INDEX incidents_group_key_status_idx ON incidents(group_key, status);
CREATE INDEX incidents_ready_at_idx         ON incidents(ready_at);

-- 4. Restore the child table with its FKs pointing at the recreated parent.
CREATE TABLE incident_alerts (
    incident_id TEXT NOT NULL,
    alert_id    TEXT NOT NULL,
    role        TEXT,
    created_at  TEXT NOT NULL,
    PRIMARY KEY (incident_id, alert_id),
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE,
    FOREIGN KEY (alert_id)    REFERENCES alerts(id)    ON DELETE CASCADE
) STRICT;

INSERT INTO incident_alerts (incident_id, alert_id, role, created_at)
    SELECT incident_id, alert_id, role, created_at
    FROM incident_alerts_backup_0002;

DROP TABLE incident_alerts_backup_0002;

CREATE INDEX incident_alerts_alert_id_idx ON incident_alerts(alert_id);
