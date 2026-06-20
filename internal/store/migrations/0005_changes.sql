-- 0005_changes.sql
-- Change events: point-in-time records of something changing in the operated
-- system (deploy/config/flag/scale/rollback), pushed in over a webhook. Unlike
-- alerts they have no firing/resolved lifecycle and are never correlated into an
-- incident of their own — they only enrich incident triage. Append-only and
-- unbounded, so the writer prunes by occurred_at (retention_days).
CREATE TABLE changes (
    id          TEXT NOT NULL PRIMARY KEY,
    source      TEXT NOT NULL,
    kind        TEXT NOT NULL,
    title       TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    version     TEXT,
    link        TEXT,
    occurred_at TEXT NOT NULL,
    received_at TEXT NOT NULL
) STRICT;

CREATE INDEX changes_occurred_at_idx ON changes(occurred_at);
