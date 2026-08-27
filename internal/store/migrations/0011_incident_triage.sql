-- 0011_incident_triage.sql
-- Durable per-Incident triage dispatch lifecycle (issue 60 / ADR-0044, ADR-0045).
--
-- Replaces the in-memory retry map: phase, attempt count, next-due time, the
-- attempt's start time, and a bounded last-error classification now survive a
-- restart. The `incidents.status` CHECK already admits 'processing'; this
-- table is what finally puts it to use as a real in-flight lease.

CREATE TABLE incident_triage (
    incident_id       TEXT    NOT NULL PRIMARY KEY,
    phase             TEXT    NOT NULL CHECK (phase IN ('pending','in_flight','backoff','skipped','exhausted')),
    -- 5 = len(triageRetryDelays)+1 in internal/correlator/triage_retry.go —
    -- keep both in sync if the retry schedule ever changes attempt count.
    attempts          INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0 AND attempts <= 5),
    next_at           TEXT,
    started_at        TEXT,
    last_error_code   TEXT,
    last_error_detail TEXT,
    updated_at        TEXT    NOT NULL,
    FOREIGN KEY (incident_id) REFERENCES incidents(id) ON DELETE CASCADE
) STRICT;

CREATE INDEX incident_triage_phase_next_idx ON incident_triage(phase, next_at);
