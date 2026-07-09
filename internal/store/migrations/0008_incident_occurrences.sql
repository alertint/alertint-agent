-- 0008_incident_occurrences.sql
-- Incident-memory M1: the append-only occurrence ledger.
--
-- Each row records one firing *episode* that attached to an already-analyzed
-- incident (a re-fire inside the collapse horizon) instead of minting a new
-- incident + LLM call. One row per attach, 1:1 with an
-- `incident.occurrence_attached` audit row. The incident's own first firing is
-- NOT an occurrence row — it is the incident itself; occurrence rows are the
-- re-fires. "recurred xN" therefore renders as (occurrence count + 1).
--
-- The ledger is load-bearing, not bookkeeping: `alerts` keeps only the latest
-- received_at (latest-wins upsert) and `incident_alerts` skips its counter on
-- duplicates, so "how often, since when?" is unanswerable at write time without
-- this table. payload_json snapshots labels+annotations per member alert so an
-- annotation trajectory survives the latest-wins upsert.
--
-- Purely additive (like 0003/0004/0007): no drop-and-recreate. STRICT and
-- RFC3339 timestamp strings, house style.

CREATE TABLE incident_occurrences (
    id                INTEGER PRIMARY KEY,
    incident_id       TEXT    NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    occurred_at       TEXT    NOT NULL,
    last_seen         TEXT    NOT NULL,
    fingerprints_json TEXT    NOT NULL,                    -- JSON array of member fingerprints
    payload_json      TEXT    NOT NULL,                    -- labels+annotations per member alert (R2 snapshot)
    -- trigger_kind, not `trigger` (an SQL keyword). Why any re-judgment happened,
    -- or 'none' for a plain attach: none | severity | new_alertname | cadence | ceiling | cap.
    trigger_kind      TEXT    NOT NULL DEFAULT 'none',
    -- declare-ephemeral snapshot hook; ships empty (no ephemeral producer yet).
    snapshot_ref      TEXT    NOT NULL DEFAULT ''
) STRICT;

CREATE INDEX incident_occurrences_incident_idx
    ON incident_occurrences(incident_id, occurred_at);

-- last_judged_at: when the incident's finding was last produced (initial triage
-- or any re-judgment). Clock B (the max-time-since-judgment ceiling) and the
-- trigger baselines measure from it. Nullable — set only on judgment success.
ALTER TABLE incidents ADD COLUMN last_judged_at TEXT;
