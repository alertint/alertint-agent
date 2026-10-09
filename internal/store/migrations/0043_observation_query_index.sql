-- SPDX-License-Identifier: FSL-1.1-ALv2

-- Intern exact query identities once, rather than sorting every historical
-- plan's JSON on each reconciliation. Preserve the original byte identities
-- and nanosecond windows used by the released current-evidence query.
CREATE VIEW situation_observation_query_keys AS
SELECT p.id AS plan_id, c.situation_id, c.input_version, c.config_digest,
    p.capability, p.scope_json, p.parameters_json, p.limit_count, p.purpose,
    (unixepoch(substr(p.end_at,1,19)||'Z')-unixepoch(substr(p.start_at,1,19)||'Z'))*1000000000
    + CASE WHEN substr(p.end_at,20,1)='.' THEN CAST(substr(substr(p.end_at,21,length(p.end_at)-21)||'000000000',1,9) AS INTEGER) ELSE 0 END
    - CASE WHEN substr(p.start_at,20,1)='.' THEN CAST(substr(substr(p.start_at,21,length(p.start_at)-21)||'000000000',1,9) AS INTEGER) ELSE 0 END AS window_ns
FROM situation_observation_plans p
JOIN situation_preparation_cycles c ON c.id = p.cycle_id;

CREATE TABLE situation_observation_query_slots (
    id INTEGER PRIMARY KEY,
    situation_id TEXT NOT NULL REFERENCES situations(id),
    input_version INTEGER NOT NULL,
    config_digest TEXT NOT NULL,
    capability TEXT NOT NULL,
    scope_json TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    limit_count INTEGER NOT NULL,
    purpose TEXT NOT NULL,
    window_ns INTEGER NOT NULL,
    UNIQUE (situation_id, input_version, config_digest, capability, scope_json,
        parameters_json, limit_count, purpose, window_ns)
) STRICT;

-- Retain generation-indexed pointers, not just an overwritable latest pointer:
-- pinning a historical decision must respect its original generation ceiling.
CREATE TABLE situation_observation_query_runs (
    run_id TEXT PRIMARY KEY REFERENCES situation_observation_runs(id) ON DELETE CASCADE,
    slot_id INTEGER NOT NULL REFERENCES situation_observation_query_slots(id),
    generation INTEGER NOT NULL,
    completed_at TEXT NOT NULL
) STRICT, WITHOUT ROWID;

INSERT OR IGNORE INTO situation_observation_query_slots
    (situation_id, input_version, config_digest, capability, scope_json, parameters_json, limit_count, purpose, window_ns)
SELECT k.situation_id, k.input_version, k.config_digest, k.capability, k.scope_json,
    k.parameters_json, k.limit_count, k.purpose, k.window_ns
FROM situation_observation_query_keys k
JOIN situation_observation_runs r ON r.plan_id = k.plan_id;

INSERT INTO situation_observation_query_runs (run_id, slot_id, generation, completed_at)
SELECT r.id, q.id, c.generation, r.completed_at
FROM situation_observation_runs r
JOIN situation_preparation_cycles c ON c.id = r.cycle_id
JOIN situation_observation_query_keys k ON k.plan_id = r.plan_id
JOIN situation_observation_query_slots q
    ON q.situation_id = k.situation_id AND q.input_version = k.input_version AND q.config_digest = k.config_digest
    AND q.capability = k.capability AND q.scope_json = k.scope_json AND q.parameters_json = k.parameters_json
    AND q.limit_count = k.limit_count AND q.purpose = k.purpose AND q.window_ns = k.window_ns;

CREATE INDEX situation_observation_query_runs_latest_idx
    ON situation_observation_query_runs(slot_id, generation DESC, completed_at DESC, run_id DESC);

-- Starting a new cycle transfers only live temporary protection. Superseded
-- history must not be enumerated to find these few remaining references.
CREATE INDEX situation_observation_references_live_cycle_idx
    ON situation_observation_references(run_id, owner_id)
    WHERE superseded = 0 AND reference_kind IN ('current_cycle','open_cycle');

-- Every writer maintains the derived lookup in the run's own transaction.
-- A failed commit rolls back both; retention cascades removal of its pointers.
CREATE TRIGGER situation_observation_runs_index_query AFTER INSERT ON situation_observation_runs
BEGIN
    INSERT OR IGNORE INTO situation_observation_query_slots
        (situation_id, input_version, config_digest, capability, scope_json, parameters_json, limit_count, purpose, window_ns)
    SELECT situation_id, input_version, config_digest, capability, scope_json, parameters_json, limit_count, purpose, window_ns
    FROM situation_observation_query_keys WHERE plan_id = NEW.plan_id;

    INSERT INTO situation_observation_query_runs (run_id, slot_id, generation, completed_at)
    SELECT NEW.id, q.id, c.generation, NEW.completed_at
    FROM situation_observation_query_keys k
    JOIN situation_preparation_cycles c ON c.id = NEW.cycle_id
    JOIN situation_observation_query_slots q
        ON q.situation_id = k.situation_id AND q.input_version = k.input_version AND q.config_digest = k.config_digest
        AND q.capability = k.capability AND q.scope_json = k.scope_json AND q.parameters_json = k.parameters_json
        AND q.limit_count = k.limit_count AND q.purpose = k.purpose AND q.window_ns = k.window_ns
    WHERE k.plan_id = NEW.plan_id;
END;

CREATE TRIGGER situation_observation_query_runs_remove_empty_slot AFTER DELETE ON situation_observation_query_runs
BEGIN
    DELETE FROM situation_observation_query_slots WHERE id = OLD.slot_id
        AND NOT EXISTS (SELECT 1 FROM situation_observation_query_runs WHERE slot_id = OLD.slot_id);
END;

DROP VIEW situation_observation_current_heads;
-- Keep the lookup rooted in current Situation pointers, so retention never
-- enumerates dictionaries belonging to historical input/configuration fences.
CREATE VIEW situation_observation_current_heads AS
SELECT r.id, r.cycle_id
FROM situations s
CROSS JOIN situation_preparation_cycles current ON current.id = s.current_preparation_cycle_id
CROSS JOIN situation_observation_query_slots q ON q.situation_id = s.id
    AND q.input_version = s.input_version AND q.config_digest = current.config_digest
JOIN situation_observation_runs r ON r.id = (
    SELECT h.run_id FROM situation_observation_query_runs h
    WHERE h.slot_id = q.id AND h.generation <= current.generation
    ORDER BY h.generation DESC, h.completed_at DESC, h.run_id DESC LIMIT 1
)
WHERE s.current_preparation_cycle_id IS NOT NULL;
