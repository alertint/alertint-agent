-- SPDX-License-Identifier: FSL-1.1-ALv2

-- Decisions can use an expired outcome or a reuse projection's metadata.
-- Pin that basis without claiming its already-expired payload is retained.
ALTER TABLE situation_observation_references ADD COLUMN metadata_only INTEGER NOT NULL DEFAULT 0
    CHECK (metadata_only IN (0, 1) AND (metadata_only = 0 OR
        (permanent = 1 AND reference_kind IN ('assessment_attempt', 'lifecycle_decision', 'transition'))));

DROP TRIGGER situation_observation_references_no_expired_target;
CREATE TRIGGER situation_observation_references_no_expired_target BEFORE INSERT ON situation_observation_references
WHEN NEW.metadata_only = 0 AND EXISTS (
    SELECT 1 FROM situation_observation_detail_expirations e WHERE e.run_id = NEW.run_id
)
BEGIN SELECT RAISE(ABORT, 'cannot reference an observation run whose detail has expired'); END;

DROP TRIGGER situation_observation_fact_payloads_guarded_delete;
CREATE TRIGGER situation_observation_fact_payloads_guarded_delete BEFORE DELETE ON situation_observation_fact_payloads
BEGIN
    SELECT RAISE(ABORT, 'observation fact payloads may only expire through the guarded retention path')
    WHERE NOT EXISTS (
        SELECT 1 FROM situation_observation_facts f
        JOIN situation_observation_detail_expirations e ON e.run_id = f.run_id
        WHERE f.id = OLD.fact_id
    ) OR EXISTS (
        SELECT 1 FROM situation_observation_facts f
        JOIN situation_observation_references r ON r.run_id = f.run_id
            AND r.superseded = 0 AND r.metadata_only = 0
        WHERE f.id = OLD.fact_id
    );
END;

-- Older decisions did not record complete basis run IDs. Conservatively keep
-- expired outcomes and reuse projections up to the last durable decision for
-- each input version. Later unused cycles can still be pruned. Future decisions
-- pin their exact bounded basis through metadata_only references above.
WITH decisions AS (
    SELECT situation_id, input_version, id AS owner_id, 'assessment_attempt' AS kind, dispatched_at AS decided_at
    FROM situation_assessment_calls
    UNION ALL
    SELECT situation_id, input_version, id, 'assessment_attempt', completed_at
    FROM situation_assessment_attempts
    UNION ALL
    SELECT situation_id, input_version, id, 'transition', created_at
    FROM situation_transitions
    UNION ALL
    SELECT c.situation_id, c.input_version, ref.owner_id, ref.reference_kind, ref.created_at
    FROM situation_observation_references ref
    JOIN situation_observation_runs r ON r.id = ref.run_id
    JOIN situation_preparation_cycles c ON c.id = r.cycle_id
    WHERE ref.permanent = 1
), ranked AS (
    SELECT *, ROW_NUMBER() OVER (
        PARTITION BY situation_id, input_version
        ORDER BY substr(decided_at,1,19) DESC, decided_at DESC, kind, owner_id) AS rank
    FROM decisions
)
INSERT OR IGNORE INTO situation_observation_references
    (id, run_id, reference_kind, owner_id, permanent, created_at, metadata_only)
SELECT 'ref:legacy:' || d.kind || ':' || d.owner_id || ':' || r.id,
    r.id, d.kind, d.owner_id, 1, d.decided_at, 1
FROM situation_observation_runs r
JOIN situation_preparation_cycles c ON c.id = r.cycle_id
JOIN ranked d ON d.situation_id = c.situation_id AND d.input_version = c.input_version AND d.rank = 1
WHERE substr(r.completed_at,1,19) <= substr(d.decided_at,1,19)
    AND (r.reused_from_run_id IS NOT NULL OR EXISTS (
        SELECT 1 FROM situation_observation_detail_expirations e WHERE e.run_id = r.id))
    AND NOT EXISTS (SELECT 1 FROM situation_observation_references ref WHERE ref.run_id = r.id AND ref.permanent = 1);

-- Retention never rewrites evidence. Old, unused cycles can be removed only
-- through a transaction-owned pruning marker; ordinary DELETE remains guarded.
CREATE TABLE situation_preparation_pruning (
    cycle_id TEXT NOT NULL PRIMARY KEY
) STRICT;

CREATE INDEX situation_observation_references_owner_idx
    ON situation_observation_references(owner_id, reference_kind, superseded);
CREATE INDEX situation_observation_runs_reuse_idx
    ON situation_observation_runs(reused_from_run_id) WHERE reused_from_run_id IS NOT NULL;
CREATE INDEX situation_observation_plans_reuse_idx
    ON situation_observation_plans(reuse_run_id) WHERE reuse_run_id IS NOT NULL;
CREATE INDEX situation_observation_refresh_cycle_idx ON situation_observation_refresh(admitted_cycle_id);
CREATE INDEX situation_observation_refresh_run_idx ON situation_observation_refresh(last_run_id);
CREATE INDEX zabbix_source_observations_run_idx ON zabbix_source_observations(run_id);
CREATE INDEX situation_preparation_cycles_retention_idx ON situation_preparation_cycles(sealed, sealed_at);
CREATE INDEX situations_preparation_cycle_idx ON situations(current_preparation_cycle_id);

-- Match the query-slot identity in loadCurrentEvidenceTx, including the exact
-- nanosecond window. Preserve the latest outcome even if it failed or expired:
-- pruning must never make an older success become the latest observation.
CREATE VIEW situation_observation_current_heads AS
WITH scoped_plans AS (
    SELECT p.*,
        (unixepoch(substr(end_at,1,19)||'Z')-unixepoch(substr(start_at,1,19)||'Z'))*1000000000
        + CASE WHEN substr(end_at,20,1)='.' THEN CAST(substr(substr(end_at,21,length(end_at)-21)||'000000000',1,9) AS INTEGER) ELSE 0 END
        - CASE WHEN substr(start_at,20,1)='.' THEN CAST(substr(substr(start_at,21,length(start_at)-21)||'000000000',1,9) AS INTEGER) ELSE 0 END AS window_ns
    FROM situation_observation_plans p
), ranked AS (
    SELECT r.id, r.cycle_id,
        ROW_NUMBER() OVER (
            PARTITION BY c.situation_id, p.capability, p.scope_json, p.parameters_json, p.window_ns, p.limit_count, p.purpose
            ORDER BY c.generation DESC, r.completed_at DESC, r.id DESC) AS rank
    FROM situation_observation_runs r
    JOIN situation_preparation_cycles c ON c.id = r.cycle_id
    JOIN scoped_plans p ON p.id = r.plan_id
    JOIN situations s ON s.id = c.situation_id
    JOIN situation_preparation_cycles current ON current.id = s.current_preparation_cycle_id
    WHERE c.input_version = s.input_version AND c.config_digest = current.config_digest
        AND c.generation <= current.generation
)
SELECT id, cycle_id FROM ranked WHERE rank = 1;

DROP TRIGGER situation_preparation_cycles_no_delete;
CREATE TRIGGER situation_preparation_cycles_no_delete BEFORE DELETE ON situation_preparation_cycles
WHEN NOT EXISTS (SELECT 1 FROM situation_preparation_pruning WHERE cycle_id = OLD.id)
BEGIN SELECT RAISE(ABORT, 'preparation cycles may only be deleted through retention'); END;

DROP TRIGGER situation_observation_plans_no_delete;
CREATE TRIGGER situation_observation_plans_no_delete BEFORE DELETE ON situation_observation_plans
WHEN NOT EXISTS (SELECT 1 FROM situation_preparation_pruning WHERE cycle_id = OLD.cycle_id)
BEGIN SELECT RAISE(ABORT, 'observation plans may only be deleted through retention'); END;

DROP TRIGGER situation_observation_runs_no_delete;
CREATE TRIGGER situation_observation_runs_no_delete BEFORE DELETE ON situation_observation_runs
WHEN NOT EXISTS (SELECT 1 FROM situation_preparation_pruning WHERE cycle_id = OLD.cycle_id)
BEGIN SELECT RAISE(ABORT, 'observation runs may only be deleted through retention'); END;

DROP TRIGGER situation_observation_requests_no_delete;
CREATE TRIGGER situation_observation_requests_no_delete BEFORE DELETE ON situation_observation_requests
WHEN NOT EXISTS (SELECT 1 FROM situation_preparation_pruning WHERE cycle_id = OLD.cycle_id)
BEGIN SELECT RAISE(ABORT, 'observation requests may only be deleted through retention'); END;

DROP TRIGGER situation_observation_request_outcomes_no_delete;
CREATE TRIGGER situation_observation_request_outcomes_no_delete BEFORE DELETE ON situation_observation_request_outcomes
WHEN NOT EXISTS (
    SELECT 1 FROM situation_observation_requests r
    JOIN situation_preparation_pruning p ON p.cycle_id = r.cycle_id WHERE r.id = OLD.reservation_id
)
BEGIN SELECT RAISE(ABORT, 'observation outcomes may only be deleted through retention'); END;

DROP TRIGGER situation_observation_facts_no_delete;
CREATE TRIGGER situation_observation_facts_no_delete BEFORE DELETE ON situation_observation_facts
WHEN NOT EXISTS (
    SELECT 1 FROM situation_observation_runs r
    JOIN situation_preparation_pruning p ON p.cycle_id = r.cycle_id WHERE r.id = OLD.run_id
)
BEGIN SELECT RAISE(ABORT, 'observation facts may only be deleted through retention'); END;

DROP TRIGGER situation_observation_detail_expirations_no_delete;
CREATE TRIGGER situation_observation_detail_expirations_no_delete BEFORE DELETE ON situation_observation_detail_expirations
WHEN NOT EXISTS (
    SELECT 1 FROM situation_observation_runs r
    JOIN situation_preparation_pruning p ON p.cycle_id = r.cycle_id WHERE r.id = OLD.run_id
)
BEGIN SELECT RAISE(ABORT, 'observation expirations may only be deleted through retention'); END;

DROP TRIGGER situation_observation_references_no_delete;
CREATE TRIGGER situation_observation_references_no_delete BEFORE DELETE ON situation_observation_references
WHEN OLD.permanent = 1 OR OLD.superseded = 0 OR NOT EXISTS (
    SELECT 1 FROM situation_preparation_pruning p WHERE p.cycle_id = OLD.owner_id
    UNION ALL
    SELECT 1 FROM situation_observation_runs r
    JOIN situation_preparation_pruning p ON p.cycle_id = r.cycle_id WHERE r.id = OLD.run_id
)
BEGIN SELECT RAISE(ABORT, 'observation references may only be deleted through retention'); END;
