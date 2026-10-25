-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Issue #99: the store kept everything forever and wrote most of it again on
-- every change. This migration splits what is kept forever (the memory: each
-- Situation, its journal, its current state) from the working record that
-- now expires by age or by volume size (the detail of old Transitions, the
-- observation evidence only they cited, superseded facts, coverage nothing
-- reads), and stores less per change:
--
--   - a Transition's briefing moves to situation_transition_briefings,
--     compressed by the application; projection_json keeps every other
--     field, so the SQL that reads it (0024, 0026, 0047, ntfy) is unchanged;
--   - a fact is written only when its content changes (situation_fact_heads);
--   - deletes and the two sanctioned Transition/attempt updates happen only
--     through the retention path, authorized by a transaction-owned marker in
--     storage_retention_pruning (0042's pattern), and never for anything the
--     current state still uses (storage_protected_transitions/_attempts).
--
-- No existing row is rewritten here. Moving old briefings out, deleting
-- repeated facts and expiring old records all run later, in short pages,
-- from the application (issue #159: never hold the connection for long).

-- Transaction-owned authorization: retention inserts (kind, id), performs the
-- guarded deletes or update, and removes the marker before it commits.
CREATE TABLE storage_retention_pruning (
    kind TEXT NOT NULL CHECK (kind IN (
        'transition', 'assessment_attempt', 'lifecycle_decision', 'coverage', 'fact', 'legacy_facts'
    )),
    id   TEXT NOT NULL CHECK (id <> ''),
    PRIMARY KEY (kind, id)
) STRICT, WITHOUT ROWID;

-- Progress of the one-time backlog walks, and the legacy watermarks: rows at
-- or below them were written before this migration.
CREATE TABLE storage_retention_state (
    key   TEXT NOT NULL PRIMARY KEY CHECK (key <> ''),
    value TEXT NOT NULL
) STRICT;
INSERT INTO storage_retention_state (key, value)
    SELECT 'facts_legacy_max_rowid', CAST(coalesce(max(rowid), 0) AS TEXT) FROM situation_facts;
INSERT INTO storage_retention_state (key, value)
    SELECT 'transitions_legacy_max_rowid', CAST(coalesce(max(rowid), 0) AS TEXT) FROM situation_transitions;

-- ----------------------------------------------------------------------
-- What the current state uses, at any age. Retention selects outside these
-- views and the guarded triggers check them again.
-- ----------------------------------------------------------------------
CREATE VIEW storage_protected_transitions AS
SELECT current_transition_id AS transition_id FROM situations WHERE current_transition_id IS NOT NULL
UNION
SELECT t.id FROM situation_episode_summaries e
JOIN situation_transitions t ON t.situation_id = e.situation_id AND t.sequence = e.source_transition_sequence
UNION
SELECT transition_id FROM notification_intents
WHERE transition_id IS NOT NULL AND status IN ('pending', 'blocked_configuration', 'failed')
UNION
SELECT transition_id FROM ntfy_notifications WHERE status IN ('pending', 'delivering', 'blocked')
UNION
SELECT transition_id FROM situation_transition_stream WHERE status = 'pending';

CREATE VIEW storage_protected_attempts AS
WITH RECURSIVE protected(id) AS (
    SELECT id FROM (
        SELECT current_assessment_id AS id FROM situations WHERE current_assessment_id IS NOT NULL
        UNION
        SELECT t.assessment_id FROM situation_transitions t
        WHERE t.assessment_id IS NOT NULL AND t.id IN (SELECT transition_id FROM storage_protected_transitions)
    )
    UNION
    SELECT a.reused_from_assessment_id FROM situation_assessment_attempts a
    JOIN protected p ON a.id = p.id
    WHERE a.reused_from_assessment_id IS NOT NULL
)
SELECT id AS attempt_id FROM protected;

CREATE INDEX situations_current_assessment_idx ON situations(current_assessment_id)
    WHERE current_assessment_id IS NOT NULL;

-- ----------------------------------------------------------------------
-- Transition briefings, stored apart and compressed.
-- ----------------------------------------------------------------------
CREATE TABLE situation_transition_briefings (
    transition_id TEXT    NOT NULL PRIMARY KEY REFERENCES situation_transitions(id),
    encoding      TEXT    NOT NULL CHECK (encoding = 'zlib'),
    raw_bytes     INTEGER NOT NULL CHECK (raw_bytes > 0),
    briefing      BLOB    NOT NULL CHECK (length(briefing) > 0)
) STRICT;
CREATE TRIGGER situation_transition_briefings_no_update BEFORE UPDATE ON situation_transition_briefings
BEGIN SELECT RAISE(ABORT, 'situation transition briefings are immutable'); END;
CREATE TRIGGER situation_transition_briefings_no_delete BEFORE DELETE ON situation_transition_briefings
WHEN NOT EXISTS (
    SELECT 1 FROM storage_retention_pruning p WHERE p.kind = 'transition' AND p.id = OLD.transition_id
)
BEGIN SELECT RAISE(ABORT, 'situation transition briefings may only expire through retention'); END;

-- briefing_execution_started: set on every Transition written with its
-- briefing stored apart (NULL: the briefing, if any, is inside
-- projection_json). detail_expired_at: when retention dropped the detail.
ALTER TABLE situation_transitions ADD COLUMN briefing_execution_started INTEGER
    CHECK (briefing_execution_started IS NULL OR briefing_execution_started IN (0, 1));
ALTER TABLE situation_transitions ADD COLUMN detail_expired_at TEXT
    CHECK (detail_expired_at IS NULL OR detail_expired_at <> '');
-- Keyed on the new column so building it reads only each row's header: a
-- Transition with an expanded briefing is mostly overflow pages.
CREATE INDEX situation_transitions_unexpired_idx ON situation_transitions(detail_expired_at)
    WHERE detail_expired_at IS NULL;

-- Every comparison in these WHEN clauses is NULL-safe (IS, EXISTS): a NULL
-- would make the whole WHEN unknown and silently skip the RAISE.
--
-- The ledger stays immutable except for two narrowly defined edits: moving
-- an existing briefing into situation_transition_briefings, and dropping the
-- detail of a Transition nothing current uses (briefing, candidates, cited
-- fact IDs). Identity, journal, contract and every other column never change.
DROP TRIGGER situation_transitions_no_update;
CREATE TRIGGER situation_transitions_no_update BEFORE UPDATE ON situation_transitions
WHEN NOT (
    NEW.id IS OLD.id AND NEW.situation_id IS OLD.situation_id AND NEW.sequence IS OLD.sequence
    AND NEW.input_version IS OLD.input_version AND NEW.material_fact_hash IS OLD.material_fact_hash
    AND NEW.assessment_id IS OLD.assessment_id AND NEW.lifecycle IS OLD.lifecycle AND NEW.attention IS OLD.attention
    AND NEW.action_contract_json IS OLD.action_contract_json AND NEW.sufficient_reason_id IS OLD.sufficient_reason_id
    AND NEW.interruption_priority IS OLD.interruption_priority AND NEW.reason IS OLD.reason
    AND NEW.journal_kind IS OLD.journal_kind AND NEW.journal_json IS OLD.journal_json
    AND NEW.operator_artifact_input_id IS OLD.operator_artifact_input_id AND NEW.actor IS OLD.actor
    AND NEW.drill IS OLD.drill AND NEW.created_at IS OLD.created_at
    AND NEW.briefing_execution_started IS OLD.briefing_execution_started
    AND (
        (OLD.detail_expired_at IS NULL AND NEW.detail_expired_at IS NULL
         AND NEW.evidence_refs_json IS OLD.evidence_refs_json
         AND json_type(OLD.projection_json, '$.briefing') IS 'object'
         AND NEW.projection_json IS json_remove(OLD.projection_json, '$.briefing')
         AND EXISTS (SELECT 1 FROM situation_transition_briefings b WHERE b.transition_id = OLD.id))
        OR
        (OLD.detail_expired_at IS NULL AND NEW.detail_expired_at IS NOT NULL
         AND NEW.evidence_refs_json IS '[]'
         AND NEW.projection_json IS json_remove(OLD.projection_json, '$.briefing', '$.operator_delta.candidates')
         AND EXISTS (SELECT 1 FROM storage_retention_pruning p WHERE p.kind = 'transition' AND p.id = OLD.id)
         AND NOT EXISTS (SELECT 1 FROM storage_protected_transitions v WHERE v.transition_id = OLD.id))
    )
)
BEGIN SELECT RAISE(ABORT, 'situation transition history is immutable'); END;

-- 0047's history facts read the briefing's execution_started flag. A new
-- Transition's briefing is no longer in projection_json, so the view reads
-- briefing_execution_started for it. Existing rows already have their facts.
DROP TRIGGER situation_transition_history_facts_insert;
DROP VIEW situation_transition_history_facts_source;
CREATE VIEW situation_transition_history_facts_source AS
SELECT
    t.id AS transition_id,
    t.situation_id,
    t.sequence,
    t.journal_kind,
    json_object(
        'operator_delta', json(CASE WHEN json_type(t.projection_json, '$.operator_delta') = 'object' THEN json_object(
            'candidates', json(CASE WHEN json_type(t.projection_json, '$.operator_delta.candidates') = 'array' THEN (
                SELECT json_group_array(json(CASE WHEN c.type = 'object' THEN json_object(
                    'kind', c.value ->> '$.kind',
                    'limitation', c.value -> '$.limitation',
                    'action', c.value -> '$.action'
                ) END) ORDER BY c.key)
                FROM json_each(t.projection_json, '$.operator_delta.candidates') c
            ) END)
        ) END),
        'briefing', json(CASE
            WHEN json_type(t.projection_json, '$.briefing') = 'object' THEN json_object(
                'work', json_object('execution_started',
                    json(CASE WHEN json_extract(t.projection_json, '$.briefing.work.execution_started') THEN 'true' ELSE 'false' END)))
            WHEN t.briefing_execution_started IS NOT NULL THEN json_object(
                'work', json_object('execution_started',
                    json(CASE WHEN t.briefing_execution_started = 1 THEN 'true' ELSE 'false' END)))
        END)
    ) AS facts_json
FROM situation_transitions t;
CREATE TRIGGER situation_transition_history_facts_insert AFTER INSERT ON situation_transitions
BEGIN
    INSERT INTO situation_transition_history_facts(transition_id, situation_id, sequence, journal_kind, facts_json)
        SELECT transition_id, situation_id, sequence, journal_kind, facts_json
        FROM situation_transition_history_facts_source WHERE transition_id = NEW.id;
END;

-- ----------------------------------------------------------------------
-- Assessment attempts: once an old attempt nothing current uses releases its
-- observation evidence, evidence_released_at records it. Nothing else about
-- an attempt ever changes.
-- ----------------------------------------------------------------------
ALTER TABLE situation_assessment_attempts ADD COLUMN evidence_released_at TEXT
    CHECK (evidence_released_at IS NULL OR evidence_released_at <> '');
CREATE INDEX situation_assessment_attempts_unreleased_idx ON situation_assessment_attempts(evidence_released_at)
    WHERE evidence_released_at IS NULL;
DROP TRIGGER situation_assessment_attempts_no_update;
CREATE TRIGGER situation_assessment_attempts_no_update BEFORE UPDATE ON situation_assessment_attempts
WHEN NOT (
    NEW.id IS OLD.id AND NEW.situation_id IS OLD.situation_id AND NEW.sequence IS OLD.sequence
    AND NEW.input_version IS OLD.input_version AND NEW.retry_epoch IS OLD.retry_epoch
    AND NEW.work_attempt IS OLD.work_attempt AND NEW.call_id IS OLD.call_id AND NEW.status IS OLD.status
    AND NEW.derivation IS OLD.derivation AND NEW.provider_request_started IS OLD.provider_request_started
    AND NEW.material_fact_hash IS OLD.material_fact_hash AND NEW.assessment_basis_hash IS OLD.assessment_basis_hash
    AND NEW.proposal_json IS OLD.proposal_json AND NEW.validation_errors_json IS OLD.validation_errors_json
    AND NEW.assessment_json IS OLD.assessment_json AND NEW.reused_from_assessment_id IS OLD.reused_from_assessment_id
    AND NEW.usage_input_tokens IS OLD.usage_input_tokens AND NEW.usage_output_tokens IS OLD.usage_output_tokens
    AND NEW.created_at IS OLD.created_at AND NEW.completed_at IS OLD.completed_at
    AND OLD.evidence_released_at IS NULL AND NEW.evidence_released_at IS NOT NULL
    AND EXISTS (SELECT 1 FROM storage_retention_pruning p WHERE p.kind = 'assessment_attempt' AND p.id = OLD.id)
    AND NOT EXISTS (SELECT 1 FROM storage_protected_attempts v WHERE v.attempt_id = OLD.id)
)
BEGIN SELECT RAISE(ABORT, 'assessment attempt history is immutable'); END;

-- Only the current assessment's coverage is ever read.
DROP TRIGGER situation_assessment_coverage_no_delete;
CREATE TRIGGER situation_assessment_coverage_no_delete BEFORE DELETE ON situation_assessment_coverage
WHEN NOT EXISTS (
    SELECT 1 FROM storage_retention_pruning p WHERE p.kind = 'coverage' AND p.id = OLD.assessment_attempt_id
) OR EXISTS (SELECT 1 FROM situations s WHERE s.current_assessment_id = OLD.assessment_attempt_id)
BEGIN SELECT RAISE(ABORT, 'assessment coverage may only be deleted through retention, never for a current assessment'); END;

-- ----------------------------------------------------------------------
-- Facts: one head per (Situation, kind, subject) names the row that holds the
-- current content. A fact equal to its head is not written again; a changed
-- one is, and the replaced head is queued with the time it was superseded.
-- ----------------------------------------------------------------------
CREATE TABLE situation_fact_heads (
    situation_id TEXT NOT NULL REFERENCES situations(id),
    kind         TEXT NOT NULL CHECK (kind <> ''),
    subject      TEXT NOT NULL CHECK (subject <> ''),
    fact_id      TEXT NOT NULL REFERENCES situation_facts(id),
    content_hash TEXT NOT NULL CHECK (content_hash <> ''),
    PRIMARY KEY (situation_id, kind, subject)
) STRICT, WITHOUT ROWID;
CREATE INDEX situation_fact_heads_fact_idx ON situation_fact_heads(fact_id);

CREATE TABLE situation_fact_supersessions (
    fact_id       TEXT NOT NULL PRIMARY KEY CHECK (fact_id <> ''),
    superseded_at TEXT NOT NULL CHECK (superseded_at <> '')
) STRICT;

DROP TRIGGER situation_facts_no_delete;
CREATE TRIGGER situation_facts_no_delete BEFORE DELETE ON situation_facts
WHEN EXISTS (SELECT 1 FROM situation_fact_heads h WHERE h.fact_id = OLD.id) OR NOT (
    EXISTS (SELECT 1 FROM situation_fact_supersessions s WHERE s.fact_id = OLD.id)
    OR EXISTS (SELECT 1 FROM storage_retention_pruning p WHERE p.kind = 'fact' AND p.id = OLD.id)
    OR (EXISTS (SELECT 1 FROM storage_retention_pruning p WHERE p.kind = 'legacy_facts')
        AND OLD.rowid <= coalesce((SELECT CAST(value AS INTEGER) FROM storage_retention_state WHERE key = 'facts_legacy_max_rowid'), 0))
)
BEGIN SELECT RAISE(ABORT, 'situation facts may only be deleted through retention'); END;

-- ----------------------------------------------------------------------
-- Observation references: a permanent reference now ends with its owner's
-- retention (an expired Transition, a released attempt, an old lifecycle
-- decision). 0042's rule for superseded cycle pointers stands.
-- ----------------------------------------------------------------------
CREATE INDEX situation_observation_references_lifecycle_idx ON situation_observation_references(created_at)
    WHERE reference_kind = 'lifecycle_decision';
DROP TRIGGER situation_observation_references_no_delete;
CREATE TRIGGER situation_observation_references_no_delete BEFORE DELETE ON situation_observation_references
WHEN NOT (
    (OLD.permanent = 0 AND OLD.superseded = 1 AND EXISTS (
        SELECT 1 FROM situation_preparation_pruning p WHERE p.cycle_id = OLD.owner_id
        UNION ALL
        SELECT 1 FROM situation_observation_runs r
        JOIN situation_preparation_pruning p ON p.cycle_id = r.cycle_id WHERE r.id = OLD.run_id
    ))
    OR (OLD.permanent = 1 AND EXISTS (
        SELECT 1 FROM storage_retention_pruning p WHERE p.kind = OLD.reference_kind AND p.id = OLD.owner_id
    ))
)
BEGIN SELECT RAISE(ABORT, 'observation references may only be deleted through retention'); END;
