-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Issue #99: the delivery-history reads (delivered, standing and root folds,
-- assurance overtaking, live transient assurance) decoded the full
-- projection_json of every Transition a Situation's replies and root syncs
-- reference. A long-lived Situation repeats its whole alert list in every
-- row, so one read held the single connection for tens of seconds and
-- hundreds of MB of heap. Those reads only ever need the candidate kinds,
-- their limitation and action facts, and the briefing's execution_started
-- flag. This table keeps exactly that, one immutable row per Transition, in
-- projection_json's own shape, so the Go folds read it unchanged.
--
-- One view is the only place the facts are derived: the backfill below and
-- the insert trigger both select from it, so existing and new Transitions
-- can never be pruned differently. Every conditional value is wrapped in
-- json() where it is used, because a CASE or a subquery may drop the JSON
-- subtype and json_object() would then store the object as a string.

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
        'briefing', json(CASE WHEN json_type(t.projection_json, '$.briefing') = 'object' THEN json_object(
            'work', json_object('execution_started',
                json(CASE WHEN json_extract(t.projection_json, '$.briefing.work.execution_started') THEN 'true' ELSE 'false' END))
        ) END)
    ) AS facts_json
FROM situation_transitions t;

CREATE TABLE situation_transition_history_facts (
    transition_id TEXT    NOT NULL PRIMARY KEY REFERENCES situation_transitions(id),
    situation_id  TEXT    NOT NULL,
    sequence      INTEGER NOT NULL,
    journal_kind  TEXT    NOT NULL,
    facts_json    TEXT    NOT NULL CHECK (json_valid(facts_json) AND json_type(facts_json) = 'object'),
    UNIQUE (situation_id, sequence)
) STRICT;

INSERT INTO situation_transition_history_facts(transition_id, situation_id, sequence, journal_kind, facts_json)
    SELECT transition_id, situation_id, sequence, journal_kind, facts_json
    FROM situation_transition_history_facts_source;

CREATE TRIGGER situation_transition_history_facts_insert AFTER INSERT ON situation_transitions
BEGIN
    INSERT INTO situation_transition_history_facts(transition_id, situation_id, sequence, journal_kind, facts_json)
        SELECT transition_id, situation_id, sequence, journal_kind, facts_json
        FROM situation_transition_history_facts_source WHERE transition_id = NEW.id;
END;
CREATE TRIGGER situation_transition_history_facts_no_update BEFORE UPDATE ON situation_transition_history_facts
BEGIN SELECT RAISE(ABORT, 'situation transition history facts are immutable'); END;
CREATE TRIGGER situation_transition_history_facts_no_delete BEFORE DELETE ON situation_transition_history_facts
BEGIN SELECT RAISE(ABORT, 'situation transition history facts are immutable'); END;
