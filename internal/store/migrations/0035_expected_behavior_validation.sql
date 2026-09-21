-- SPDX-License-Identifier: FSL-1.1-ALv2

-- Migration 0026's original capability column has a closed CHECK. Keep it
-- as the compatibility value and add the authoritative v2 capability for
-- policy-only reads, avoiding a destructive rebuild of immutable plans and
-- their request/run foreign-key graph.
ALTER TABLE situation_observation_plans ADD COLUMN capability_v2 TEXT
    CHECK (capability_v2 IS NULL OR capability_v2 IN (
        'store_read','prometheus_query','zabbix_metric_range','zabbix_problem_history',
        'zabbix_problem_state','loki_query','sentry_issues','change_events'
    ));

CREATE TABLE expected_behavior_validation_requests (
    id                       TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id             TEXT    NOT NULL REFERENCES situations(id) ON DELETE RESTRICT,
    situation_input_version  INTEGER NOT NULL CHECK (situation_input_version >= 1),
    binding_digest           TEXT    NOT NULL CHECK (binding_digest <> ''),
    bindings_json            TEXT    NOT NULL CHECK (json_valid(bindings_json) AND json_type(bindings_json) = 'array'),
    status                   TEXT    NOT NULL CHECK (status IN ('pending','ready','unavailable')),
    observation_refs_json    TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(observation_refs_json) AND json_type(observation_refs_json) = 'array'),
    observations_json        TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(observations_json) AND json_type(observations_json) = 'array'),
    unavailable_reason       TEXT,
    expires_at               TEXT    NOT NULL CHECK (expires_at <> ''),
    created_at               TEXT    NOT NULL CHECK (created_at <> ''),
    updated_at               TEXT    NOT NULL CHECK (updated_at <> ''),
    UNIQUE (situation_id, situation_input_version, binding_digest),
    CHECK ((status = 'unavailable') = (unavailable_reason IS NOT NULL))
) STRICT;
CREATE INDEX expected_behavior_validation_pending_idx
    ON expected_behavior_validation_requests(status, expires_at, created_at);

CREATE TRIGGER expected_behavior_validation_identity_immutable BEFORE UPDATE OF
    situation_id,situation_input_version,binding_digest,bindings_json,created_at
    ON expected_behavior_validation_requests
BEGIN SELECT RAISE(ABORT, 'expected behavior validation identity is immutable'); END;
CREATE TRIGGER expected_behavior_validation_no_delete BEFORE DELETE ON expected_behavior_validation_requests
BEGIN SELECT RAISE(ABORT, 'expected behavior validation requests are durable'); END;
