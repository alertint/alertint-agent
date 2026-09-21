-- SPDX-License-Identifier: FSL-1.1-ALv2

CREATE TABLE expected_behavior_envelope_revisions (
    id                       TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    envelope_id              TEXT    NOT NULL CHECK (envelope_id <> ''),
    version                  INTEGER NOT NULL CHECK (version >= 1),
    operation                TEXT    NOT NULL CHECK (operation IN ('confirm','replace','revoke','restore')),
    state                    TEXT    NOT NULL CHECK (state IN ('active','revoked')),
    policy_json              TEXT    CHECK (policy_json IS NULL OR (json_valid(policy_json) AND json_type(policy_json) = 'object')),
    source_judgment_id       TEXT    REFERENCES situation_judgments(id) ON DELETE RESTRICT,
    source_situation_id      TEXT    REFERENCES situations(id) ON DELETE RESTRICT,
    asserted_operator        TEXT    NOT NULL CHECK (asserted_operator <> ''),
    trust_domain             TEXT    NOT NULL CHECK (trust_domain = 'authenticated_mcp'),
    request_id               TEXT    NOT NULL UNIQUE CHECK (request_id <> ''),
    request_hash             TEXT    NOT NULL CHECK (request_hash <> ''),
    expected_previous_version INTEGER NOT NULL CHECK (expected_previous_version >= 0),
    created_at               TEXT    NOT NULL CHECK (created_at <> ''),
    UNIQUE (envelope_id, version),
    CHECK ((state = 'active' AND policy_json IS NOT NULL AND source_judgment_id IS NOT NULL AND source_situation_id IS NOT NULL)
        OR (state = 'revoked' AND operation = 'revoke' AND policy_json IS NULL))
) STRICT;

CREATE TABLE expected_behavior_envelope_heads (
    envelope_id               TEXT    NOT NULL PRIMARY KEY CHECK (envelope_id <> ''),
    revision_id               TEXT    NOT NULL UNIQUE REFERENCES expected_behavior_envelope_revisions(id) ON DELETE RESTRICT,
    version                   INTEGER NOT NULL CHECK (version >= 1),
    state                     TEXT    NOT NULL CHECK (state IN ('active','revoked')),
    group_key                 TEXT    NOT NULL CHECK (group_key <> ''),
    source                    TEXT    NOT NULL CHECK (source = 'zabbix'),
    source_instance_id        TEXT    NOT NULL CHECK (source_instance_id <> ''),
    host                      TEXT    NOT NULL CHECK (host <> ''),
    primary_trigger_id        TEXT    NOT NULL CHECK (primary_trigger_id <> ''),
    primary_trigger_version   TEXT    NOT NULL CHECK (primary_trigger_version <> ''),
    invalidated_at            TEXT,
    invalidation_reason       TEXT CHECK (invalidation_reason IS NULL OR invalidation_reason IN
        ('source_instance_changed','primary_definition_changed','binding_definition_changed')),
    updated_at                TEXT    NOT NULL CHECK (updated_at <> ''),
    CHECK ((invalidated_at IS NULL) = (invalidation_reason IS NULL))
) STRICT;

CREATE INDEX expected_behavior_envelope_scope_idx
    ON expected_behavior_envelope_heads(group_key, source, source_instance_id, host, primary_trigger_id, state);
CREATE INDEX expected_behavior_envelope_history_idx
    ON expected_behavior_envelope_revisions(envelope_id, version);

CREATE TABLE expected_behavior_system_events (
    id                  TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    envelope_id         TEXT    NOT NULL REFERENCES expected_behavior_envelope_heads(envelope_id) ON DELETE RESTRICT,
    envelope_version    INTEGER NOT NULL CHECK (envelope_version >= 1),
    kind                TEXT    NOT NULL CHECK (kind = 'invalidated'),
    reason              TEXT    NOT NULL CHECK (reason IN
        ('source_instance_changed','primary_definition_changed','binding_definition_changed')),
    evidence_json       TEXT    NOT NULL CHECK (json_valid(evidence_json) AND json_type(evidence_json) = 'object'),
    created_at          TEXT    NOT NULL CHECK (created_at <> ''),
    UNIQUE (envelope_id, envelope_version, kind, reason)
) STRICT;

CREATE TABLE expected_behavior_evaluations (
    id                       TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id             TEXT    NOT NULL REFERENCES situations(id) ON DELETE RESTRICT,
    situation_input_version  INTEGER NOT NULL CHECK (situation_input_version >= 1),
    disposition              TEXT    NOT NULL CHECK (disposition IN ('matched','authority_unavailable','violated','not_applicable')),
    reason                   TEXT,
    chosen_envelope_id       TEXT,
    chosen_version           INTEGER,
    evaluation_json          TEXT    NOT NULL CHECK (json_valid(evaluation_json) AND json_type(evaluation_json) = 'object'),
    basis_hash               TEXT    NOT NULL CHECK (basis_hash <> ''),
    evaluated_at             TEXT    NOT NULL CHECK (evaluated_at <> ''),
    UNIQUE (situation_id, basis_hash)
) STRICT;

CREATE TABLE expected_behavior_evaluation_heads (
    situation_id       TEXT NOT NULL PRIMARY KEY REFERENCES situations(id) ON DELETE RESTRICT,
    evaluation_id      TEXT NOT NULL UNIQUE REFERENCES expected_behavior_evaluations(id) ON DELETE RESTRICT,
    updated_at         TEXT NOT NULL CHECK (updated_at <> '')
) STRICT;

CREATE TRIGGER expected_behavior_envelope_revisions_immutable BEFORE UPDATE ON expected_behavior_envelope_revisions
BEGIN SELECT RAISE(ABORT, 'expected behavior revisions are immutable'); END;
CREATE TRIGGER expected_behavior_envelope_revisions_no_delete BEFORE DELETE ON expected_behavior_envelope_revisions
BEGIN SELECT RAISE(ABORT, 'expected behavior revisions are immutable'); END;
CREATE TRIGGER expected_behavior_envelope_heads_no_delete BEFORE DELETE ON expected_behavior_envelope_heads
BEGIN SELECT RAISE(ABORT, 'expected behavior heads are durable'); END;
CREATE TRIGGER expected_behavior_system_events_immutable BEFORE UPDATE ON expected_behavior_system_events
BEGIN SELECT RAISE(ABORT, 'expected behavior system events are immutable'); END;
CREATE TRIGGER expected_behavior_system_events_no_delete BEFORE DELETE ON expected_behavior_system_events
BEGIN SELECT RAISE(ABORT, 'expected behavior system events are immutable'); END;
CREATE TRIGGER expected_behavior_evaluations_immutable BEFORE UPDATE ON expected_behavior_evaluations
BEGIN SELECT RAISE(ABORT, 'expected behavior evaluations are immutable'); END;
CREATE TRIGGER expected_behavior_evaluations_no_delete BEFORE DELETE ON expected_behavior_evaluations
BEGIN SELECT RAISE(ABORT, 'expected behavior evaluations are immutable'); END;
