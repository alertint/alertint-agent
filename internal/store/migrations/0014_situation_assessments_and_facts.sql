-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Bounded observation audit, immutable normalized facts, and versioned
-- Assessment attempts. Raw connector responses deliberately have no column.

CREATE TABLE situation_observation_runs (
    id                    TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id          TEXT    NOT NULL REFERENCES situations(id) ON DELETE CASCADE,
    input_version         INTEGER NOT NULL CHECK (input_version >= 1),
    proposed_plan_json    TEXT    NOT NULL CHECK (length(proposed_plan_json) <= 65536 AND json_valid(proposed_plan_json) AND json_type(proposed_plan_json) = 'object'),
    validated_plan_json   TEXT    NOT NULL CHECK (length(validated_plan_json) <= 65536 AND json_valid(validated_plan_json) AND json_type(validated_plan_json) = 'object'),
    capability            TEXT    NOT NULL CHECK (capability IN ('store_read','prometheus_query','zabbix_metric_range','zabbix_problem_history','loki_query','sentry_issues','change_events')),
    scope_json             TEXT    NOT NULL CHECK (length(scope_json) <= 65536 AND json_valid(scope_json) AND json_type(scope_json) = 'object'),
    parameters_json        TEXT    NOT NULL CHECK (length(parameters_json) <= 32768 AND json_valid(parameters_json) AND json_type(parameters_json) = 'object'),
    budget                 INTEGER NOT NULL CHECK (budget >= 0),
    status                 TEXT    NOT NULL CHECK (status IN ('confirmed_value','confirmed_empty','unconfirmed_empty','unavailable','failed','stale','truncated','withheld_by_budget','vocabulary_unresolved')),
    observed_at            TEXT    NOT NULL CHECK (observed_at <> ''),
    freshness              TEXT    NOT NULL CHECK (freshness IN ('fresh','stale','unknown')),
    truncated              INTEGER NOT NULL CHECK (truncated IN (0,1)),
    digest                 TEXT    NOT NULL CHECK (digest <> ''),
    retry_error_class      TEXT,
    token_cost             INTEGER NOT NULL CHECK (token_cost >= 0),
    source_call_cost       INTEGER NOT NULL CHECK (source_call_cost >= 0),
    created_at             TEXT    NOT NULL CHECK (created_at <> '')
) STRICT;

CREATE INDEX situation_observation_runs_situation_version_idx
    ON situation_observation_runs(situation_id, input_version, observed_at);

CREATE TRIGGER situation_observation_runs_no_update
BEFORE UPDATE ON situation_observation_runs
BEGIN
    SELECT RAISE(ABORT, 'situation observation runs are immutable');
END;

CREATE TRIGGER situation_observation_runs_no_delete
BEFORE DELETE ON situation_observation_runs
BEGIN
    SELECT RAISE(ABORT, 'situation observation runs are immutable');
END;

CREATE TABLE situation_facts (
    id                 TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id       TEXT    NOT NULL REFERENCES situations(id) ON DELETE CASCADE,
    input_version      INTEGER NOT NULL CHECK (input_version >= 1),
    kind               TEXT    NOT NULL CHECK (kind <> ''),
    subject            TEXT    NOT NULL CHECK (subject <> ''),
    value_json         TEXT    NOT NULL CHECK (length(value_json) <= 524288 AND json_valid(value_json)),
    source_capability  TEXT    NOT NULL CHECK (source_capability IN ('store_read','prometheus_query','zabbix_metric_range','zabbix_problem_history','loki_query','sentry_issues','change_events')),
    observed_at        TEXT    NOT NULL CHECK (observed_at <> ''),
    freshness          TEXT    NOT NULL CHECK (freshness IN ('fresh','stale','unknown')),
    result_status      TEXT    NOT NULL CHECK (result_status IN ('confirmed_value','confirmed_empty','unconfirmed_empty','unavailable','failed','stale','truncated','withheld_by_budget','vocabulary_unresolved')),
    digest             TEXT    NOT NULL CHECK (digest <> ''),
    evidence_refs_json TEXT    NOT NULL CHECK (length(evidence_refs_json) <= 65536 AND json_valid(evidence_refs_json) AND json_type(evidence_refs_json) = 'array'),
    material           INTEGER NOT NULL CHECK (material IN (0,1)),
    created_at         TEXT    NOT NULL CHECK (created_at <> '')
) STRICT;

CREATE INDEX situation_facts_situation_version_idx
    ON situation_facts(situation_id, input_version, observed_at);

CREATE INDEX situation_facts_digest_idx
    ON situation_facts(situation_id, digest);

CREATE TRIGGER situation_facts_no_update
BEFORE UPDATE ON situation_facts
BEGIN
    SELECT RAISE(ABORT, 'situation facts are immutable');
END;

CREATE TRIGGER situation_facts_no_delete
BEFORE DELETE ON situation_facts
BEGIN
    SELECT RAISE(ABORT, 'situation facts are immutable');
END;

CREATE TABLE situation_assessment_attempts (
    id                          TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id                TEXT    NOT NULL REFERENCES situations(id) ON DELETE CASCADE,
    sequence                    INTEGER NOT NULL CHECK (sequence >= 1),
    input_version               INTEGER NOT NULL CHECK (input_version >= 1),
    fact_hash                   TEXT    NOT NULL CHECK (fact_hash <> ''),
    actor                       TEXT    NOT NULL CHECK (actor IN ('deterministic_controller','llm')),
    status                      TEXT    NOT NULL CHECK (status IN ('proposed','authoritative','rejected','failed','stale')),
    trigger_reasons_json        TEXT    NOT NULL CHECK (length(trigger_reasons_json) <= 65536 AND json_valid(trigger_reasons_json) AND json_type(trigger_reasons_json) = 'array'),
    snapshot_digest             TEXT    NOT NULL CHECK (snapshot_digest <> ''),
    proposal_json               TEXT    CHECK (proposal_json IS NULL OR (length(proposal_json) <= 524288 AND json_valid(proposal_json) AND json_type(proposal_json) = 'object')),
    validated_json              TEXT    CHECK (validated_json IS NULL OR (length(validated_json) <= 524288 AND json_valid(validated_json) AND json_type(validated_json) = 'object')),
    validation_adjustments_json TEXT    NOT NULL CHECK (length(validation_adjustments_json) <= 262144 AND json_valid(validation_adjustments_json) AND json_type(validation_adjustments_json) = 'array'),
    model_usage_json            TEXT    CHECK (model_usage_json IS NULL OR (length(model_usage_json) <= 262144 AND json_valid(model_usage_json) AND json_type(model_usage_json) = 'object')),
    created_at                  TEXT    NOT NULL CHECK (created_at <> ''),
    completed_at                TEXT,
    UNIQUE(situation_id, sequence),
    CHECK (status <> 'authoritative' OR (validated_json IS NOT NULL AND completed_at IS NOT NULL))
) STRICT;

CREATE INDEX situation_assessment_attempts_situation_version_idx
    ON situation_assessment_attempts(situation_id, input_version, sequence);

CREATE TRIGGER situation_assessment_attempts_no_update
BEFORE UPDATE ON situation_assessment_attempts
BEGIN
    SELECT RAISE(ABORT, 'situation assessment attempts are immutable');
END;

CREATE TRIGGER situation_assessment_attempts_no_delete
BEFORE DELETE ON situation_assessment_attempts
BEGIN
    SELECT RAISE(ABORT, 'situation assessment attempts are immutable');
END;

CREATE TRIGGER situations_current_assessment_authoritative
BEFORE UPDATE OF current_assessment_id ON situations
WHEN NEW.current_assessment_id IS NOT NULL
 AND NEW.current_assessment_id IS NOT OLD.current_assessment_id
 AND NOT EXISTS (
    SELECT 1 FROM situation_assessment_attempts AS attempt
    WHERE attempt.id = NEW.current_assessment_id
      AND attempt.situation_id = NEW.id
      AND attempt.status = 'authoritative'
 )
BEGIN
    SELECT RAISE(ABORT, 'current assessment must be authoritative');
END;

CREATE TRIGGER situations_initial_assessment_authoritative
BEFORE INSERT ON situations
WHEN NEW.current_assessment_id IS NOT NULL
 AND NOT EXISTS (
    SELECT 1 FROM situation_assessment_attempts AS attempt
    WHERE attempt.id = NEW.current_assessment_id
      AND attempt.situation_id = NEW.id
      AND attempt.status = 'authoritative'
 )
BEGIN
    SELECT RAISE(ABORT, 'initial assessment must be authoritative');
END;
