-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 2 controller schema: immutable material facts, immutable L2 provider
-- dispatch/outcome history, bounded per-Incident Assessment coverage tuples,
-- and the current-Assessment/controller-retry projection on `situations`.
--
-- Identity conventions (plan.md Task 2):
--   - situation_facts:              fact identity (its own deterministic id)
--   - situation_assessment_calls:   (situation_id,input_version,retry_epoch,work_attempt,call_number)
--   - situation_assessment_attempts:(situation_id,sequence)
-- Calls and attempts both carry retry_epoch/work_attempt explicitly so an
-- attempt stands on its own even when it has no backing call (deterministic,
-- fallback, and reuse derivations never dispatch a provider call).

-- situation_facts holds every immutable, store-derived material fact
-- (CONTEXT: Fact). A newer fact supersedes an older one by deterministic
-- selection at read time; rows are never edited or removed.
CREATE TABLE situation_facts (
    id                 TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id       TEXT    NOT NULL REFERENCES situations(id),
    input_version      INTEGER NOT NULL CHECK (input_version >= 1),
    kind               TEXT    NOT NULL CHECK (kind IN (
                           'source_symptom_state', 'source_lifecycle_summary', 'current_duration',
                           'incident_membership', 'incident_triage_state', 'acute_finding',
                           'prior_situation_duration_distribution', 'capability_limitation'
                       )),
    subject            TEXT    NOT NULL CHECK (subject <> ''),
    digest             TEXT    NOT NULL CHECK (digest <> ''),
    value_json         TEXT    NOT NULL CHECK (json_valid(value_json)),
    result_status      TEXT    NOT NULL CHECK (result_status IN ('confirmed_value', 'confirmed_empty', 'unavailable', 'failed', 'stale')),
    evidence_refs_json TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_refs_json) AND json_type(evidence_refs_json) = 'array'),
    material           INTEGER NOT NULL CHECK (material IN (0, 1)),
    observed_at        TEXT    NOT NULL CHECK (observed_at <> '')
) STRICT;
CREATE INDEX situation_facts_situation_idx ON situation_facts(situation_id, input_version, kind);
CREATE TRIGGER situation_facts_no_update BEFORE UPDATE ON situation_facts
BEGIN SELECT RAISE(ABORT, 'situation facts are immutable'); END;
CREATE TRIGGER situation_facts_no_delete BEFORE DELETE ON situation_facts
BEGIN SELECT RAISE(ABORT, 'situation facts are immutable'); END;

-- situation_assessment_calls is the immutable L2 provider dispatch ledger.
-- A row commits durably before the physical HTTP request is made; its
-- existence alone proves the call budget was consumed (spec: "Provider
-- dispatch is recorded durably before the call"). Each dispatch permits at
-- most one physical request, so call_number is bounded to the two-call
-- draft/verification ceiling per controller attempt.
CREATE TABLE situation_assessment_calls (
    id                 TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id       TEXT    NOT NULL REFERENCES situations(id),
    input_version      INTEGER NOT NULL CHECK (input_version >= 1),
    retry_epoch        INTEGER NOT NULL DEFAULT 0 CHECK (retry_epoch >= 0),
    work_attempt       INTEGER NOT NULL CHECK (work_attempt >= 1 AND work_attempt <= 5),
    call_number        INTEGER NOT NULL CHECK (call_number IN (1, 2)),
    material_fact_hash TEXT    NOT NULL CHECK (material_fact_hash <> ''),
    provider_profile   TEXT,
    dispatched_at      TEXT    NOT NULL CHECK (dispatched_at <> ''),
    UNIQUE (situation_id, input_version, retry_epoch, work_attempt, call_number)
) STRICT;
CREATE INDEX situation_assessment_calls_situation_idx ON situation_assessment_calls(situation_id, dispatched_at);
CREATE TRIGGER situation_assessment_calls_no_update BEFORE UPDATE ON situation_assessment_calls
BEGIN SELECT RAISE(ABORT, 'assessment call dispatch is immutable'); END;
CREATE TRIGGER situation_assessment_calls_no_delete BEFORE DELETE ON situation_assessment_calls
BEGIN SELECT RAISE(ABORT, 'assessment call dispatch is immutable'); END;

-- situation_assessment_attempts is the immutable outcome ledger: every
-- validated/rejected/failed/stale L2 result, plus every non-model
-- authoritative derivation (deterministic_controller, deterministic_fallback,
-- revalidated_reuse). Only a status='authoritative' row may ever become a
-- Situation's current_assessment_id (enforced by the trigger below). Rows
-- never retain raw prompts, raw provider responses, or provider error
-- bodies — only bounded, persistence-safe content.
CREATE TABLE situation_assessment_attempts (
    id                        TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id              TEXT    NOT NULL REFERENCES situations(id),
    sequence                  INTEGER NOT NULL CHECK (sequence >= 1),
    input_version             INTEGER NOT NULL CHECK (input_version >= 1),
    retry_epoch               INTEGER NOT NULL DEFAULT 0 CHECK (retry_epoch >= 0),
    work_attempt              INTEGER NOT NULL CHECK (work_attempt >= 1 AND work_attempt <= 5),
    call_id                   TEXT REFERENCES situation_assessment_calls(id),
    status                    TEXT    NOT NULL CHECK (status IN ('authoritative', 'rejected', 'failed', 'stale')),
    derivation                TEXT CHECK (derivation IS NULL OR derivation IN ('model_validated', 'deterministic_controller', 'deterministic_fallback', 'revalidated_reuse')),
    provider_request_started  TEXT    NOT NULL CHECK (provider_request_started IN ('true', 'false', 'unknown')),
    material_fact_hash        TEXT    NOT NULL CHECK (material_fact_hash <> ''),
    assessment_basis_hash     TEXT,
    proposal_json             TEXT CHECK (proposal_json IS NULL OR (json_valid(proposal_json) AND json_type(proposal_json) = 'object')),
    validation_errors_json    TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(validation_errors_json) AND json_type(validation_errors_json) = 'array'),
    assessment_json           TEXT CHECK (assessment_json IS NULL OR (json_valid(assessment_json) AND json_type(assessment_json) = 'object')),
    reused_from_assessment_id TEXT REFERENCES situation_assessment_attempts(id),
    usage_input_tokens        INTEGER CHECK (usage_input_tokens IS NULL OR usage_input_tokens >= 0),
    usage_output_tokens       INTEGER CHECK (usage_output_tokens IS NULL OR usage_output_tokens >= 0),
    created_at                TEXT    NOT NULL CHECK (created_at <> ''),
    completed_at              TEXT    NOT NULL CHECK (completed_at <> ''),
    -- Only an authoritative row carries a derivation and full Assessment
    -- content; every other status leaves both null.
    CHECK ((status = 'authoritative') = (derivation IS NOT NULL)),
    CHECK (status != 'authoritative' OR assessment_json IS NOT NULL),
    CHECK (derivation IS NULL OR derivation != 'revalidated_reuse' OR reused_from_assessment_id IS NOT NULL),
    -- model_validated is the only derivation backed by a provider call;
    -- every other authoritative derivation forbids call_id (Task 3 ground
    -- truth: "non-model derivations forbid call_id").
    CHECK (derivation IS NULL OR derivation != 'model_validated' OR call_id IS NOT NULL),
    CHECK (derivation IS NULL OR derivation = 'model_validated' OR call_id IS NULL),
    -- A rejected or failed outcome is always the direct result of a
    -- dispatched call; only a stale outcome may belong to a non-model
    -- derivation caught by a concurrent-input race.
    CHECK (status NOT IN ('rejected', 'failed') OR call_id IS NOT NULL),
    UNIQUE (situation_id, sequence)
) STRICT;
CREATE INDEX situation_assessment_attempts_situation_idx ON situation_assessment_attempts(situation_id, sequence DESC);
CREATE TRIGGER situation_assessment_attempts_no_update BEFORE UPDATE ON situation_assessment_attempts
BEGIN SELECT RAISE(ABORT, 'assessment attempt history is immutable'); END;
CREATE TRIGGER situation_assessment_attempts_no_delete BEFORE DELETE ON situation_assessment_attempts
BEGIN SELECT RAISE(ABORT, 'assessment attempt history is immutable'); END;

-- situation_assessment_coverage records the bounded coverage tuple (Incident
-- ID plus both canonical digests) an authoritative attempt covers for each
-- member Incident (model.IncidentCoverage). A clean Triage skip requires
-- exact equality between current Incident digests, this covered tuple, and
-- the persisted Triage decision.
CREATE TABLE situation_assessment_coverage (
    assessment_attempt_id TEXT NOT NULL REFERENCES situation_assessment_attempts(id),
    incident_id           TEXT NOT NULL REFERENCES incidents(id),
    membership_digest     TEXT NOT NULL CHECK (membership_digest <> ''),
    incident_input_digest TEXT NOT NULL CHECK (incident_input_digest <> ''),
    PRIMARY KEY (assessment_attempt_id, incident_id)
) STRICT;
CREATE INDEX situation_assessment_coverage_incident_idx ON situation_assessment_coverage(incident_id);
CREATE TRIGGER situation_assessment_coverage_no_update BEFORE UPDATE ON situation_assessment_coverage
BEGIN SELECT RAISE(ABORT, 'assessment coverage is immutable'); END;
CREATE TRIGGER situation_assessment_coverage_no_delete BEFORE DELETE ON situation_assessment_coverage
BEGIN SELECT RAISE(ABORT, 'assessment coverage is immutable'); END;

-- Extend situations (0014) with the current-Assessment pointer, the bounded
-- current Operator-contract/hash projection MCP reads without joining
-- attempt history, and the controller's own retry/park/dependency-recovery
-- machinery. All default to "no Assessment yet" (NULL / 0) so existing
-- Plan 1 rows upgrade cleanly.
ALTER TABLE situations ADD COLUMN current_assessment_id TEXT REFERENCES situation_assessment_attempts(id);
ALTER TABLE situations ADD COLUMN current_assessment_basis_hash TEXT;
ALTER TABLE situations ADD COLUMN current_material_fact_hash TEXT;
ALTER TABLE situations ADD COLUMN current_action_contract_json TEXT
    CHECK (current_action_contract_json IS NULL OR (json_valid(current_action_contract_json) AND json_type(current_action_contract_json) = 'object'));
-- current_eligible_reasons_json is the bounded eligible Sufficient-reason
-- candidate set (id/code/versions/evidence refs/deterministic floor) the
-- controller's most recent commit derived from the current material facts —
-- the "eligible reasons with evidence references and versions" the
-- read-only Situation view exposes. Never the accepted reason alone (that
-- lives inside the Assessment) and never free text.
ALTER TABLE situations ADD COLUMN current_eligible_reasons_json TEXT NOT NULL DEFAULT '[]'
    CHECK (json_valid(current_eligible_reasons_json) AND json_type(current_eligible_reasons_json) = 'array');
-- controller_retry_epoch/controller_work_attempts are Plan 2's Assessment
-- work counters and are distinct from Plan 1's generic claim/lease
-- attempt_count: five durable controller attempts are budgeted per
-- unchanged input, and a durable dependency-recovery generation can open
-- exactly one new epoch for work parked on that dependency.
ALTER TABLE situations ADD COLUMN controller_retry_epoch INTEGER NOT NULL DEFAULT 0 CHECK (controller_retry_epoch >= 0);
ALTER TABLE situations ADD COLUMN controller_work_attempts INTEGER NOT NULL DEFAULT 0 CHECK (controller_work_attempts >= 0 AND controller_work_attempts <= 5);
ALTER TABLE situations ADD COLUMN controller_parked_at TEXT;
ALTER TABLE situations ADD COLUMN controller_parked_reason TEXT;
-- last_consumed_recovery_generation fences exactly-once dependency re-arm:
-- the controller compares it against llm_health.outage_generation and only
-- opens a new retry epoch when the observed generation is newer.
ALTER TABLE situations ADD COLUMN last_consumed_recovery_generation INTEGER NOT NULL DEFAULT 0 CHECK (last_consumed_recovery_generation >= 0);

-- Only an authoritative attempt belonging to the same Situation may become
-- current_assessment_id (spec: "Only an authoritative Assessment belonging
-- to the same Situation may become current_assessment_id").
CREATE TRIGGER situations_current_assessment_guard BEFORE UPDATE OF current_assessment_id ON situations
WHEN NEW.current_assessment_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM situation_assessment_attempts a
    WHERE a.id = NEW.current_assessment_id AND a.situation_id = NEW.id AND a.status = 'authoritative'
)
BEGIN SELECT RAISE(ABORT, 'current_assessment_id must reference an authoritative attempt owned by the same situation'); END;

-- Installation LLM health learns the controller's own L2 capability. The
-- Situation controller's Assessment dispatch feeds the same installation-
-- level LLM dependency state Acute Triage does (spec: "LLM health remains
-- one installation-level capability state fed by real Acute Triage and
-- Assessment outcomes") under internal/llmhealth's CapabilityAssessment
-- ("assessment"). 0012's llm_health_capabilities.capability CHECK is a
-- closed enum that does not include it; SQLite cannot ALTER a CHECK
-- constraint in place, so this rebuilds the table, preserving every
-- existing row verbatim and widening only the enum. It never edits 0012.
CREATE TABLE llm_health_capabilities_new (
    capability       TEXT    NOT NULL PRIMARY KEY
                     CHECK (capability IN ('triage_draft','verification_rejudge','memory_classifier','query_repair','probe','assessment')),
    healthy          INTEGER NOT NULL CHECK (healthy IN (0, 1)),
    reason_code      TEXT    NOT NULL DEFAULT '',
    detail           TEXT    NOT NULL DEFAULT '',
    last_success_at  TEXT,
    last_failure_at  TEXT,
    unhealthy_since  TEXT,
    content_subjects TEXT    NOT NULL DEFAULT '[]'
                     CHECK (json_valid(content_subjects) AND json_type(content_subjects) = 'array'),
    updated_at       TEXT    NOT NULL
) STRICT;

INSERT INTO llm_health_capabilities_new (
    capability, healthy, reason_code, detail, last_success_at, last_failure_at, unhealthy_since, content_subjects, updated_at
)
SELECT capability, healthy, reason_code, detail, last_success_at, last_failure_at, unhealthy_since, content_subjects, updated_at
FROM llm_health_capabilities;

DROP TABLE llm_health_capabilities;
ALTER TABLE llm_health_capabilities_new RENAME TO llm_health_capabilities;
