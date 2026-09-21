-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 4 bounded evidence preparation: frozen cycles, canonical plans,
-- durable physical-request reservations/outcomes, normalized observation
-- runs/facts (separate from Plan 2's closed situation_facts CHECK), the
-- per-subject/capability refresh cursor, and the ten-day unused-detail
-- retention machinery (ADR-0051). See spec.md "Preparation cycles, request
-- accounting, and reuse" and "Observation history retention".

-- situation_preparation_cycles is one durable, frozen preparation cycle,
-- keyed by (situation_id, input_version, generation). Once created its
-- Draft (anchor/config_digest/profile_version_ids/profile_guidance/
-- allocation) is authoritative forever; a retry loads this row unchanged
-- regardless of what a recomputed draft would now propose. Sealing (by
-- CommitController, in the same transaction as its authoritative state
-- commit) sets sealed=1 and freezes sealed_at; it never un-seals.
CREATE TABLE situation_preparation_cycles (
    id                       TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    situation_id             TEXT    NOT NULL REFERENCES situations(id),
    input_version            INTEGER NOT NULL CHECK (input_version >= 1),
    generation               INTEGER NOT NULL CHECK (generation >= 1),
    anchor                   TEXT    NOT NULL CHECK (anchor <> ''),
    config_digest            TEXT    NOT NULL CHECK (config_digest <> ''),
    profile_version_ids_json TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(profile_version_ids_json) AND json_type(profile_version_ids_json) = 'array'),
    profile_guidance_json    TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(profile_guidance_json) AND json_type(profile_guidance_json) = 'array'),
    max_requests             INTEGER NOT NULL CHECK (max_requests >= 1),
    allocation_json          TEXT    NOT NULL CHECK (json_valid(allocation_json) AND json_type(allocation_json) = 'object'),
    optional_credit_spent    INTEGER NOT NULL DEFAULT 0 CHECK (optional_credit_spent >= 0),
    sealed                   INTEGER NOT NULL DEFAULT 0 CHECK (sealed IN (0, 1)),
    sealed_at                TEXT,
    created_at               TEXT    NOT NULL CHECK (created_at <> ''),
    CHECK ((sealed = 1) = (sealed_at IS NOT NULL)),
    UNIQUE (situation_id, input_version, generation)
) STRICT;
CREATE INDEX situation_preparation_cycles_open_idx ON situation_preparation_cycles(situation_id, sealed);
-- Sealing is the only permitted mutation (0 -> 1); every other column is
-- frozen forever once the row exists. Enforced at the application layer
-- (sealPreparationCycleTx checks sealed=0 before its UPDATE) rather than a
-- trigger, since sealing IS a legitimate single UPDATE this table must
-- allow — a blanket no-update trigger would also block it.
CREATE TRIGGER situation_preparation_cycles_no_delete BEFORE DELETE ON situation_preparation_cycles
BEGIN SELECT RAISE(ABORT, 'preparation cycles are immutable'); END;

-- situation_observation_plans is one canonical, frozen plan belonging to a
-- cycle. Its id is CanonicalPlanID(cycle_id, plan) — a full content digest,
-- never a UUID or retry timestamp.
CREATE TABLE situation_observation_plans (
    id                 TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    cycle_id           TEXT    NOT NULL REFERENCES situation_preparation_cycles(id),
    capability         TEXT    NOT NULL CHECK (capability IN (
                           'store_read', 'prometheus_query', 'zabbix_metric_range',
                           'zabbix_problem_history', 'loki_query', 'sentry_issues', 'change_events'
                       )),
    phase              TEXT    NOT NULL CHECK (phase IN ('lifecycle', 'assessment')),
    scope_json         TEXT    NOT NULL CHECK (json_valid(scope_json) AND json_type(scope_json) = 'object'),
    parameters_json    TEXT    NOT NULL CHECK (json_valid(parameters_json)),
    start_at           TEXT    NOT NULL CHECK (start_at <> ''),
    end_at             TEXT    NOT NULL CHECK (end_at <> ''),
    eligible_at        TEXT    NOT NULL CHECK (eligible_at <> ''),
    limit_count        INTEGER NOT NULL CHECK (limit_count >= 0),
    max_requests       INTEGER NOT NULL CHECK (max_requests >= 0),
    purpose            TEXT    NOT NULL CHECK (purpose <> ''),
    reconsider_on_json TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(reconsider_on_json) AND json_type(reconsider_on_json) = 'array'),
    stop_on_json       TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(stop_on_json) AND json_type(stop_on_json) = 'array'),
    created_at         TEXT    NOT NULL CHECK (created_at <> '')
) STRICT;
CREATE INDEX situation_observation_plans_cycle_idx ON situation_observation_plans(cycle_id);
CREATE TRIGGER situation_observation_plans_no_update BEFORE UPDATE ON situation_observation_plans
BEGIN SELECT RAISE(ABORT, 'observation plans are immutable'); END;
CREATE TRIGGER situation_observation_plans_no_delete BEFORE DELETE ON situation_observation_plans
BEGIN SELECT RAISE(ABORT, 'observation plans are immutable'); END;

-- situation_observation_requests is the durable, pre-dispatch reservation
-- for exactly one physical request. ordinal is a per-cycle monotonically
-- increasing counter (1..N across every plan in the cycle), which trivially
-- also satisfies plan-scoped uniqueness (a subset of a unique set is
-- unique). A crash after this INSERT but before an outcome is recorded
-- still durably consumes the slot.
CREATE TABLE situation_observation_requests (
    id          TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    cycle_id    TEXT    NOT NULL REFERENCES situation_preparation_cycles(id),
    plan_id     TEXT    NOT NULL REFERENCES situation_observation_plans(id),
    ordinal     INTEGER NOT NULL CHECK (ordinal >= 1),
    reserved_at TEXT    NOT NULL CHECK (reserved_at <> ''),
    UNIQUE (cycle_id, ordinal),
    UNIQUE (plan_id, ordinal)
) STRICT;
CREATE INDEX situation_observation_requests_cycle_idx ON situation_observation_requests(cycle_id);
CREATE INDEX situation_observation_requests_plan_idx ON situation_observation_requests(plan_id);
CREATE TRIGGER situation_observation_requests_no_update BEFORE UPDATE ON situation_observation_requests
BEGIN SELECT RAISE(ABORT, 'observation request reservations are immutable'); END;
CREATE TRIGGER situation_observation_requests_no_delete BEFORE DELETE ON situation_observation_requests
BEGIN SELECT RAISE(ABORT, 'observation request reservations are immutable'); END;

-- situation_observation_request_outcomes finishes one reservation. It may
-- append even after the owning Situation's claim is lost (the reservation
-- identity it references is already immutable, and the outcome accounts
-- for work that really happened) — so it carries no Fence of its own.
CREATE TABLE situation_observation_request_outcomes (
    reservation_id  TEXT NOT NULL PRIMARY KEY REFERENCES situation_observation_requests(id),
    request_started TEXT NOT NULL CHECK (request_started IN ('true', 'false', 'unknown')),
    code            TEXT NOT NULL CHECK (code <> ''),
    completed_at    TEXT NOT NULL CHECK (completed_at <> '')
) STRICT;
CREATE TRIGGER situation_observation_request_outcomes_no_update BEFORE UPDATE ON situation_observation_request_outcomes
BEGIN SELECT RAISE(ABORT, 'observation request outcomes are immutable'); END;
CREATE TRIGGER situation_observation_request_outcomes_no_delete BEFORE DELETE ON situation_observation_request_outcomes
BEGIN SELECT RAISE(ABORT, 'observation request outcomes are immutable'); END;

-- situation_observation_runs is one completed (or explicitly limited/
-- failed) execution of a plan. At most one durable run per plan (UNIQUE
-- plan_id) — a retry replays the SAME run under the SAME id, never
-- appending a second row. completed_at is this store's own durable
-- completion clock (the ADR-0051 retention anchor), set once on first
-- commit and never touched again. Run metadata rows are permanent; only
-- their fact VALUE payloads (situation_observation_fact_payloads) are ever
-- deleted, through the guarded retention path below.
CREATE TABLE situation_observation_runs (
    id                     TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    cycle_id               TEXT    NOT NULL REFERENCES situation_preparation_cycles(id),
    plan_id                TEXT    NOT NULL UNIQUE REFERENCES situation_observation_plans(id),
    status                 TEXT    NOT NULL CHECK (status IN (
                               'confirmed_value', 'confirmed_empty', 'unconfirmed_empty', 'unavailable',
                               'failed', 'stale', 'truncated', 'withheld_by_budget', 'vocabulary_unresolved'
                           )),
    coverage_start         TEXT    NOT NULL CHECK (coverage_start <> ''),
    coverage_end           TEXT    NOT NULL CHECK (coverage_end <> ''),
    coverage_complete      INTEGER NOT NULL CHECK (coverage_complete IN (0, 1)),
    coverage_returned      INTEGER NOT NULL CHECK (coverage_returned >= 0),
    coverage_omitted       INTEGER NOT NULL CHECK (coverage_omitted >= 0),
    limitation_codes_json  TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(limitation_codes_json) AND json_type(limitation_codes_json) = 'array'),
    observed_at            TEXT    NOT NULL CHECK (observed_at <> ''),
    expires_at             TEXT    NOT NULL CHECK (expires_at <> ''),
    completed_at           TEXT    NOT NULL CHECK (completed_at <> ''),
    reused_from_run_id     TEXT REFERENCES situation_observation_runs(id)
) STRICT;
CREATE INDEX situation_observation_runs_cycle_idx ON situation_observation_runs(cycle_id);
CREATE INDEX situation_observation_runs_completed_idx ON situation_observation_runs(completed_at);
CREATE TRIGGER situation_observation_runs_no_update BEFORE UPDATE ON situation_observation_runs
BEGIN SELECT RAISE(ABORT, 'observation run metadata is immutable'); END;
CREATE TRIGGER situation_observation_runs_no_delete BEFORE DELETE ON situation_observation_runs
BEGIN SELECT RAISE(ABORT, 'observation run metadata is immutable'); END;

-- situation_observation_facts is one run's normalized, typed observations —
-- immutable metadata forever, separate from the expirable Value payload
-- (situation_observation_fact_payloads) so ten-day detail expiry never
-- touches identity, digests, or accounting. A reused run cites the
-- ORIGINAL run's facts (via situation_observation_runs.reused_from_run_id);
-- it never duplicates fact rows.
CREATE TABLE situation_observation_facts (
    id                 TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    run_id             TEXT    NOT NULL REFERENCES situation_observation_runs(id),
    kind               TEXT    NOT NULL CHECK (kind IN (
                           'metric_summary', 'log_summary', 'error_issue', 'change_event',
                           'problem_episode', 'source_lifecycle', 'source_definition', 'capability_result'
                       )),
    subject            TEXT    NOT NULL CHECK (subject <> ''),
    digest             TEXT    NOT NULL CHECK (digest <> ''),
    schema_version     INTEGER NOT NULL CHECK (schema_version >= 1),
    result_status      TEXT    NOT NULL CHECK (result_status IN (
                           'confirmed_value', 'confirmed_empty', 'unconfirmed_empty', 'unavailable',
                           'failed', 'stale', 'truncated', 'withheld_by_budget', 'vocabulary_unresolved'
                       )),
    freshness          TEXT    NOT NULL CHECK (freshness IN ('fresh', 'stale', 'unknown')),
    observed_at        TEXT    NOT NULL CHECK (observed_at <> ''),
    expires_at         TEXT    NOT NULL CHECK (expires_at <> ''),
    evidence_refs_json TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(evidence_refs_json) AND json_type(evidence_refs_json) = 'array'),
    material           INTEGER NOT NULL CHECK (material IN (0, 1))
) STRICT;
CREATE INDEX situation_observation_facts_run_idx ON situation_observation_facts(run_id);
CREATE TRIGGER situation_observation_facts_no_update BEFORE UPDATE ON situation_observation_facts
BEGIN SELECT RAISE(ABORT, 'observation facts are immutable'); END;
CREATE TRIGGER situation_observation_facts_no_delete BEFORE DELETE ON situation_observation_facts
BEGIN SELECT RAISE(ABORT, 'observation facts are immutable'); END;

-- situation_observation_fact_payloads holds one fact's actual normalized
-- Value — the ONLY row this slice ever deletes, and only through the
-- guarded ten-day retention transaction (which rechecks references and
-- appends situation_observation_detail_expirations atomically with the
-- delete). No trigger forbids DELETE here; UPDATE remains forbidden, since
-- an existing payload is never edited in place.
CREATE TABLE situation_observation_fact_payloads (
    fact_id    TEXT NOT NULL PRIMARY KEY REFERENCES situation_observation_facts(id),
    value_json TEXT NOT NULL CHECK (json_valid(value_json))
) STRICT;
CREATE TRIGGER situation_observation_fact_payloads_no_update BEFORE UPDATE ON situation_observation_fact_payloads
BEGIN SELECT RAISE(ABORT, 'observation fact payloads cannot be edited in place'); END;

-- situation_observation_refresh is the per-subject/capability admission
-- cursor: it survives cycles, generations, and input versions (never
-- deleted), so a superseded or replaced cycle cannot bypass source cadence
-- and re-admit the same subject/capability immediately. admitted_cycle_id
-- names the cycle that first admitted the CURRENT freshness window (for
-- audit only).
CREATE TABLE situation_observation_refresh (
    situation_id      TEXT NOT NULL REFERENCES situations(id),
    subject           TEXT NOT NULL CHECK (subject <> ''),
    capability        TEXT NOT NULL CHECK (capability <> ''),
    scope_digest      TEXT NOT NULL CHECK (scope_digest <> ''),
    last_served_at    TEXT NOT NULL CHECK (last_served_at <> ''),
    next_refresh_at   TEXT NOT NULL CHECK (next_refresh_at <> ''),
    admitted_cycle_id TEXT REFERENCES situation_preparation_cycles(id),
    PRIMARY KEY (situation_id, subject, capability, scope_digest)
) STRICT;
CREATE INDEX situation_observation_refresh_due_idx ON situation_observation_refresh(situation_id, next_refresh_at);

-- situation_observation_references records one typed, owning reference
-- that protects a run's fact payloads from ten-day expiry: a dispatched
-- (including rejected) Assessment attempt, a committed lifecycle decision
-- or Transition, or the situation's own current/open-cycle pointer.
-- "permanent" references (attempt/decision/transition) never expire;
-- "temporary" ones (current_cycle/open_cycle) are superseded when the
-- pointer moves on, at which point the ORIGINAL run's own completion time
-- still governs eligibility (no fresh ten-day period starts).
CREATE TABLE situation_observation_references (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    run_id         TEXT    NOT NULL REFERENCES situation_observation_runs(id),
    reference_kind TEXT    NOT NULL CHECK (reference_kind IN (
                       'assessment_attempt', 'lifecycle_decision', 'transition', 'current_cycle', 'open_cycle'
                   )),
    owner_id       TEXT    NOT NULL CHECK (owner_id <> ''),
    permanent      INTEGER NOT NULL CHECK (permanent IN (0, 1)),
    superseded     INTEGER NOT NULL DEFAULT 0 CHECK (superseded IN (0, 1)),
    created_at     TEXT    NOT NULL CHECK (created_at <> ''),
    CHECK (permanent = 1 OR reference_kind IN ('current_cycle', 'open_cycle'))
) STRICT;
CREATE INDEX situation_observation_references_run_idx ON situation_observation_references(run_id, superseded);
CREATE TRIGGER situation_observation_references_no_delete BEFORE DELETE ON situation_observation_references
BEGIN SELECT RAISE(ABORT, 'observation references are append-only'); END;

-- situation_observation_detail_expirations is the append-only cleanup
-- completion record: one row per run whose fact payloads have been
-- expired. Its existence is what ListObservationRuns/RunRecord uses to
-- report detail_state=expired.
CREATE TABLE situation_observation_detail_expirations (
    run_id     TEXT NOT NULL PRIMARY KEY REFERENCES situation_observation_runs(id),
    expired_at TEXT NOT NULL CHECK (expired_at <> '')
) STRICT;
CREATE TRIGGER situation_observation_detail_expirations_no_update BEFORE UPDATE ON situation_observation_detail_expirations
BEGIN SELECT RAISE(ABORT, 'detail expiration records are immutable'); END;
CREATE TRIGGER situation_observation_detail_expirations_no_delete BEFORE DELETE ON situation_observation_detail_expirations
BEGIN SELECT RAISE(ABORT, 'detail expiration records are immutable'); END;

-- Extend situations (0014) with the preparation generation counter, the
-- current-cycle pointer the bounded Situation detail view reads, and the
-- durable investigative-fairness credit (spec.md "Defaults and hard
-- limits": a fixed one-third request allowance accrued across refresh
-- rounds, capped at 3x the cycle's request cap). All default to "no
-- preparation yet" so existing rows upgrade cleanly.
ALTER TABLE situations ADD COLUMN preparation_generation INTEGER NOT NULL DEFAULT 0 CHECK (preparation_generation >= 0);
ALTER TABLE situations ADD COLUMN current_preparation_cycle_id TEXT REFERENCES situation_preparation_cycles(id);
ALTER TABLE situations ADD COLUMN investigation_credit INTEGER NOT NULL DEFAULT 0 CHECK (investigation_credit >= 0);
ALTER TABLE situations ADD COLUMN investigation_credit_accrued_at TEXT;
