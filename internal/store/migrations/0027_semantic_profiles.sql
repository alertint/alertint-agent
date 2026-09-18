-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 4 Task 7: durable advisory semantic-profile inference — the
-- append-only delivery-to-signature mapping, immutable versions and their
-- CAS-protected head, the deduplicated inference-job/call/outcome ledger,
-- and the head-change fan-out outbox. See spec.md "Source identity and
-- advisory signatures" and "Durable semantic-profile inference".

-- delivery_semantic_signatures is one immutable mapping per delivery (never
-- updated once inserted — an Alert's proven identity fields never change
-- after the fact) from an alert_deliveries row to its deterministic
-- advisory signature (internal/semanticprofile.BuildSignature's own output).
CREATE TABLE delivery_semantic_signatures (
    delivery_id      TEXT    NOT NULL PRIMARY KEY REFERENCES alert_deliveries(id),
    signature_key    TEXT    NOT NULL CHECK (signature_key <> ''),
    signature_digest TEXT    NOT NULL CHECK (signature_digest <> ''),
    schema_version   INTEGER NOT NULL CHECK (schema_version >= 1),
    material_json    TEXT    NOT NULL CHECK (json_valid(material_json)),
    mode             TEXT    NOT NULL CHECK (mode IN ('signal_version', 'signal_id_only', 'fallback')),
    advisory_only    INTEGER NOT NULL CHECK (advisory_only IN (0, 1)),
    created_at       TEXT    NOT NULL CHECK (created_at <> '')
) STRICT;
CREATE INDEX delivery_semantic_signatures_signature_idx ON delivery_semantic_signatures(signature_key);
CREATE TRIGGER delivery_semantic_signatures_no_update BEFORE UPDATE ON delivery_semantic_signatures
BEGIN SELECT RAISE(ABORT, 'delivery semantic signatures are immutable'); END;
CREATE TRIGGER delivery_semantic_signatures_no_delete BEFORE DELETE ON delivery_semantic_signatures
BEGIN SELECT RAISE(ABORT, 'delivery semantic signatures are immutable'); END;

-- semantic_profile_versions is one immutable Profile version — model
-- inference output or an operator correction. Versions are never edited or
-- superseded in place; semantic_profile_heads (below) is the only mutable
-- projection.
CREATE TABLE semantic_profile_versions (
    id                    TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    signature_key         TEXT    NOT NULL CHECK (signature_key <> ''),
    version               INTEGER NOT NULL CHECK (version >= 1),
    schema_version        INTEGER NOT NULL CHECK (schema_version >= 1),
    prompt_version        INTEGER NOT NULL CHECK (prompt_version >= 1),
    semantic_input_digest TEXT    NOT NULL CHECK (semantic_input_digest <> ''),
    origin                TEXT    NOT NULL CHECK (origin IN ('inferred', 'correction')),
    provider              TEXT    NOT NULL DEFAULT '',
    model                 TEXT    NOT NULL DEFAULT '',
    usage_input_tokens    INTEGER NOT NULL DEFAULT 0 CHECK (usage_input_tokens >= 0),
    usage_output_tokens   INTEGER NOT NULL DEFAULT 0 CHECK (usage_output_tokens >= 0),
    profile_json          TEXT    NOT NULL CHECK (json_valid(profile_json)),
    created_at            TEXT    NOT NULL CHECK (created_at <> ''),
    asserted_by           TEXT    NOT NULL DEFAULT '',
    CHECK ((origin = 'correction') = (asserted_by <> '')),
    UNIQUE (signature_key, version)
) STRICT;
CREATE TRIGGER semantic_profile_versions_no_update BEFORE UPDATE ON semantic_profile_versions
BEGIN SELECT RAISE(ABORT, 'semantic profile versions are immutable'); END;
CREATE TRIGGER semantic_profile_versions_no_delete BEFORE DELETE ON semantic_profile_versions
BEGIN SELECT RAISE(ABORT, 'semantic profile versions are immutable'); END;

-- semantic_profile_heads is the one mutable, CAS-protected "current version"
-- projection per signature. current_version is the expected-version CAS
-- CorrectSemanticProfile compares against; version_id names the immutable
-- row it currently points at.
CREATE TABLE semantic_profile_heads (
    signature_key   TEXT    NOT NULL PRIMARY KEY,
    current_version INTEGER NOT NULL CHECK (current_version >= 1),
    version_id      TEXT    NOT NULL REFERENCES semantic_profile_versions(id),
    updated_at      TEXT    NOT NULL CHECK (updated_at <> '')
) STRICT;

-- semantic_profile_inference_jobs is deduplicated by (signature_key,
-- frozen_input_digest): the same frozen semantic input never gets a second
-- job. max_attempts freezes the configured cap onto the row at creation
-- (mirroring situation_preparation_cycles.max_requests) so RecoverSemanticInference
-- can decide exhaustion from the row alone. The partial unique index below
-- enforces "at most one LIVE job per signature" (a signature may still have
-- many historical complete/exhausted job rows).
CREATE TABLE semantic_profile_inference_jobs (
    id                    TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    signature_key         TEXT    NOT NULL CHECK (signature_key <> ''),
    frozen_input_json     TEXT    NOT NULL CHECK (json_valid(frozen_input_json)),
    frozen_input_digest   TEXT    NOT NULL CHECK (frozen_input_digest <> ''),
    expected_head_version INTEGER NOT NULL DEFAULT 0 CHECK (expected_head_version >= 0),
    status                TEXT    NOT NULL CHECK (status IN ('pending', 'running', 'complete', 'exhausted')),
    attempt               INTEGER NOT NULL DEFAULT 0 CHECK (attempt >= 0),
    max_attempts          INTEGER NOT NULL CHECK (max_attempts >= 1),
    owner                 TEXT,
    token                 INTEGER NOT NULL DEFAULT 0 CHECK (token >= 0),
    lease_expires_at      TEXT,
    retry_at              TEXT,
    error_class           TEXT,
    created_at            TEXT    NOT NULL CHECK (created_at <> ''),
    CHECK (status != 'running' OR (owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    UNIQUE (signature_key, frozen_input_digest)
) STRICT;
CREATE UNIQUE INDEX semantic_profile_inference_jobs_live_idx ON semantic_profile_inference_jobs(signature_key)
    WHERE status IN ('pending', 'running');
CREATE INDEX semantic_profile_inference_jobs_due_idx ON semantic_profile_inference_jobs(status, retry_at);

-- semantic_profile_calls/semantic_profile_call_outcomes mirror Task 2's own
-- request-reservation/outcome split: one immutable reservation per
-- dispatched CompleteOnce attempt (durably consuming its attempt slot the
-- instant it is reserved, before the request), and an immutable outcome
-- committed after.
CREATE TABLE semantic_profile_calls (
    id            TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    job_id        TEXT    NOT NULL REFERENCES semantic_profile_inference_jobs(id),
    attempt       INTEGER NOT NULL CHECK (attempt >= 1),
    dispatched_at TEXT    NOT NULL CHECK (dispatched_at <> ''),
    UNIQUE (job_id, attempt)
) STRICT;
CREATE TRIGGER semantic_profile_calls_no_update BEFORE UPDATE ON semantic_profile_calls
BEGIN SELECT RAISE(ABORT, 'semantic profile calls are immutable'); END;
CREATE TRIGGER semantic_profile_calls_no_delete BEFORE DELETE ON semantic_profile_calls
BEGIN SELECT RAISE(ABORT, 'semantic profile calls are immutable'); END;

CREATE TABLE semantic_profile_call_outcomes (
    call_id             TEXT    NOT NULL PRIMARY KEY REFERENCES semantic_profile_calls(id),
    outcome             TEXT    NOT NULL CHECK (outcome IN ('accepted', 'rejected', 'malformed', 'failed', 'stale')),
    request_started     TEXT    NOT NULL CHECK (request_started IN ('true', 'false', 'unknown')),
    usage_input_tokens  INTEGER NOT NULL DEFAULT 0 CHECK (usage_input_tokens >= 0),
    usage_output_tokens INTEGER NOT NULL DEFAULT 0 CHECK (usage_output_tokens >= 0),
    provider            TEXT    NOT NULL DEFAULT '',
    model               TEXT    NOT NULL DEFAULT '',
    completed_at        TEXT    NOT NULL CHECK (completed_at <> '')
) STRICT;
CREATE TRIGGER semantic_profile_call_outcomes_no_update BEFORE UPDATE ON semantic_profile_call_outcomes
BEGIN SELECT RAISE(ABORT, 'semantic profile call outcomes are immutable'); END;
CREATE TRIGGER semantic_profile_call_outcomes_no_delete BEFORE DELETE ON semantic_profile_call_outcomes
BEGIN SELECT RAISE(ABORT, 'semantic profile call outcomes are immutable'); END;

-- semantic_profile_changes is one head-advancement outbox row (both an
-- inferred acceptance and a correction create one). fan_out_cursor is the
-- last situation_id a paginated fan-out batch (100/transaction) has already
-- delivered to; acknowledged flips once the cursor has exhausted every
-- matching nonterminal Situation.
CREATE TABLE semantic_profile_changes (
    id             TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    signature_key  TEXT    NOT NULL CHECK (signature_key <> ''),
    version_id     TEXT    NOT NULL REFERENCES semantic_profile_versions(id),
    fan_out_cursor TEXT,
    acknowledged   INTEGER NOT NULL DEFAULT 0 CHECK (acknowledged IN (0, 1)),
    created_at     TEXT    NOT NULL CHECK (created_at <> '')
) STRICT;
CREATE INDEX semantic_profile_changes_pending_idx ON semantic_profile_changes(acknowledged, id);

-- semantic_profile_change_deliveries records one unique (change, situation)
-- fan-out delivery — the "delivered exactly once" guarantee.
CREATE TABLE semantic_profile_change_deliveries (
    change_id    TEXT NOT NULL REFERENCES semantic_profile_changes(id),
    situation_id TEXT NOT NULL REFERENCES situations(id),
    delivered_at TEXT NOT NULL CHECK (delivered_at <> '')
) STRICT;
CREATE UNIQUE INDEX semantic_profile_change_once ON semantic_profile_change_deliveries(change_id, situation_id);
