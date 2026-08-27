-- 0012_llm_health.sql
-- Installation-level LLM dependency health. One aggregate row (id = 1) plus
-- one row per observed capability. Owned by internal/llmhealth; nothing here
-- references Situations. Details are sanitized reason text, never provider
-- bodies, prompts, headers, or credentials.

CREATE TABLE llm_health (
    id                   INTEGER PRIMARY KEY CHECK (id = 1),
    state                TEXT    NOT NULL CHECK (state IN ('healthy','degraded','unavailable')),
    reason_code          TEXT    NOT NULL DEFAULT '',
    detail               TEXT    NOT NULL DEFAULT '',
    unhealthy_since      TEXT,
    outage_generation    INTEGER NOT NULL DEFAULT 0,
    last_real_success_at TEXT,
    last_real_call_at    TEXT,
    last_probe_at        TEXT,
    last_probe_outcome   TEXT    NOT NULL DEFAULT '',
    slack_ts             TEXT    NOT NULL DEFAULT '',
    slack_channel        TEXT    NOT NULL DEFAULT '',
    slack_delivery       TEXT    NOT NULL DEFAULT 'none'
                         CHECK (slack_delivery IN ('none','pending','delivered','recovery_pending','recovered','suppressed')),
    slack_state          TEXT    NOT NULL DEFAULT '',
    slack_generation     INTEGER NOT NULL DEFAULT 0,
    recovered_at         TEXT,
    updated_at           TEXT    NOT NULL
) STRICT;

INSERT INTO llm_health (id, state, updated_at)
VALUES (1, 'healthy', strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

CREATE TABLE llm_health_capabilities (
    capability       TEXT    NOT NULL PRIMARY KEY
                     CHECK (capability IN ('triage_draft','verification_rejudge','memory_classifier','probe')),
    healthy          INTEGER NOT NULL CHECK (healthy IN (0, 1)),
    reason_code      TEXT    NOT NULL DEFAULT '',
    detail           TEXT    NOT NULL DEFAULT '',
    last_success_at  TEXT,
    last_failure_at  TEXT,
    unhealthy_since  TEXT,
    -- content_subjects is the bounded (<= 8) JSON array of distinct Incident
    -- IDs that content-class-failed this capability since its last success —
    -- the H1 two-distinct-Incident corroboration evidence. Durable so an
    -- outage spanning a restart still corroborates correctly instead of
    -- silently resetting to zero uncorroborated failures.
    content_subjects TEXT    NOT NULL DEFAULT '[]',
    updated_at       TEXT    NOT NULL
) STRICT;
