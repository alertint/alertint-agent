-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Durable notification intents (persisted before every outward Slack
-- effect, including the two installation-level surfaces that have no
-- owning Situation), one installation-level dependency-health record per
-- dependency, and the stable Slack coordinates each editable surface needs
-- for idempotent updates.

CREATE TABLE notification_intents (
    id                    TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    idempotency_key       TEXT    NOT NULL UNIQUE CHECK (idempotency_key <> ''),
    subject_kind          TEXT    NOT NULL CHECK (subject_kind IN ('situation', 'dependency_health', 'expected_behavior_envelope')),
    subject_id            TEXT    NOT NULL CHECK (subject_id <> ''),
    situation_id          TEXT    REFERENCES situations(id),
    transition_id         TEXT,
    kind                  TEXT    NOT NULL CHECK (kind IN (
        'situation_root_create', 'situation_root_edit', 'situation_thread_reply',
        'situation_broadcast_reply', 'health_root', 'health_update', 'envelope_review'
    )),
    main_channel_poke     INTEGER NOT NULL CHECK (main_channel_poke IN (0, 1)),
    interruption_priority TEXT    CHECK (interruption_priority IS NULL OR interruption_priority IN ('low', 'medium', 'high', 'critical')),
    status                TEXT    NOT NULL CHECK (status IN ('pending', 'delivered', 'failed', 'withheld_by_operator_slack_floor')),
    channel               TEXT,
    message_ts            TEXT,
    client_msg_id         TEXT    NOT NULL CHECK (client_msg_id <> ''),
    attempt_count         INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class      TEXT,
    retry_at              TEXT,
    created_at            TEXT    NOT NULL CHECK (created_at <> ''),
    delivered_at          TEXT,
    -- A Situation intent carries situation_id; the two installation-level
    -- surfaces (dependency_health, expected_behavior_envelope) forbid it.
    CHECK ((subject_kind = 'situation') = (situation_id IS NOT NULL)),
    -- kind and subject_kind must agree.
    CHECK (
        (kind IN ('situation_root_create', 'situation_root_edit', 'situation_thread_reply', 'situation_broadcast_reply') AND subject_kind = 'situation')
        OR (kind IN ('health_root', 'health_update') AND subject_kind = 'dependency_health')
        OR (kind = 'envelope_review' AND subject_kind = 'expected_behavior_envelope')
    ),
    -- Every main-channel poke requires an Interruption priority; every
    -- non-poke root edit or thread reply leaves it null.
    CHECK ((main_channel_poke = 1) = (interruption_priority IS NOT NULL)),
    -- A withheld intent was always going to be a poke — withholding never
    -- rewrites a quiet root edit's status.
    CHECK (status != 'withheld_by_operator_slack_floor' OR main_channel_poke = 1),
    CHECK ((status = 'delivered') = (delivered_at IS NOT NULL)),
    CHECK (status != 'delivered' OR (channel IS NOT NULL AND message_ts IS NOT NULL))
) STRICT;

CREATE INDEX notification_intents_claim_idx
    ON notification_intents(status, retry_at, created_at)
    WHERE status = 'pending';

CREATE INDEX notification_intents_situation_idx
    ON notification_intents(situation_id, created_at)
    WHERE situation_id IS NOT NULL;

CREATE TRIGGER notification_intents_no_delete
BEFORE DELETE ON notification_intents
BEGIN
    SELECT RAISE(ABORT, 'notification intents are immutable once created');
END;

-- One durable installation-level state per dependency so a shared outage
-- produces at most one health root plus one recovery update rather than
-- fanning out into a per-Situation notice.
CREATE TABLE dependency_health (
    dependency        TEXT NOT NULL PRIMARY KEY CHECK (dependency <> ''),
    status            TEXT NOT NULL CHECK (status IN ('healthy', 'degraded', 'unavailable')),
    degraded_since    TEXT,
    last_broadcast_at TEXT,
    recovered_at      TEXT,
    slack_channel     TEXT,
    slack_message_ts  TEXT,
    updated_at        TEXT NOT NULL CHECK (updated_at <> ''),
    CHECK ((status = 'healthy') = (degraded_since IS NULL)),
    CHECK ((slack_channel IS NULL) = (slack_message_ts IS NULL))
) STRICT;

-- Stable Slack coordinates for the Situation's one immutable root, so a
-- later edit targets the exact persisted channel/message rather than
-- re-deriving it. Set once, at first publication.
ALTER TABLE situations ADD COLUMN slack_channel TEXT;
ALTER TABLE situations ADD COLUMN slack_root_ts TEXT;

-- Stable Slack coordinates for the envelope's most recent review reminder.
-- The reminder is a standalone message the review flow never edits in
-- place, but the durable subject row still records where it landed —
-- consistent with the health/root coordinate contract and useful for
-- audit/troubleshooting.
ALTER TABLE expected_behavior_envelopes ADD COLUMN slack_channel TEXT;
ALTER TABLE expected_behavior_envelopes ADD COLUMN slack_message_ts TEXT;
