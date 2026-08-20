-- Immutable accepted alert deliveries and their durable correlation outbox.
-- The alerts table remains the compatibility latest-wins projection; every
-- accepted source delivery is retained here for replay and audit.

CREATE TABLE alert_deliveries (
    id                          TEXT NOT NULL PRIMARY KEY,
    alert_id                    TEXT NOT NULL REFERENCES alerts(id),
    source                      TEXT NOT NULL CHECK (source <> ''),
    source_event_id             TEXT,
    source_episode_key          TEXT NOT NULL CHECK (source_episode_key <> ''),
    status                      TEXT NOT NULL CHECK (status IN ('firing','resolved')),
    labels_json                 TEXT NOT NULL,
    annotations_json            TEXT NOT NULL,
    starts_at                   TEXT NOT NULL,
    ends_at                     TEXT,
    source_started_at           TEXT,
    source_resolved_at          TEXT,
    started_at_basis            TEXT NOT NULL CHECK (started_at_basis IN ('source_payload','source_api','receipt_fallback','missing','mixed')),
    resolved_at_basis           TEXT NOT NULL CHECK (resolved_at_basis IN ('source_payload','source_api','receipt_fallback','missing','mixed')),
    receiver_grouping_identity  TEXT NOT NULL CHECK (receiver_grouping_identity <> ''),
    payload_digest              TEXT NOT NULL CHECK (payload_digest <> ''),
    received_at                 TEXT NOT NULL
) STRICT;

CREATE INDEX alert_deliveries_source_episode_key_idx ON alert_deliveries(source_episode_key);
CREATE INDEX alert_deliveries_received_at_idx ON alert_deliveries(received_at);

CREATE TABLE alert_delivery_dispatches (
    delivery_id TEXT PRIMARY KEY REFERENCES alert_deliveries(id),
    status TEXT NOT NULL CHECK (status IN ('pending','claimed','applied','failed')),
    lease_owner TEXT,
    lease_expires_at TEXT,
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class TEXT,
    retry_at TEXT,
    applied_at TEXT
) STRICT;

CREATE INDEX alert_delivery_dispatches_status_retry_at_idx ON alert_delivery_dispatches(status, retry_at);

CREATE TABLE incident_alert_deliveries (
    incident_id  TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    delivery_id  TEXT NOT NULL UNIQUE REFERENCES alert_deliveries(id),
    created_at   TEXT NOT NULL,
    PRIMARY KEY (incident_id, delivery_id)
) STRICT;

CREATE INDEX incident_alert_deliveries_incident_id_idx ON incident_alert_deliveries(incident_id);
