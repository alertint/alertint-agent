-- SPDX-License-Identifier: FSL-1.1-ALv2
CREATE TABLE alert_deliveries (
    id                         TEXT NOT NULL PRIMARY KEY CHECK (id <> ''),
    alert_id                   TEXT NOT NULL REFERENCES alerts(id),
    source                     TEXT NOT NULL CHECK (source <> ''),
    source_event_id            TEXT,
    source_episode_key         TEXT NOT NULL CHECK (source_episode_key <> ''),
    status                     TEXT NOT NULL CHECK (status IN ('firing','resolved')),
    labels_json                TEXT NOT NULL CHECK (json_valid(labels_json)),
    annotations_json           TEXT NOT NULL CHECK (json_valid(annotations_json)),
    starts_at                  TEXT NOT NULL CHECK (starts_at <> ''),
    ends_at                    TEXT,
    source_started_at          TEXT,
    source_resolved_at         TEXT,
    started_at_basis           TEXT NOT NULL CHECK (started_at_basis IN ('source_payload','source_api','receipt_fallback','missing','mixed')),
    resolved_at_basis          TEXT NOT NULL CHECK (resolved_at_basis IN ('source_payload','source_api','receipt_fallback','missing','mixed')),
    receiver_grouping_identity TEXT NOT NULL CHECK (receiver_grouping_identity <> ''),
    payload_digest             TEXT NOT NULL CHECK (payload_digest <> ''),
    source_signal_id           TEXT CHECK (source_signal_id IS NULL OR source_signal_id <> ''),
    source_signal_version      TEXT CHECK (source_signal_version IS NULL OR source_signal_version <> ''),
    generator_url              TEXT NOT NULL DEFAULT '',
    acquisition_mode           TEXT NOT NULL CHECK (acquisition_mode IN ('webhook','poll')),
    poll_interval_seconds      INTEGER NOT NULL DEFAULT 0 CHECK (poll_interval_seconds >= 0),
    received_at                TEXT NOT NULL CHECK (received_at <> ''),
    CHECK ((acquisition_mode='webhook' AND poll_interval_seconds=0) OR
           (acquisition_mode='poll' AND poll_interval_seconds>0)),
    CHECK (source_signal_version IS NULL OR source_signal_id IS NOT NULL)
) STRICT;
CREATE INDEX alert_deliveries_episode_idx ON alert_deliveries(source_episode_key, received_at);
CREATE INDEX alert_deliveries_signal_idx ON alert_deliveries(source, source_signal_id, received_at);

CREATE TABLE alert_delivery_dispatches (
    delivery_id     TEXT NOT NULL PRIMARY KEY REFERENCES alert_deliveries(id),
    status          TEXT NOT NULL CHECK (status IN ('pending','claimed','applied','failed')),
    lease_owner     TEXT,
    lease_expires_at TEXT,
    claim_token     INTEGER NOT NULL DEFAULT 0 CHECK (claim_token >= 0),
    attempt_count   INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class TEXT,
    retry_at        TEXT,
    applied_at      TEXT,
    CHECK ((status='claimed') = (lease_owner IS NOT NULL AND lease_expires_at IS NOT NULL)),
    CHECK ((status='applied') = (applied_at IS NOT NULL)),
    CHECK (status!='failed' OR retry_at IS NULL)
) STRICT;
CREATE INDEX alert_delivery_dispatches_claim_idx ON alert_delivery_dispatches(status, retry_at, delivery_id);

CREATE UNIQUE INDEX incidents_one_collecting_group_idx ON incidents(group_key)
    WHERE status='collecting';

CREATE TABLE incident_alert_deliveries (
    incident_id  TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    delivery_id  TEXT NOT NULL UNIQUE REFERENCES alert_deliveries(id),
    occurrence_id INTEGER REFERENCES incident_occurrences(id) ON DELETE SET NULL,
    created_at   TEXT NOT NULL CHECK (created_at <> ''),
    PRIMARY KEY (incident_id, delivery_id)
) STRICT;
CREATE INDEX incident_alert_deliveries_incident_idx ON incident_alert_deliveries(incident_id, created_at);
