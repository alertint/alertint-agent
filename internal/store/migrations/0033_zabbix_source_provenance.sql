-- SPDX-License-Identifier: FSL-1.1-ALv2

-- The installation identity is ingress-time truth. Existing deliveries stay
-- NULL: a later API configuration must never be backfilled as historical
-- proof for an already accepted webhook.
ALTER TABLE alert_deliveries
    ADD COLUMN source_instance_id TEXT
    CHECK (source_instance_id IS NULL OR source_instance_id <> '');

-- Immutable source-definition observations remain available after generic
-- fact payload retention expires. They hold only bounded digests and source
-- identifiers, never raw expressions, macros, credentials, or full config.
CREATE TABLE zabbix_source_observations (
    id                     TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    fact_id                TEXT    NOT NULL UNIQUE REFERENCES situation_observation_facts(id) ON DELETE RESTRICT,
    run_id                 TEXT    NOT NULL REFERENCES situation_observation_runs(id) ON DELETE RESTRICT,
    situation_id           TEXT    NOT NULL REFERENCES situations(id) ON DELETE RESTRICT,
    source_key             TEXT    NOT NULL CHECK (source_key <> ''),
    source_instance_id     TEXT,
    rule_id                TEXT    NOT NULL CHECK (rule_id <> ''),
    host                   TEXT    NOT NULL CHECK (host <> ''),
    endpoint_id            TEXT,
    available              INTEGER NOT NULL CHECK (available IN (0,1)),
    version_algorithm      TEXT,
    version_value          TEXT,
    unavailable_reason     TEXT,
    content_digest         TEXT    NOT NULL CHECK (content_digest <> ''),
    component_digests_json TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(component_digests_json) AND json_type(component_digests_json) = 'object'),
    trigger_ids_json       TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(trigger_ids_json) AND json_type(trigger_ids_json) = 'array'),
    item_ids_json          TEXT    NOT NULL DEFAULT '[]' CHECK (json_valid(item_ids_json) AND json_type(item_ids_json) = 'array'),
    observed_at            TEXT    NOT NULL CHECK (observed_at <> ''),
    expires_at             TEXT    NOT NULL CHECK (expires_at <> ''),
    CHECK (source_instance_id IS NULL OR source_instance_id <> ''),
    CHECK ((available = 1 AND endpoint_id IS NOT NULL AND version_algorithm IS NOT NULL AND version_value IS NOT NULL AND unavailable_reason IS NULL)
        OR (available = 0 AND version_algorithm IS NULL AND version_value IS NULL AND unavailable_reason IS NOT NULL))
) STRICT;
CREATE INDEX zabbix_source_observations_history_idx
    ON zabbix_source_observations(situation_id, observed_at, id);
CREATE TRIGGER zabbix_source_observations_immutable BEFORE UPDATE ON zabbix_source_observations
BEGIN SELECT RAISE(ABORT, 'zabbix source observations are immutable'); END;
CREATE TRIGGER zabbix_source_observations_no_delete BEFORE DELETE ON zabbix_source_observations
BEGIN SELECT RAISE(ABORT, 'zabbix source observations are immutable'); END;

-- The head always points at the newest observation, including an explicit
-- failure. A failed or expired current read can therefore never fall back to
-- an older successful version.
CREATE TABLE zabbix_source_observation_heads (
    situation_id  TEXT NOT NULL REFERENCES situations(id) ON DELETE RESTRICT,
    source_key    TEXT NOT NULL CHECK (source_key <> ''),
    observation_id TEXT NOT NULL UNIQUE REFERENCES zabbix_source_observations(id) ON DELETE RESTRICT,
    updated_at    TEXT NOT NULL CHECK (updated_at <> ''),
    PRIMARY KEY (situation_id, source_key)
) STRICT;
CREATE TRIGGER zabbix_source_observation_heads_no_delete BEFORE DELETE ON zabbix_source_observation_heads
BEGIN SELECT RAISE(ABORT, 'zabbix source observation heads are durable'); END;
