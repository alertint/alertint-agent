-- SPDX-License-Identifier: FSL-1.1-ALv2

-- Extend the proven-current observation ledger without rewriting immutable
-- Zabbix history. Existing rows retain source='zabbix'.
ALTER TABLE zabbix_source_observations ADD COLUMN source TEXT NOT NULL DEFAULT 'zabbix'
    CHECK (source IN ('zabbix','alertmanager'));
ALTER TABLE zabbix_source_observations ADD COLUMN producer_id TEXT;
ALTER TABLE zabbix_source_observations ADD COLUMN rule_group TEXT;
ALTER TABLE zabbix_source_observations ADD COLUMN presence TEXT
    CHECK (presence IS NULL OR presence IN ('present','absent','unknown'));
ALTER TABLE zabbix_source_observations ADD COLUMN scope_labels_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(scope_labels_json) AND json_type(scope_labels_json)='object');

-- Migration 0034 constrained its original source columns to Zabbix. Retain
-- those columns only as a schema bridge; every 0037-aware reader must use the
-- authoritative source-neutral fields below. They also preserve revoked heads,
-- whose current revision intentionally has no policy_json to reconstruct from.
ALTER TABLE expected_behavior_envelope_heads ADD COLUMN source_v2 TEXT
    CHECK (source_v2 IS NULL OR source_v2 IN ('zabbix','alertmanager'));
ALTER TABLE expected_behavior_envelope_heads ADD COLUMN producer_id TEXT;
ALTER TABLE expected_behavior_envelope_heads ADD COLUMN primary_rule_id TEXT;
ALTER TABLE expected_behavior_envelope_heads ADD COLUMN primary_rule_version TEXT;
ALTER TABLE expected_behavior_envelope_heads ADD COLUMN rule_group TEXT;
ALTER TABLE expected_behavior_envelope_heads ADD COLUMN rule_name TEXT;
ALTER TABLE expected_behavior_envelope_heads ADD COLUMN scope_labels_json TEXT NOT NULL DEFAULT '{}'
    CHECK (json_valid(scope_labels_json) AND json_type(scope_labels_json)='object');

CREATE INDEX expected_behavior_envelope_source_v2_scope_idx
    ON expected_behavior_envelope_heads(group_key,source_v2,source_instance_id,producer_id,primary_rule_id,state);
