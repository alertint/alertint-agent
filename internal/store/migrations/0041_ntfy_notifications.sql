-- SPDX-License-Identifier: FSL-1.1-ALv2
-- ntfy has its own policy and ledger; Slack acknowledgement never consumes it.
CREATE TABLE ntfy_configuration (
 id INTEGER PRIMARY KEY CHECK (id = 1),
 enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
 destination TEXT NOT NULL DEFAULT '',
 events_json TEXT NOT NULL DEFAULT '[]'
);
INSERT INTO ntfy_configuration(id) VALUES(1);
CREATE TABLE ntfy_notifications (
 id TEXT PRIMARY KEY,
 situation_id TEXT NOT NULL REFERENCES situations(id),
 transition_id TEXT NOT NULL REFERENCES situation_transitions(id),
 sequence INTEGER NOT NULL,
 destination TEXT NOT NULL,
 events_json TEXT NOT NULL,
 message_json TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('pending','delivering','blocked','delivered','retired','superseded')),
 attempts INTEGER NOT NULL DEFAULT 0,
 claim_token INTEGER NOT NULL DEFAULT 0,
 claim_owner TEXT NOT NULL DEFAULT '',
 lease_until INTEGER NOT NULL DEFAULT 0,
 retry_at INTEGER NOT NULL DEFAULT 0,
 delayed INTEGER NOT NULL DEFAULT 0,
 catchup INTEGER NOT NULL DEFAULT 0,
 reason TEXT NOT NULL DEFAULT '',
 replacement_id TEXT REFERENCES ntfy_notifications(id),
 created_at TEXT NOT NULL,
 delivered_at TEXT
);
CREATE INDEX ntfy_notifications_pending ON ntfy_notifications(status,retry_at,situation_id,sequence);
