-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- B0 integration contract §5.3/§6 (E1): a live, undelivered first-execution-
-- assurance thread_append may now be superseded when a later commit, in the
-- SAME fenced CommitController transaction, plans a useful_finding,
-- inconclusive_completion or terminal_end reply for the same Situation.
-- Migration 0018 permitted superseding a root_sync only ("an immutable
-- thread_append/broadcast_handoff journal entry never is"); that was correct
-- for material history in general (ADR 0042/0052) but too strict for the one
-- narrow transient reply ADR 0052 carves out: a delivered assurance is still
-- never touched (0020's live-only rule is unchanged), and only a thread_append
-- whose own Transition actually IS an investigation_started assurance may
-- ever become superseded — every other journal entry (a finding, a member
-- change, an all-clear, a terminal end, and so on) is exactly the durable
-- material history 0018 already protects.
--
-- SQLite cannot relax a CHECK constraint via ALTER TABLE, so this rebuilds
-- notification_intents in place (0016's pattern), preserving every existing
-- row exactly and fabricating nothing. broadcast_handoff is deliberately
-- NOT added to the relaxed CHECK: the accepted design names thread_append
-- only (an assurance is a quiet reply, never the one poke a commit selects);
-- if a future assurance is ever eligible to be poked, that is a fresh design
-- decision, not an oversight here.
--
-- notification_intents is the FK target of slack_delivery_gaps.
-- recovery_notice_intent_id. SQLite enforces that a table may not be
-- DROPped while another table holds a live (non-NULL) row referencing it,
-- and the migration runner applies this whole file inside one transaction —
-- `PRAGMA foreign_keys` cannot be toggled mid-transaction, only
-- `defer_foreign_keys`, which does not cover a dropped parent table. The
-- fix is the same either way: temporarily clear the referencing values,
-- rebuild, then restore them from a transaction-local backup. The
-- self-referencing replacement_intent_id column needs no such handling —
-- it is copied wholesale into the SAME rebuilt table, so old and new rows
-- move together.
-- ----------------------------------------------------------------------

CREATE TEMP TABLE gap_recovery_notice_backup AS
    SELECT id, recovery_notice_intent_id FROM slack_delivery_gaps WHERE recovery_notice_intent_id IS NOT NULL;
UPDATE slack_delivery_gaps SET recovery_notice_intent_id = NULL WHERE recovery_notice_intent_id IS NOT NULL;

CREATE TABLE notification_intents_new (
    id                     TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    idempotency_key        TEXT    NOT NULL UNIQUE CHECK (idempotency_key <> ''),
    effect_class           TEXT    NOT NULL CHECK (effect_class IN (
                               'root_sync','thread_append','broadcast_handoff','installation_gap_recovery'
                           )),
    situation_id           TEXT    REFERENCES situations(id),
    transition_id          TEXT    REFERENCES situation_transitions(id),
    transition_sequence    INTEGER CHECK (transition_sequence IS NULL OR transition_sequence >= 1),
    summary_version        INTEGER CHECK (summary_version IS NULL OR summary_version >= 1),
    gap_generation         TEXT    REFERENCES slack_delivery_gaps(id),
    requires_root          INTEGER NOT NULL CHECK (requires_root IN (0, 1)),
    main_channel_poke      INTEGER NOT NULL CHECK (main_channel_poke IN (0, 1)),
    interruption_priority  TEXT    CHECK (interruption_priority IS NULL OR interruption_priority IN ('low','medium','high','critical')),
    contract_deadline_at   TEXT,
    client_message_id      TEXT    NOT NULL CHECK (client_message_id <> ''),
    status                 TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN (
                               'pending','delivered','blocked_configuration','failed',
                               'withheld_by_operator_slack_floor','superseded'
                           )),
    claim_owner            TEXT,
    claim_token            INTEGER NOT NULL DEFAULT 0 CHECK (claim_token >= 0),
    lease_expires_at       TEXT,
    attempt_count          INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class       TEXT,
    retry_at               TEXT,
    supersession_reason    TEXT,
    replacement_intent_id  TEXT    REFERENCES notification_intents_new(id),
    delivered_as           TEXT    CHECK (delivered_as IS NULL OR delivered_as IN ('root','thread','broadcast','delayed_thread','system')),
    channel                TEXT,
    message_ts             TEXT,
    created_at             TEXT    NOT NULL CHECK (created_at <> ''),
    delivered_at           TEXT,

    CHECK (
        (effect_class = 'installation_gap_recovery'
            AND situation_id IS NULL AND transition_id IS NULL AND transition_sequence IS NULL
            AND gap_generation IS NOT NULL)
        OR
        (effect_class != 'installation_gap_recovery'
            AND situation_id IS NOT NULL AND transition_id IS NOT NULL AND transition_sequence IS NOT NULL
            AND gap_generation IS NULL)
    ),
    CHECK ((summary_version IS NOT NULL) = (effect_class = 'root_sync')),
    CHECK (contract_deadline_at IS NULL OR effect_class = 'root_sync'),
    CHECK (requires_root = (effect_class IN ('thread_append','broadcast_handoff'))),
    CHECK ((main_channel_poke = 1) = (interruption_priority IS NOT NULL)),
    CHECK ((claim_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (claim_owner IS NULL OR status = 'pending'),
    CHECK (status != 'failed' OR retry_at IS NULL),
    CHECK ((status = 'delivered') = (delivered_at IS NOT NULL AND channel IS NOT NULL AND message_ts IS NOT NULL AND delivered_as IS NOT NULL)),
    -- Relaxed (E1): a pending root_sync OR a pending/blocked/failed
    -- thread_append assurance may become superseded. broadcast_handoff
    -- remains immutable material history, same as every other journal
    -- entry — only the one narrow transient reply class changes here.
    CHECK (status != 'superseded' OR effect_class IN ('root_sync','thread_append')),
    CHECK ((status = 'superseded') = (supersession_reason IS NOT NULL)),
    CHECK ((status = 'superseded') = (replacement_intent_id IS NOT NULL)),
    CHECK (replacement_intent_id IS NULL OR replacement_intent_id != id)
) STRICT;

INSERT INTO notification_intents_new SELECT
    id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
    summary_version, gap_generation, requires_root, main_channel_poke, interruption_priority,
    contract_deadline_at, client_message_id, status, claim_owner, claim_token, lease_expires_at,
    attempt_count, last_error_class, retry_at, supersession_reason, replacement_intent_id,
    delivered_as, channel, message_ts, created_at, delivered_at
FROM notification_intents;

DROP TABLE notification_intents;
ALTER TABLE notification_intents_new RENAME TO notification_intents;

UPDATE slack_delivery_gaps
SET recovery_notice_intent_id = (
    SELECT b.recovery_notice_intent_id FROM gap_recovery_notice_backup b WHERE b.id = slack_delivery_gaps.id
)
WHERE id IN (SELECT id FROM gap_recovery_notice_backup);
DROP TABLE gap_recovery_notice_backup;

-- Every trigger and index below is recreated verbatim from 0018/0020/0021's
-- cumulative definitions (a rebuilt table carries neither) except the one
-- new guard at the end.
CREATE TRIGGER notification_intents_transition_guard BEFORE INSERT ON notification_intents
WHEN NEW.transition_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM situation_transitions tr
    WHERE tr.id = NEW.transition_id AND tr.situation_id = NEW.situation_id AND tr.sequence = NEW.transition_sequence
)
BEGIN SELECT RAISE(ABORT, 'notification intent transition_id must reference a transition owned by the same situation with matching sequence'); END;

CREATE TRIGGER notification_intents_identity_immutable BEFORE UPDATE ON notification_intents
WHEN NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.effect_class IS NOT OLD.effect_class
  OR NEW.situation_id IS NOT OLD.situation_id OR NEW.transition_id IS NOT OLD.transition_id
  OR NEW.transition_sequence IS NOT OLD.transition_sequence OR NEW.summary_version IS NOT OLD.summary_version
  OR NEW.gap_generation IS NOT OLD.gap_generation OR NEW.requires_root IS NOT OLD.requires_root
  OR NEW.main_channel_poke IS NOT OLD.main_channel_poke OR NEW.interruption_priority IS NOT OLD.interruption_priority
  OR NEW.contract_deadline_at IS NOT OLD.contract_deadline_at OR NEW.client_message_id IS NOT OLD.client_message_id
  OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'notification intent identity is immutable'); END;

CREATE TRIGGER notification_intents_no_delete BEFORE DELETE ON notification_intents
BEGIN SELECT RAISE(ABORT, 'notification intent history is immutable'); END;

-- 0020's live-only rule, unchanged: pending, blocked_configuration or
-- failed may become superseded; delivered/withheld/already-superseded may
-- not. Applies to BOTH supersedable classes now (root_sync, thread_append).
CREATE TRIGGER notification_intents_supersede_from_live_only BEFORE UPDATE OF status ON notification_intents
WHEN NEW.status = 'superseded' AND OLD.status NOT IN ('pending', 'blocked_configuration', 'failed')
BEGIN SELECT RAISE(ABORT, 'only a live root_sync or thread_append intent (pending, blocked_configuration, or failed) may become superseded'); END;

-- New (E1): a superseded thread_append must actually BE the one-time
-- execution assurance reply — its own Transition's journal_kind is
-- investigation_started — never any other material journal entry.
CREATE TRIGGER notification_intents_thread_supersession_guard BEFORE UPDATE OF status ON notification_intents
WHEN NEW.status = 'superseded' AND NEW.effect_class = 'thread_append' AND NOT EXISTS (
    SELECT 1 FROM situation_transitions tr WHERE tr.id = NEW.transition_id AND tr.journal_kind = 'investigation_started'
)
BEGIN SELECT RAISE(ABORT, 'a superseded thread_append must reference an investigation_started transition'); END;

CREATE UNIQUE INDEX notification_intents_root_sync_pending_idx ON notification_intents(situation_id)
    WHERE effect_class = 'root_sync' AND status = 'pending';
CREATE UNIQUE INDEX notification_intents_thread_broadcast_uniq_idx ON notification_intents(situation_id, transition_sequence, effect_class)
    WHERE effect_class IN ('thread_append','broadcast_handoff');
CREATE INDEX notification_intents_claim_idx ON notification_intents(status, lease_expires_at, retry_at, created_at)
    WHERE status = 'pending';
CREATE INDEX notification_intents_root_dependency_idx ON notification_intents(situation_id, status)
    WHERE effect_class = 'root_sync';
CREATE INDEX notification_intents_situation_order_idx ON notification_intents(situation_id, transition_sequence, id)
    WHERE situation_id IS NOT NULL;
CREATE INDEX notification_intents_gap_generation_idx ON notification_intents(gap_generation)
    WHERE gap_generation IS NOT NULL;
CREATE INDEX notification_intents_blocked_configuration_idx ON notification_intents(status)
    WHERE status = 'blocked_configuration';
CREATE INDEX notification_intents_live_idx ON notification_intents(status, situation_id, transition_sequence, id)
    WHERE status IN ('pending', 'blocked_configuration', 'failed');
