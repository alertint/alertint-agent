-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Canonical Slack replies are independent durable obligations. A single
-- authoritative Transition may make analysis and recovery ready together;
-- reply_kind preserves both identities and their deterministic delivery order.
-- Empty is the legacy renderer selection for every pre-migration row.

ALTER TABLE notification_intents ADD COLUMN reply_kind TEXT NOT NULL DEFAULT ''
    CHECK (reply_kind IN ('','correlation_started','investigation_started',
        'analysis_completed','partial_clearance','recovery_observed','recovered'));

DROP INDEX notification_intents_thread_broadcast_uniq_idx;
CREATE UNIQUE INDEX notification_intents_thread_broadcast_uniq_idx
    ON notification_intents(situation_id, transition_sequence, effect_class, reply_kind)
    WHERE effect_class IN ('thread_append','broadcast_handoff');

DROP TRIGGER notification_intents_identity_immutable;
CREATE TRIGGER notification_intents_identity_immutable BEFORE UPDATE ON notification_intents
WHEN NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.effect_class IS NOT OLD.effect_class
  OR NEW.reply_kind IS NOT OLD.reply_kind
  OR NEW.situation_id IS NOT OLD.situation_id OR NEW.transition_id IS NOT OLD.transition_id
  OR NEW.transition_sequence IS NOT OLD.transition_sequence OR NEW.summary_version IS NOT OLD.summary_version
  OR NEW.gap_generation IS NOT OLD.gap_generation OR NEW.requires_root IS NOT OLD.requires_root
  OR NEW.main_channel_poke IS NOT OLD.main_channel_poke OR NEW.interruption_priority IS NOT OLD.interruption_priority
  OR NEW.contract_deadline_at IS NOT OLD.contract_deadline_at OR NEW.client_message_id IS NOT OLD.client_message_id
  OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'notification intent identity is immutable'); END;
