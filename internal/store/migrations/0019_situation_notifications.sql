-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 3 notification-delivery schema: the durable notification_intents
-- ledger (model.NotificationIntent), persisted Situation root Slack
-- coordinates, and the installation-level Delivery-gap tracking tables
-- (slack_delivery_state, slack_delivery_gaps). This migration never
-- fabricates a notification intent or gap for any Plan 1/2/3 Situation that
-- predates it: an upgraded database simply gains the new tables empty, one
-- seeded slack_delivery_state singleton row, and NULL slack_channel/
-- slack_root_ts on every existing situations row. Deciding when to actually
-- create intents is application-level controller/worker logic for later
-- tasks (Task 4 onward), not a migration-time SQL backfill.

-- ----------------------------------------------------------------------
-- situations: persisted Slack root coordinates. Nullable until the
-- Situation's root is durably published (root_sync's first successful
-- delivery); paired so a Situation is never left with a channel and no
-- timestamp or vice versa. Root edits reuse the same coordinates via
-- chat.update, so this migration does not need a history table for them —
-- situation_transition_stream/notification_intents already carry the
-- immutable per-effect delivery history.
-- ----------------------------------------------------------------------
ALTER TABLE situations ADD COLUMN slack_channel TEXT CHECK (slack_channel IS NULL OR slack_channel <> '');
ALTER TABLE situations ADD COLUMN slack_root_ts  TEXT CHECK (slack_root_ts  IS NULL OR slack_root_ts  <> '');
-- ALTER TABLE ADD COLUMN cannot express a cross-column CHECK, so the pairing
-- invariant is a trigger, mirroring 0017's situations_current_transition_guard
-- shape: it fires only when either coordinate is touched, never on the
-- unrelated updates every other situations write already performs.
CREATE TRIGGER situations_slack_root_pairing_guard BEFORE UPDATE OF slack_channel, slack_root_ts ON situations
WHEN (NEW.slack_channel IS NULL) != (NEW.slack_root_ts IS NULL)
BEGIN SELECT RAISE(ABORT, 'situation slack_channel and slack_root_ts must be set or unset together'); END;

-- ----------------------------------------------------------------------
-- notification_intents: one durable, fenced Slack delivery obligation per
-- model.NotificationIntent, created inside the authoritative controller
-- commit (Task 5) and claimed/delivered by the notification worker
-- (Task 6/7). Rows are inserted once and never deleted, but — unlike
-- situation_transitions — they are NOT wholesale immutable: status, claim,
-- retry, supersession, and delivery columns mutate across the intent's own
-- lifecycle (claim -> retry -> deliver, or claim -> block -> redrive, or
-- pending -> superseded). Only the columns that name WHAT this intent is
-- (effect class, subject references, poke/priority, the deadline it
-- renders, its client message id, and its creation time) are immutable
-- once inserted.
--
-- Effect classes (model.EffectClass) are exactly root_sync, thread_append,
-- broadcast_handoff, and installation_gap_recovery. installation_gap_recovery
-- is the one class with no Situation/Transition/summary reference — it
-- references a slack_delivery_gaps generation instead. The other three
-- reference a Situation and the Transition that created their content;
-- root_sync additionally references the Episode-summary version it renders
-- (thread_append/broadcast_handoff render only their own Transition's
-- stored journal data, never the newest Situation, so they carry no summary
-- reference — spec.md "Notification intent contract").
-- ----------------------------------------------------------------------
CREATE TABLE notification_intents (
    id                     TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    idempotency_key        TEXT    NOT NULL UNIQUE CHECK (idempotency_key <> ''),
    effect_class           TEXT    NOT NULL CHECK (effect_class IN (
                               'root_sync','thread_append','broadcast_handoff','installation_gap_recovery'
                           )),
    situation_id           TEXT    REFERENCES situations(id),
    transition_id          TEXT    REFERENCES situation_transitions(id),
    -- Denormalized alongside transition_id (same shape as
    -- situation_transition_stream's own situation_id+sequence columns) so
    -- the thread/broadcast and root-pending partial unique indexes below
    -- don't need a join. The identity-guard trigger keeps it truthful.
    transition_sequence    INTEGER CHECK (transition_sequence IS NULL OR transition_sequence >= 1),
    -- root_sync only (R4): the Episode-summary version this root renders.
    summary_version        INTEGER CHECK (summary_version IS NULL OR summary_version >= 1),
    -- installation_gap_recovery only.
    gap_generation         TEXT    REFERENCES slack_delivery_gaps(id),
    -- Denormalized derived fact: true for exactly thread_append and
    -- broadcast_handoff (spec.md "a root must be durably delivered before
    -- any reply is claimable"). root_sync creates or edits the root itself
    -- and installation_gap_recovery has no Situation root to depend on, so
    -- both are false. Enforced by the requires_root CHECK below rather than
    -- left to worker logic, so a future effect class cannot silently ship
    -- without deciding this.
    requires_root          INTEGER NOT NULL CHECK (requires_root IN (0, 1)),
    main_channel_poke      INTEGER NOT NULL CHECK (main_channel_poke IN (0, 1)),
    -- Set if and only if main_channel_poke is true: the InterruptionPriority
    -- this poke candidate was evaluated against the notify.slack.min_severity
    -- floor with (spec.md "Publication authority and Interruption priority").
    -- A non-poke effect (a plain root edit, an ordinary journal reply, or the
    -- installation-level gap-recovery notice) carries no Interruption
    -- priority of its own.
    interruption_priority  TEXT    CHECK (interruption_priority IS NULL OR interruption_priority IN ('low','medium','high','critical')),
    -- root_sync only (R4): the committed promise this root renders, captured
    -- at commit time from the committed Operator contract — never from the
    -- Episode summary, and never on any other effect class.
    contract_deadline_at   TEXT,
    client_message_id      TEXT    NOT NULL CHECK (client_message_id <> ''),
    status                 TEXT    NOT NULL DEFAULT 'pending' CHECK (status IN (
                               'pending','delivered','blocked_configuration','failed',
                               'withheld_by_operator_slack_floor','superseded'
                           )),
    claim_owner            TEXT,
    claim_token            INTEGER NOT NULL DEFAULT 0 CHECK (claim_token >= 0),
    lease_expires_at       TEXT,
    -- Attempt count is preserved across every status transition, including
    -- into and out of blocked_configuration: no column here expresses a
    -- maximum-attempt terminal outcome, since only 'failed' (an invalid
    -- durable intent or non-recoverable programming/data error) is
    -- terminal-by-attempts, and even that is explicitly operator-redriveable
    -- (spec.md "Required fields and states").
    attempt_count          INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    last_error_class       TEXT,
    retry_at               TEXT,
    supersession_reason    TEXT,
    replacement_intent_id  TEXT    REFERENCES notification_intents(id),
    -- The delivery-mode a completed Deliver() call reported (worker-internal
    -- NotificationDelivery.DeliveredAs), not present on the wire contract
    -- Task 1 closed: root | thread | broadcast | delayed_thread | system.
    -- delayed_thread covers both an ordinary-delay backlog entry and a
    -- broadcast_handoff revalidated stale and downgraded to a non-broadcast,
    -- no-longer-current entry (spec.md "Recovery replay").
    delivered_as           TEXT    CHECK (delivered_as IS NULL OR delivered_as IN ('root','thread','broadcast','delayed_thread','system')),
    channel                TEXT,
    message_ts             TEXT,
    created_at             TEXT    NOT NULL CHECK (created_at <> ''),
    delivered_at           TEXT,

    -- Effect-class-specific reference shape (model.NotificationIntent.Validate
    -- mirrored at the store layer): installation_gap_recovery carries no
    -- Situation/Transition/summary reference and requires a gap generation;
    -- every other class requires a Situation/Transition reference and
    -- forbids a gap generation.
    CHECK (
        (effect_class = 'installation_gap_recovery'
            AND situation_id IS NULL AND transition_id IS NULL AND transition_sequence IS NULL
            AND gap_generation IS NOT NULL)
        OR
        (effect_class != 'installation_gap_recovery'
            AND situation_id IS NOT NULL AND transition_id IS NOT NULL AND transition_sequence IS NOT NULL
            AND gap_generation IS NULL)
    ),
    -- summary_version is set if and only if effect_class = 'root_sync'.
    CHECK ((summary_version IS NOT NULL) = (effect_class = 'root_sync')),
    -- contract_deadline_at is nullable even on root_sync (a terminal root has
    -- no pending promise), but non-NULL only ever appears on root_sync (R4).
    CHECK (contract_deadline_at IS NULL OR effect_class = 'root_sync'),
    -- requires_root is the deterministic function of effect_class described
    -- above, never an independently-set flag.
    CHECK (requires_root = (effect_class IN ('thread_append','broadcast_handoff'))),
    -- Main-poke/priority equivalence: a candidate main-channel poke always
    -- carries the Interruption priority it was floor-evaluated against
    -- (including a poke immediately withheld by that floor), and nothing
    -- that isn't a poke candidate carries one.
    CHECK ((main_channel_poke = 1) = (interruption_priority IS NOT NULL)),
    -- Claim-owner/lease pairing, and claiming only ever moves a pending
    -- intent's lease deadline (spec.md "Claims retain pending").
    CHECK ((claim_owner IS NULL) = (lease_expires_at IS NULL)),
    CHECK (claim_owner IS NULL OR status = 'pending'),
    -- failed is never auto-retried (mirrors 0017's situation_transition_stream
    -- and situation_input_outbox: status != 'failed' OR retry_at IS NULL).
    CHECK (status != 'failed' OR retry_at IS NULL),
    -- Delivered coordinates/time consistency: all four or none.
    CHECK ((status = 'delivered') = (delivered_at IS NOT NULL AND channel IS NOT NULL AND message_ts IS NOT NULL AND delivered_as IS NOT NULL)),
    -- Only a pending root projection may ever become superseded — an
    -- immutable thread_append/broadcast_handoff journal entry never is
    -- (spec.md "Older root projections ... may become superseded ...
    -- Distinct episodes and material journal entries never become
    -- superseded"), and every superseded row records why and by what.
    CHECK (status != 'superseded' OR effect_class = 'root_sync'),
    CHECK ((status = 'superseded') = (supersession_reason IS NOT NULL)),
    CHECK ((status = 'superseded') = (replacement_intent_id IS NOT NULL)),
    CHECK (replacement_intent_id IS NULL OR replacement_intent_id != id)
) STRICT;

-- Same-Situation Transition guard, mirroring 0014/0017's current-pointer and
-- Assessment guards: an intent's transition_id must belong to the same
-- Situation this row claims, at the exact sequence this row also claims.
-- INSERT-only: transition_id/transition_sequence/situation_id are part of
-- this row's immutable identity (enforced below), so no legal UPDATE can
-- ever change them.
CREATE TRIGGER notification_intents_transition_guard BEFORE INSERT ON notification_intents
WHEN NEW.transition_id IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM situation_transitions tr
    WHERE tr.id = NEW.transition_id AND tr.situation_id = NEW.situation_id AND tr.sequence = NEW.transition_sequence
)
BEGIN SELECT RAISE(ABORT, 'notification intent transition_id must reference a transition owned by the same situation with matching sequence'); END;

-- Identity is immutable; status/claim/retry/supersession/delivery columns
-- are the intent's mutable lifecycle and may be freely updated.
CREATE TRIGGER notification_intents_identity_immutable BEFORE UPDATE ON notification_intents
WHEN NEW.idempotency_key IS NOT OLD.idempotency_key OR NEW.effect_class IS NOT OLD.effect_class
  OR NEW.situation_id IS NOT OLD.situation_id OR NEW.transition_id IS NOT OLD.transition_id
  OR NEW.transition_sequence IS NOT OLD.transition_sequence OR NEW.summary_version IS NOT OLD.summary_version
  OR NEW.gap_generation IS NOT OLD.gap_generation OR NEW.requires_root IS NOT OLD.requires_root
  OR NEW.main_channel_poke IS NOT OLD.main_channel_poke OR NEW.interruption_priority IS NOT OLD.interruption_priority
  OR NEW.contract_deadline_at IS NOT OLD.contract_deadline_at OR NEW.client_message_id IS NOT OLD.client_message_id
  OR NEW.created_at IS NOT OLD.created_at
BEGIN SELECT RAISE(ABORT, 'notification intent identity is immutable'); END;
-- No DELETE, ever — this is durable delivery history, not a queue that
-- forgets. Unlike situation_transitions there is deliberately no
-- "_no_update" trigger here: the lifecycle columns above are the whole
-- point of this table's mutability.
CREATE TRIGGER notification_intents_no_delete BEFORE DELETE ON notification_intents
BEGIN SELECT RAISE(ABORT, 'notification intent history is immutable'); END;
-- Only a currently-pending root_sync may become superseded — never one
-- already delivered/blocked/failed/withheld (those are already resolved
-- outcomes, not live candidates a newer root_sync coalesces away), and
-- never a second hop through an already-superseded row.
CREATE TRIGGER notification_intents_supersede_from_pending_only BEFORE UPDATE OF status ON notification_intents
WHEN NEW.status = 'superseded' AND OLD.status != 'pending'
BEGIN SELECT RAISE(ABORT, 'only a pending root_sync intent may become superseded'); END;

-- At most one pending, unsuperseded root_sync per Situation: a root_sync
-- refresh (R4) or a newly warranted root edit must supersede any existing
-- pending root_sync before (or in the same commit as) inserting its
-- replacement, rather than ever letting two compete for the same root.
CREATE UNIQUE INDEX notification_intents_root_sync_pending_idx ON notification_intents(situation_id)
    WHERE effect_class = 'root_sync' AND status = 'pending';
-- thread_append and broadcast_handoff are immutable historical effects: at
-- most one per (Situation, Transition sequence, effect class), for all
-- time, not just while pending. root_sync is deliberately excluded — a
-- root_sync refresh (R4) reuses its authority Transition's sequence on
-- purpose, so its own idempotency key (which also folds in summary_version
-- and contract_deadline_at) is what keeps it unique, not this index.
CREATE UNIQUE INDEX notification_intents_thread_broadcast_uniq_idx ON notification_intents(situation_id, transition_sequence, effect_class)
    WHERE effect_class IN ('thread_append','broadcast_handoff');
-- Due-claim ordering: the worker's claim query scans exactly this shape,
-- mirroring situation_transition_stream_claim_idx.
CREATE INDEX notification_intents_claim_idx ON notification_intents(status, lease_expires_at, retry_at, created_at)
    WHERE status = 'pending';
-- Root-dependency lookups: "has this Situation's root already been
-- delivered" (thread_append/broadcast_handoff claimability) and "what is
-- the current root_sync's status" both scan this shape.
CREATE INDEX notification_intents_root_dependency_idx ON notification_intents(situation_id, status)
    WHERE effect_class = 'root_sync';
-- Situation ordering: a Situation's intents in Transition-sequence order,
-- the shape spec.md's ordering rules (root before reply, sequence order,
-- handoff-edit before broadcast) read against.
CREATE INDEX notification_intents_situation_order_idx ON notification_intents(situation_id, transition_sequence, id)
    WHERE situation_id IS NOT NULL;
-- Gap-recovery replay: locate the one installation_gap_recovery intent for
-- a given generation (to confirm it delivered before backlog replay
-- starts).
CREATE INDEX notification_intents_gap_generation_idx ON notification_intents(gap_generation)
    WHERE gap_generation IS NOT NULL;

-- ----------------------------------------------------------------------
-- slack_delivery_gaps: one row per installation-level Delivery-gap
-- generation (spec.md "Gap lifecycle" / "Recovery replay"). open while
-- continuous Slack failures persist, replaying once a readiness check
-- succeeds and the recovery notice + backlog delivery is underway, complete
-- once the backlog finishes. Rows are inserted once (open) and mutate
-- forward through this lifecycle; never deleted.
-- ----------------------------------------------------------------------
CREATE TABLE slack_delivery_gaps (
    id                        TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    status                    TEXT    NOT NULL DEFAULT 'open' CHECK (status IN ('open','replaying','complete')),
    opened_at                 TEXT    NOT NULL CHECK (opened_at <> ''),
    affected_situation_count  INTEGER NOT NULL DEFAULT 0 CHECK (affected_situation_count >= 0),
    delayed_effect_count      INTEGER NOT NULL DEFAULT 0 CHECK (delayed_effect_count >= 0),
    -- Set once the gap starts replaying: the claimable installation_gap_recovery
    -- intent that must deliver before the affected-Situation backlog does.
    recovery_notice_intent_id TEXT    REFERENCES notification_intents(id),
    recovered_at              TEXT,
    completed_at              TEXT,
    CHECK (status != 'open'      OR (recovered_at IS NULL     AND completed_at IS NULL AND recovery_notice_intent_id IS NULL)),
    CHECK (status != 'replaying' OR (recovered_at IS NOT NULL AND completed_at IS NULL)),
    CHECK (status != 'complete'  OR (recovered_at IS NOT NULL AND completed_at IS NOT NULL))
) STRICT;
-- id/opened_at are this generation's immutable identity; status, the
-- counts, the recovery-notice reference, and the recovered/completed
-- instants are its mutable lifecycle.
CREATE TRIGGER slack_delivery_gaps_identity_immutable BEFORE UPDATE ON slack_delivery_gaps
WHEN NEW.id IS NOT OLD.id OR NEW.opened_at IS NOT OLD.opened_at
BEGIN SELECT RAISE(ABORT, 'slack delivery gap identity is immutable'); END;
CREATE TRIGGER slack_delivery_gaps_no_delete BEFORE DELETE ON slack_delivery_gaps
BEGIN SELECT RAISE(ABORT, 'slack delivery gap history is immutable'); END;

-- ----------------------------------------------------------------------
-- slack_delivery_state: the one aggregate Slack-dependency-health row,
-- exactly the fixed-id singleton idiom 0012_llm_health.sql already
-- established for the LLM-dependency aggregate. Seeded here so the worker
-- (Task 6/7) only ever UPDATEs it.
-- ----------------------------------------------------------------------
CREATE TABLE slack_delivery_state (
    id                        INTEGER PRIMARY KEY CHECK (id = 1),
    first_failure_at          TEXT,
    last_success_at           TEXT,
    -- The gap generation currently open or replaying, or NULL when Slack
    -- delivery is healthy or the last gap has fully completed. Guarded below
    -- so this can never point at an already-complete generation.
    open_gap_generation       TEXT REFERENCES slack_delivery_gaps(id),
    -- Bumped when startup detects corrected Slack configuration (spec.md
    -- "blocked_configuration ... Startup with corrected configuration
    -- increments a durable configuration generation"); moves affected
    -- intents back to pending independently of the gap-generation lifecycle
    -- above.
    configuration_generation  INTEGER NOT NULL DEFAULT 0 CHECK (configuration_generation >= 0),
    -- The last time a bounded retry WARN was emitted, so the worker can
    -- honor the "bounded retry WARNs at dependency health cadence" pacing
    -- without re-deriving it from notification_intents on every tick.
    last_warning_at           TEXT,
    updated_at                TEXT    NOT NULL CHECK (updated_at <> '')
) STRICT;

INSERT INTO slack_delivery_state (id, configuration_generation, updated_at)
VALUES (1, 0, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'));

-- open_gap_generation may only ever name a gap still open or replaying —
-- never one already complete, and never a generation that doesn't exist.
CREATE TRIGGER slack_delivery_state_open_gap_guard BEFORE UPDATE OF open_gap_generation ON slack_delivery_state
WHEN NEW.open_gap_generation IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM slack_delivery_gaps g WHERE g.id = NEW.open_gap_generation AND g.status IN ('open','replaying')
)
BEGIN SELECT RAISE(ABORT, 'slack delivery state open_gap_generation must reference an open or replaying gap'); END;
CREATE TRIGGER slack_delivery_state_no_delete BEFORE DELETE ON slack_delivery_state
BEGIN SELECT RAISE(ABORT, 'slack delivery state is a singleton and may not be deleted'); END;
