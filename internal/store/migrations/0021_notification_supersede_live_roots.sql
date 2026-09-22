-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- One trigger replaced, no table, column, index, or row changed: a newer
-- root projection may now supersede a configuration-blocked or failed
-- older one, not only a pending one.
--
-- Migration 0018 let only a PENDING root_sync become superseded, calling
-- blocked/failed "already resolved outcomes, not live candidates a newer
-- root_sync coalesces away". Review round 1 (R1-F2) showed why that cannot
-- hold once ordering is honest: a blocked or failed root projection still
-- names the Situation's unmet publication obligation, so it must keep the
-- head of its Situation's claim queue — a handoff whose root edit never
-- delivered is not claimable just because an older root exists. A row that
-- holds the queue but can never be retired by newer state would be a
-- permanent blocker. So the three LIVE statuses — pending,
-- blocked_configuration, failed — are all coalesced by the next root
-- projection; delivered, withheld, and superseded rows still never are,
-- and a superseded row still records why and by what.
--
-- This migration fabricates nothing for any Situation that predates it.
-- ----------------------------------------------------------------------
DROP TRIGGER notification_intents_supersede_from_pending_only;
CREATE TRIGGER notification_intents_supersede_from_live_only BEFORE UPDATE OF status ON notification_intents
WHEN NEW.status = 'superseded' AND OLD.status NOT IN ('pending', 'blocked_configuration', 'failed')
BEGIN SELECT RAISE(ABORT, 'only a live root_sync intent (pending, blocked_configuration, or failed) may become superseded'); END;
