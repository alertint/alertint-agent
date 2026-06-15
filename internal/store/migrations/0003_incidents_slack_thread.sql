-- 0003_incidents_slack_thread.sql
-- Add Slack thread tracking columns to incidents.
--
-- These nullable columns store the message timestamp (ts) and channel ID
-- returned by chat.postMessage when the initial firing notification is sent.
-- The Slack notifier reads them on resolution to update the original message
-- and post a thread reply rather than creating a new top-level message.

ALTER TABLE incidents ADD COLUMN slack_ts      TEXT;
ALTER TABLE incidents ADD COLUMN slack_channel TEXT;
