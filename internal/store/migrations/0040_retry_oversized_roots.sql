-- SPDX-License-Identifier: FSL-1.1-ALv2
-- The old root renderer could exceed Slack's chat.update text limit. The
-- bounded renderer in this build can send the same current projection, so
-- return those failed root intents to the ordinary delivery queue exactly
-- once on upgrade. Preserve identity, attempt count and error history.
-- Other invalid payloads are not made retryable by this fix.
UPDATE notification_intents AS ni
SET status = 'pending',
    retry_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')
WHERE ni.effect_class = 'root_sync'
  AND ni.status = 'failed'
  AND ni.last_error_class = 'msg_too_long'
  AND ni.summary_version = (
      SELECT es.version FROM situation_episode_summaries AS es
      WHERE es.situation_id = ni.situation_id
  )
  AND NOT EXISTS (
      SELECT 1 FROM notification_intents AS newer
      WHERE newer.situation_id = ni.situation_id
        AND newer.effect_class = 'root_sync'
        AND newer.status = 'pending'
  );
