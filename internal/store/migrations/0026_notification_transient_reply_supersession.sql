-- SPDX-License-Identifier: FSL-1.1-ALv2
-- A queued canonical correlation orientation is transient in the same narrow
-- sense as a pure execution-start assurance. Later progress may retire it so
-- a delayed latest root is never followed by an obsolete countdown.

DROP TRIGGER notification_intents_thread_supersession_guard;

CREATE TRIGGER notification_intents_thread_supersession_guard BEFORE UPDATE OF status ON notification_intents
WHEN NEW.status = 'superseded' AND NEW.effect_class = 'thread_append'
 AND NEW.reply_kind <> 'correlation_started' AND NOT EXISTS (
    SELECT 1 FROM situation_transitions tr
    WHERE tr.id = NEW.transition_id
      AND CASE
            WHEN json_type(tr.projection_json, '$.operator_delta.candidates') IS NULL
                 OR json_type(tr.projection_json, '$.operator_delta.candidates') = 'null'
              THEN tr.journal_kind = 'investigation_started'
            WHEN json_type(tr.projection_json, '$.operator_delta.candidates') <> 'array'
              THEN 0
            WHEN json_array_length(tr.projection_json, '$.operator_delta.candidates') = 0
              THEN tr.journal_kind = 'investigation_started'
            ELSE NOT EXISTS (
                   SELECT 1
                     FROM json_each(tr.projection_json, '$.operator_delta.candidates') c
                    WHERE CASE
                            WHEN c.type = 'object'
                              THEN json_extract(c.value, '$.kind') IS NOT 'first_execution_assurance'
                            ELSE 1
                          END
                 )
          END
)
BEGIN SELECT RAISE(ABORT, 'a superseded thread_append must be a transient correlation or purely transient first_execution_assurance reply'); END;
