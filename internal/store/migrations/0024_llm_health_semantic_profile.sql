-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 4 Task 8: installation LLM health learns the semantic-profile
-- inference worker's own capability. Semantic profile dispatch feeds the
-- same installation-level LLM dependency state Acute Triage/Assessment do
-- (spec.md: "Register semantic_profile with installation LLM health as a
-- shared-primary inference capability") under internal/llmhealth's
-- CapabilitySemanticProfile ("semantic_profile"). 0015's
-- llm_health_capabilities.capability CHECK is a closed enum that does not
-- include it; SQLite cannot ALTER a CHECK constraint in place, so this
-- rebuilds the table again, preserving every existing row verbatim and
-- widening only the enum. It never edits 0012 or 0015.
CREATE TABLE llm_health_capabilities_new (
    capability       TEXT    NOT NULL PRIMARY KEY
                     CHECK (capability IN ('triage_draft','verification_rejudge','memory_classifier','query_repair','probe','assessment','semantic_profile')),
    healthy          INTEGER NOT NULL CHECK (healthy IN (0, 1)),
    reason_code      TEXT    NOT NULL DEFAULT '',
    detail           TEXT    NOT NULL DEFAULT '',
    last_success_at  TEXT,
    last_failure_at  TEXT,
    unhealthy_since  TEXT,
    content_subjects TEXT    NOT NULL DEFAULT '[]'
                     CHECK (json_valid(content_subjects) AND json_type(content_subjects) = 'array'),
    updated_at       TEXT    NOT NULL
) STRICT;

INSERT INTO llm_health_capabilities_new (
    capability, healthy, reason_code, detail, last_success_at, last_failure_at, unhealthy_since, content_subjects, updated_at
)
SELECT capability, healthy, reason_code, detail, last_success_at, last_failure_at, unhealthy_since, content_subjects, updated_at
FROM llm_health_capabilities;

DROP TABLE llm_health_capabilities;
ALTER TABLE llm_health_capabilities_new RENAME TO llm_health_capabilities;
