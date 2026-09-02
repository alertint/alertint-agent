-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- 0017_llm_health_assessment_capability.sql
--
-- Task 9 wires the Situation controller's own L2 (Assessment) dispatch into
-- installation-level LLM health (spec.md: "LLM health remains one
-- installation-level capability state fed by real Acute Triage and
-- Assessment outcomes") — internal/llmhealth's own new CapabilityAssessment
-- ("assessment"). 0012's llm_health_capabilities.capability CHECK is a
-- closed enum that does not include it; SQLite cannot ALTER a CHECK
-- constraint in place, so this rebuilds the table exactly as 0016 rebuilt
-- incident_triage, preserving every existing row verbatim and widening only
-- the enum. It never edits 0012 itself.

CREATE TABLE llm_health_capabilities_new (
    capability       TEXT    NOT NULL PRIMARY KEY
                     CHECK (capability IN ('triage_draft','verification_rejudge','memory_classifier','query_repair','probe','assessment')),
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
