-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 4 review round 1 (findings F14, F22): durable semantic-profile
-- inference gains a rearmable attempt budget and a persisted recovery
-- generation so dependency-exhausted jobs rearm exactly once per newer
-- durable healthy generation (spec.md R6/A8), and an append-only miss
-- record so a delivery whose signature material is permanently
-- unsupported (oversize/invalid) stops being reselected by the bounded
-- startup backfill forever.

-- attempt_budget is the number of attempts this job may spend in total
-- across its original allowance and every later rearm; the original
-- max_attempts stays frozen for audit. Exhaustion is attempt >= attempt_budget.
ALTER TABLE semantic_profile_inference_jobs ADD COLUMN attempt_budget INTEGER NOT NULL DEFAULT 0 CHECK (attempt_budget >= 0);
UPDATE semantic_profile_inference_jobs SET attempt_budget = max_attempts;

-- rearmed_generation is the durable healthy recovery generation that last
-- rearmed this job (0 = never rearmed); a job rearms only for a generation
-- strictly newer than this.
ALTER TABLE semantic_profile_inference_jobs ADD COLUMN rearmed_generation INTEGER NOT NULL DEFAULT 0 CHECK (rearmed_generation >= 0);

-- delivery_semantic_signature_misses records, append-only, a delivery whose
-- advisory signature could not be built (permanently unsupported material).
-- BackfillActiveSemanticMappings excludes these rows so the same row is
-- never selected again; the delivery itself stays immutable and unmapped.
CREATE TABLE delivery_semantic_signature_misses (
    delivery_id TEXT NOT NULL PRIMARY KEY REFERENCES alert_deliveries(id),
    reason      TEXT NOT NULL CHECK (reason <> ''),
    created_at  TEXT NOT NULL CHECK (created_at <> '')
) STRICT;
CREATE TRIGGER delivery_semantic_signature_misses_no_update BEFORE UPDATE ON delivery_semantic_signature_misses
BEGIN SELECT RAISE(ABORT, 'delivery semantic signature misses are immutable'); END;
CREATE TRIGGER delivery_semantic_signature_misses_no_delete BEFORE DELETE ON delivery_semantic_signature_misses
BEGIN SELECT RAISE(ABORT, 'delivery semantic signature misses are immutable'); END;
