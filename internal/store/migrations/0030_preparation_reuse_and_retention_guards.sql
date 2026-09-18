-- SPDX-License-Identifier: FSL-1.1-ALv2
--
-- Plan 4 review round 1 (findings F4, F7, F11, F16): frozen cycles carry
-- their own refresh cadence so the first durable request reservation can
-- record fresh-read admission without consulting configuration; plans
-- carry their fairness tier and an explicit reused prior run; the refresh
-- cursor remembers the last committed run so an unchanged subject can be
-- projected into the current cycle by explicit reference; and the
-- retention path is guarded structurally (payload deletion only through
-- the expiration record, no reference to already-expired detail).

ALTER TABLE situation_preparation_cycles ADD COLUMN refresh_seconds INTEGER NOT NULL DEFAULT 300 CHECK (refresh_seconds >= 1);

ALTER TABLE situation_observation_plans ADD COLUMN tier TEXT NOT NULL DEFAULT 'routine'
    CHECK (tier IN ('time_sensitive', 'optional', 'routine', 'local', 'reuse'));
ALTER TABLE situation_observation_plans ADD COLUMN reuse_run_id TEXT REFERENCES situation_observation_runs(id);

ALTER TABLE situation_observation_refresh ADD COLUMN last_run_id TEXT REFERENCES situation_observation_runs(id);

-- A fact payload may only be deleted once its run's expiration record
-- exists and no live (unsuperseded) reference protects the run — the
-- guarded retention transaction inserts the expiration record first.
CREATE TRIGGER situation_observation_fact_payloads_guarded_delete BEFORE DELETE ON situation_observation_fact_payloads
BEGIN
    SELECT RAISE(ABORT, 'observation fact payloads may only expire through the guarded retention path')
    WHERE NOT EXISTS (
        SELECT 1 FROM situation_observation_facts f
        JOIN situation_observation_detail_expirations e ON e.run_id = f.run_id
        WHERE f.id = OLD.fact_id
    ) OR EXISTS (
        SELECT 1 FROM situation_observation_facts f
        JOIN situation_observation_references r ON r.run_id = f.run_id AND r.superseded = 0
        WHERE f.id = OLD.fact_id
    );
END;

-- No reference may ever be established to a run whose detail has already
-- expired: racing readers/writers can never publish a reference to
-- already-deleted payloads.
CREATE TRIGGER situation_observation_references_no_expired_target BEFORE INSERT ON situation_observation_references
BEGIN
    SELECT RAISE(ABORT, 'cannot reference an observation run whose detail has expired')
    WHERE EXISTS (SELECT 1 FROM situation_observation_detail_expirations e WHERE e.run_id = NEW.run_id);
END;
