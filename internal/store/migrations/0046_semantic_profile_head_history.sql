-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Preserve a committed head snapshot without keeping the single connection
-- occupied while reading all delivery mappings and decoding profile JSON.
CREATE TABLE semantic_profile_head_history (
    sequence      INTEGER PRIMARY KEY,
    signature_key TEXT NOT NULL CHECK (signature_key <> ''),
    version_id    TEXT REFERENCES semantic_profile_versions(id)
) STRICT;
CREATE INDEX semantic_profile_head_history_signature_idx
    ON semantic_profile_head_history(signature_key, sequence DESC);

-- Backfill the published pointers, never the highest unpublished version.
INSERT INTO semantic_profile_head_history(signature_key, version_id)
    SELECT signature_key, version_id FROM semantic_profile_heads ORDER BY signature_key;

CREATE TRIGGER semantic_profile_head_history_insert AFTER INSERT ON semantic_profile_heads
BEGIN
    INSERT INTO semantic_profile_head_history(signature_key, version_id)
        VALUES (NEW.signature_key, NEW.version_id);
END;
CREATE TRIGGER semantic_profile_head_history_update AFTER UPDATE ON semantic_profile_heads
WHEN OLD.signature_key <> NEW.signature_key OR OLD.version_id <> NEW.version_id
BEGIN
    INSERT INTO semantic_profile_head_history(signature_key, version_id)
        SELECT OLD.signature_key, NULL WHERE OLD.signature_key <> NEW.signature_key;
    INSERT INTO semantic_profile_head_history(signature_key, version_id)
        VALUES (NEW.signature_key, NEW.version_id);
END;
CREATE TRIGGER semantic_profile_head_history_delete AFTER DELETE ON semantic_profile_heads
BEGIN
    INSERT INTO semantic_profile_head_history(signature_key, version_id)
        VALUES (OLD.signature_key, NULL);
END;
CREATE TRIGGER semantic_profile_head_history_no_update BEFORE UPDATE ON semantic_profile_head_history
BEGIN SELECT RAISE(ABORT, 'semantic profile head history is immutable'); END;
CREATE TRIGGER semantic_profile_head_history_no_delete BEFORE DELETE ON semantic_profile_head_history
BEGIN SELECT RAISE(ABORT, 'semantic profile head history is immutable'); END;
