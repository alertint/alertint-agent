-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Immutable, advisory L0 semantic-profile history. A head only points at the
-- latest version; it contains no Situation, policy, membership, or delivery
-- state.

CREATE TABLE semantic_profile_heads (
    signature_key  TEXT    NOT NULL PRIMARY KEY CHECK (signature_key <> ''),
    current_version INTEGER NOT NULL CHECK (current_version >= 0),
    updated_at     TEXT    NOT NULL
) STRICT;

CREATE TABLE semantic_profile_versions (
    id                      TEXT    NOT NULL PRIMARY KEY CHECK (id <> ''),
    signature_key           TEXT    NOT NULL REFERENCES semantic_profile_heads(signature_key) ON DELETE CASCADE,
    version                 INTEGER NOT NULL CHECK (version >= 1),
    source                  TEXT    NOT NULL CHECK (source <> ''),
    signature_material_json TEXT    NOT NULL CHECK (json_valid(signature_material_json)),
    profile_json            TEXT    NOT NULL CHECK (json_valid(profile_json)),
    origin                  TEXT    NOT NULL CHECK (origin IN ('inferred', 'correction')),
    input_digest            TEXT    NOT NULL CHECK (input_digest <> ''),
    model                   TEXT,
    prompt_version          TEXT,
    token_usage_json        TEXT    CHECK (token_usage_json IS NULL OR json_valid(token_usage_json)),
    created_at              TEXT    NOT NULL,
    superseded_at           TEXT,
    UNIQUE (signature_key, version)
) STRICT;

CREATE INDEX semantic_profile_versions_signature_version_idx
    ON semantic_profile_versions(signature_key, version);

CREATE TRIGGER semantic_profile_versions_no_delete
BEFORE DELETE ON semantic_profile_versions
BEGIN
    SELECT RAISE(ABORT, 'semantic profile versions are immutable');
END;

-- The one permitted change to a version is recording when a current row was
-- superseded. Every provenance/profile field remains immutable.
CREATE TRIGGER semantic_profile_versions_only_supersede
BEFORE UPDATE ON semantic_profile_versions
WHEN NEW.id IS NOT OLD.id
  OR NEW.signature_key IS NOT OLD.signature_key
  OR NEW.version IS NOT OLD.version
  OR NEW.source IS NOT OLD.source
  OR NEW.signature_material_json IS NOT OLD.signature_material_json
  OR NEW.profile_json IS NOT OLD.profile_json
  OR NEW.origin IS NOT OLD.origin
  OR NEW.input_digest IS NOT OLD.input_digest
  OR NEW.model IS NOT OLD.model
  OR NEW.prompt_version IS NOT OLD.prompt_version
  OR NEW.token_usage_json IS NOT OLD.token_usage_json
  OR NEW.created_at IS NOT OLD.created_at
  OR OLD.superseded_at IS NOT NULL
  OR NEW.superseded_at IS NULL
BEGIN
    SELECT RAISE(ABORT, 'semantic profile versions are immutable');
END;
