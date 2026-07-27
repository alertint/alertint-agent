-- 0010_feedback_capture.sql
-- Feedback & verdict capture (ADR-0027/0028): operator annotations and
-- captured verdicts. Both append-only; the latest annotation / highest
-- verdict version is operative. The verdict marker is DERIVED from
-- incident_verdicts existence — the incidents table is untouched.

CREATE TABLE incident_annotations (
    id          INTEGER PRIMARY KEY,
    incident_id TEXT    NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    kind        TEXT    NOT NULL CHECK (kind IN ('correction','observation','confirmation')),
    note        TEXT    NOT NULL,
    created_at  TEXT    NOT NULL
) STRICT;

CREATE INDEX incident_annotations_incident_idx
    ON incident_annotations(incident_id, created_at);

CREATE TABLE incident_verdicts (
    id               INTEGER PRIMARY KEY,
    incident_id      TEXT    NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    version          INTEGER NOT NULL,
    verdict          TEXT    NOT NULL CHECK (verdict IN ('correction','confirmation')),
    source           TEXT    NOT NULL CHECK (source <> ''),  -- label provenance: 'human' = explicit MCP capture; harvest channels add their own values
    label_confidence REAL    NOT NULL CHECK (label_confidence > 0.0 AND label_confidence <= 1.0),  -- weight of a label from this source; human = 1.0
    expectation_json TEXT    NOT NULL,
    widened_json     TEXT,                -- VerificationQuery-shaped entries, source "capture"
    cause_category   TEXT,                -- free-form, no taxonomy (D11)
    created_at       TEXT    NOT NULL,
    UNIQUE (incident_id, version)
) STRICT;
