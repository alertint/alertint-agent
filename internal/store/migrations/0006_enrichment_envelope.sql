-- 0006_enrichment_envelope.sql
-- Make incidents.enrichment_json uniform: every non-null value is a keyed
-- multi-source envelope {"logs": {...}, "changes": {...}, ...} rather than a
-- bare LogEnrichment. Wrap legacy bare rows IN PLACE and BYTE-FOR-BYTE — the
-- inner object's stored bytes are preserved verbatim via string concat, so
-- ADR-0001 replay fidelity is exact (not merely semantic): the evidence pack
-- replays precisely what the LLM saw. enrichment_json is incident state, not
-- part of the hash-chained audit log, so this structural wrap touches no hash.
--
-- No injection vector (log text flows into enrichment_json):
--   1. NOT SQL injection — enrichment_json is a COLUMN reference; SQLite
--      concatenates the stored VALUE at the engine level. Column content can
--      never become SQL (no query-string is built from it).
--   2. NOT JSON injection — by storage time Go's json.Marshal has escaped every
--      log character into a JSON string literal (" -> \", <>& -> \uXXXX, control
--      chars -> \uXXXX), so log text is inert string data inside the object.
--   3. Guarded — json_valid() re-confirms the whole value is one well-formed
--      JSON object before wrapping, so '{"logs":' || <valid object> || '}' is
--      always well-formed.
-- Guarded to touch ONLY bare rows: non-null, valid JSON, has a top-level
-- "source" key (every LogEnrichment does), and lacks any envelope key.
UPDATE incidents
SET enrichment_json = '{"logs":' || enrichment_json || '}'
WHERE enrichment_json IS NOT NULL
  AND json_valid(enrichment_json)
  AND json_extract(enrichment_json, '$.source') IS NOT NULL
  AND json_extract(enrichment_json, '$.logs') IS NULL
  AND json_extract(enrichment_json, '$.changes') IS NULL;
