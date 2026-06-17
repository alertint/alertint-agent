-- 0004_incidents_enrichment.sql
-- Persist log enrichment with the incident so the evidence pack can replay it.
--
-- This nullable column stores the marshaled *LogEnrichment snapshot (source,
-- native query, window, normalized newest-first lines, or a note explaining an
-- empty/failed fetch). The acute-triage skill writes it once in the LLM path and
-- the MCP evidence pack replays it verbatim — no live log-backend call at
-- pack-fetch time, even after the backend's retention has rotated the source
-- lines. A purely additive column add (like 0003), safe over an existing DB.

ALTER TABLE incidents ADD COLUMN enrichment_json TEXT;
