-- Resolve an Incident member's authoritative delivery without scanning and
-- sorting the retained delivery ledger. The expressions mirror
-- unresolvedIncidentMembersTx's RFC3339Nano chronological ordering.
CREATE INDEX alert_deliveries_alert_authority_idx ON alert_deliveries (
    alert_id,
    (substr(COALESCE(source_started_at, received_at), 1, 19) || '.' ||
     substr(ltrim(rtrim(substr(COALESCE(source_started_at, received_at), 20), 'Z'), '.') || '000000000', 1, 9)) DESC,
    (substr(received_at, 1, 19) || '.' ||
     substr(ltrim(rtrim(substr(received_at, 20), 'Z'), '.') || '000000000', 1, 9)) DESC,
    id DESC,
    status
);
