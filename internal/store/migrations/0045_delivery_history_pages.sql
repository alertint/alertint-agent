-- SPDX-License-Identifier: FSL-1.1-ALv2
-- Keyset paging of an Alert's immutable deliveries must not sort its retained
-- source-episode history for every page. The authority index serves a different order.
CREATE INDEX alert_deliveries_alert_id_page_idx ON alert_deliveries(alert_id, id);

-- Expected-judgment authority uses source time with missing values ordered
-- before known episodes, matching situation.deliveryLess exactly.
CREATE INDEX alert_deliveries_judgment_authority_idx ON alert_deliveries (
    alert_id,
    (substr(COALESCE(source_started_at,'0001-01-01T00:00:00Z'),1,19)||'.'||substr(ltrim(rtrim(substr(COALESCE(source_started_at,'0001-01-01T00:00:00Z'),20),'Z'),'.')||'000000000',1,9)) DESC,
    (substr(received_at,1,19)||'.'||substr(ltrim(rtrim(substr(received_at,20),'Z'),'.')||'000000000',1,9)) DESC,
    id DESC
);

-- Enumerating owned Alert keys must not rejoin every retained delivery during
-- atomic expected-judgment checks. This distinct key projection carries no
-- payload or source authority; the immutable ledger remains the source of truth.
CREATE TABLE incident_delivery_alerts (
    incident_id TEXT NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    alert_id TEXT NOT NULL REFERENCES alerts(id),
    PRIMARY KEY (incident_id, alert_id)
) STRICT;
INSERT INTO incident_delivery_alerts(incident_id,alert_id)
SELECT DISTINCT owner.incident_id,ad.alert_id FROM incident_alert_deliveries owner
JOIN alert_deliveries ad ON ad.id=owner.delivery_id;
CREATE TRIGGER incident_delivery_alerts_on_ownership AFTER INSERT ON incident_alert_deliveries
BEGIN
    INSERT INTO incident_delivery_alerts(incident_id,alert_id)
    SELECT NEW.incident_id,ad.alert_id FROM alert_deliveries ad WHERE ad.id=NEW.delivery_id
    ON CONFLICT(incident_id,alert_id) DO NOTHING;
END;
