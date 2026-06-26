-- 0007_connector_state.sql
-- Generic per-connector cursor store: one row per named connector. The Sentry
-- release/deploy poller persists its watermark JSON here
-- ({last_emitted_at, boundary_deploy_ids}) so it never re-emits an already-seen
-- deploy across cycles or restarts. value is opaque JSON owned by the connector;
-- the store only round-trips it by name. Deliberately generic so later pull
-- connectors (Specs 2/3) can store their own cursors under their own names
-- without another migration. STRICT for the same type-safety reasons as 0005/0006.
CREATE TABLE connector_state (
    name       TEXT NOT NULL PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL
) STRICT;
