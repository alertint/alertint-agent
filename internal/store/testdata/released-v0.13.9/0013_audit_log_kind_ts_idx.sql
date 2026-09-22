-- 0013_audit_log_kind_ts_idx.sql
-- Composite (kind, ts) index on the audit log so kind-scoped, time-windowed
-- reads (alertint_usage_stats: alert.received, notify.sent, llm.response over
-- [since, until)) walk only the window instead of every row of that kind
-- ever written. The single-column kind index is a strict prefix of the new
-- one and is dropped as redundant; audit_log_ts_idx stays for unscoped
-- time-range reads.

CREATE INDEX audit_log_kind_ts_idx ON audit_log(kind, ts);
DROP INDEX audit_log_kind_idx;
