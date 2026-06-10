# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-06-10

### Added

- **Alertmanager webhook receiver** — `POST /webhook/alertmanager` accepts Alertmanager v4
  payloads with bearer-token auth; deduplicates alerts by fingerprint into SQLite.
- **Fixed-window correlator** — groups alerts by configurable labels within a time window;
  dispatches incidents when the window expires.
- **Acute-triage skill** — builds an evidence pack (shared labels, timeline, severity
  distribution, top annotations) and calls the Anthropic Claude API to produce a
  structured finding (summary, root cause, confidence, per-alert roles).
- **Notifiers** — stdout (JSON), human-readable console, and optional Slack delivery via the
  bot-token API (`chat.postMessage`) with in-thread resolution updates.
  Resolution events are also forwarded through all configured notifiers.
- **MCP HTTP server** — `alertint serve` exposes `:9912/mcp` when `mcp.enabled: true`.
  Five read-only tools: `alertint_list_incidents`, `alertint_get_incident`,
  `alertint_search_alerts`, `alertint_get_evidence_pack`, `alertint_verify_audit`.
  Compatible with Claude Code, Cursor, and Windsurf.
- **Prometheus read connector** — optional read-only PromQL client; powers two MCP tools
  (`prometheus_query`, `prometheus_query_range`) for live metric context during investigation.
  Also enriches the LLM prompt with relevant metric values at triage time.
- **Hash-chained audit log** — every action (alert received, LLM call, notification sent)
  appends a SHA-256-chained row. `alertint verify-audit` detects any tampering.
- **Health endpoint** — `GET /health` on the webhook port returns `{"status":"ok"}` when
  SQLite is reachable; used as the Docker healthcheck.
- **`alertint health` subcommand** — probes `GET /health` and exits 0/1; safe to use as a
  Docker `CMD` healthcheck on scratch-based images with no shell.
- **MCP client examples** — copy-paste configs for Claude Code, Cursor, and Windsurf under
  `examples/mcp-clients/`.
- **Docker Compose dev stack** — Alertmanager + AlertINT agent + Prometheus + Pushgateway;
  synthetic metric script for local testing.
- **Single static binary** — pure-Go SQLite (no CGO), no external runtime dependencies.
  Multi-platform builds: `linux/amd64`, `linux/arm64`, `darwin/arm64`.

[Unreleased]: https://github.com/alertint/alertint-agent/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alertint/alertint-agent/releases/tag/v0.1.0
