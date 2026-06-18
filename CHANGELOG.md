# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Loki log-enrichment connector** — optional read-only Loki/Grafana-Cloud-Logs client.
  At triage time it enriches the LLM prompt with the most relevant recent log lines
  (error-biased filtered query, with one unfiltered fallback), translating the incident's
  shared alert labels into LogQL via a configurable `label_map`. The exact lines the model
  saw are persisted with the finding and replayed by `alertint_get_evidence_pack`.
- **`loki_query_range` MCP tool** — read-only native-LogQL range query, registered when the
  Loki connector is enabled, so an investigating agent can drill into logs over MCP.
- **Demo log stack** — bundled Loki service in the Docker Compose dev stack plus
  `docker/push-synthetic-logs.py` (`task logs:push:local` / `task logs:push:cloud`) to seed
  fake multi-level log lines for local Loki or Grafana Cloud.
- **Human-readable `console` log format** — a colored, one-line-per-event format
  (`HH:MM:SS LEVEL  message · key=value …`) for live watching, plus an `auto` default that
  resolves to `console` on a terminal and `json` otherwise (keyed off stderr). Selectable
  via `log_format: auto | console | json` (config) or `--log-format`, with precedence
  CLI flag > config > default. `CLICOLOR_FORCE` forces color when the stream is not a TTY
  (e.g. `docker logs`); `NO_COLOR` always disables it.
- **Operator action trail** — every meaningful action emits one INFO line that stands alone
  with incident context: `webhook received`, `loki fetched`, `llm responded`, `finding`,
  `notified` / `notify partial` / `notify failed`, `triage done`, plus a `notifiers ready`
  line at startup listing the active sinks (and the Slack channel).
- **Per-sink notification outcomes** — `Notifier.Name()` and a `Multi`-owned outcome line
  name each sink `ok`/`FAIL`; any failure additionally logs one detail line per failing sink
  carrying the full wrapped error (Slack includes the channel). Closes the silent-Slack-send
  gap.
- **Dev convenience** — `task docker:logs` / `task docker:up:logs` follow the agent container
  with color intact; `CLICOLOR_FORCE=1` is set in the Compose dev stack.

### Changed

- **Default log format** flips from JSON to `auto` (console on a terminal, json otherwise);
  non-TTY deployments (compose, pipes, journald) are unchanged.
- **Log level/format are now config-driven** — the previously-dead `log_level` config value
  is applied, and config loads before the logger is built so the first `alertint starting`
  line honors it.
- **Cleaner INFO view** — chatty internals (per-alert upsert, correlator bookkeeping,
  selector derivation) moved to DEBUG; the default view reads as the action trail.
- **Finding output** — the full machine-readable JSON finding to stdout is reserved for
  `--log-level=debug`; at INFO the finding shows as a one-line `finding` summary while the
  stdout sink still confirms delivery on the `notified` line.
- **Anthropic client** — `Complete` now returns token usage and latency so the caller emits
  `llm responded` without re-deriving them.

### Removed

- **`text` log format** (breaking) — removed and not aliased; an unknown `log_format`
  (including `text`) fails loud at startup. The slog `TextHandler` and the separate 3-line
  "card" finding notifier are gone — the finding is now the one-line `finding` summary.

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
