---
title: "Configuration"
description: "Complete YAML configuration reference for the AlertINT agent."
section: "Getting started"
order: 2
slug: "configuration"
---

# Configuration

**AlertINT** runs from a single YAML file plus environment-based secrets.
Start from `config.example.yaml` at the repo root.

Secrets are **never** stored inline. Fields named `*_env` hold the
**name** of an environment variable; the value is read at startup.

## `alertmanager`

The inbound Alertmanager webhook receiver. Enabled by default — it is the
only integration that is. Every integration section carries an `enabled`
flag; when a section is enabled, its required fields must be set or the
agent refuses to start. At least one of `alertmanager` or `mcp` must be
enabled.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Run the webhook receiver (also serves `GET /health`) |
| `webhook_addr` | string | `"0.0.0.0:9911"` | TCP address the HTTP server binds to |
| `webhook_token_env` | string | — | **Required when enabled.** Env var name holding the webhook bearer token |

The agent returns `401` for any request missing or mismatching the token.

## `storage`

| Field | Type | Default | Description |
|---|---|---|---|
| `sqlite_path` | string | `./alertint-agent.db` | Path to the SQLite database file. The directory must be writable. |

## `llm`

| Field | Type | Default | Description |
|---|---|---|---|
| `provider` | string | `anthropic` | Only `anthropic` is supported today |
| `api_key_env` | string | — | **Required.** Env var name holding the Anthropic API key |
| `model` | string | `claude-haiku-4-5-20251001` | Anthropic model ID used for incident analysis |

This is the model that triages your incidents and writes the finding
summaries, so every dispatched incident consumes Anthropic API tokens.
The Haiku default keeps per-incident cost low; if you switch to a larger
model, keep an eye on your spend in the Anthropic console — the agent
does not yet meter or cap usage (budget tracking is planned).

## `correlator`

| Field | Type | Default | Description |
|---|---|---|---|
| `window_seconds` | int | `90` | Alerts sharing the same group key within this window form one incident |
| `min_alerts` | int | `2` | Minimum alerts before the incident is dispatched to the skill. Set to `1` for single-alert triage. |
| `group_labels` | list | `[alertname, cluster, namespace, service]` | Label names used to compute the group key. Two alerts are correlated when all of these labels match. |

`window_seconds` is a tradeoff. A lower value reacts faster, but an
incident may be analyzed with only the first alert or two of a burst
grouped in; a higher value waits to gather more related alerts — more
context for the analysis — at the cost of a slower first finding.

## `notify`

| Field | Type | Default | Description |
|---|---|---|---|
| `stdout` | bool | `true` | Deliver the finding to **stdout** as one JSON line. The full JSON is verbose detail: it is written **only at `--log-level=debug`** (consistently, in every format). At `info` the sink is still active — a send is confirmed on the `notified` line — but no JSON is written; the result shows as the one-line `finding` summary instead. Recommended to leave on. |
| `slack.enabled` | bool | `false` | Post a Block Kit message to a Slack channel via the bot-token API (message updated in-place on resolve) |
| `slack.bot_token_env` | string | — | Required when `slack.enabled: true`. Env var name holding the Slack bot token (`xoxb-…`, requires the `chat:write` scope) |
| `slack.channel` | string | — | Required when `slack.enabled: true`. Channel name (e.g. `#alerts`) or ID (e.g. `C1234567890`) |

At startup the agent logs one `notifiers ready` line listing the active sinks
(and the Slack channel) so you can see where findings will go. Every analysis
then logs, at INFO regardless of format:

- one human-readable `finding` summary (severity, confidence, alert count,
  incident id, analysis name) — the live-watch view of the result; and
- one `notified` line confirming delivery per sink (`notified · stdout=ok
  slack=ok …`), so a send — or a sink-specific failure — is never silent.

The full JSON finding (`notify.stdout`, above) is the verbose machine
representation, reserved for `--log-level=debug`.

See [Slack](../notifications/slack.md) for the full setup walkthrough.

## `mcp`

When enabled, `alertint serve` starts a second HTTP listener — a
Streamable HTTP MCP server — that AI coding agents (Claude Code, Cursor,
Windsurf) connect to for incident, alert, evidence, audit, and Prometheus
tools.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Start the MCP HTTP server inside `serve` |
| `addr` | string | `"0.0.0.0:9912"` | TCP address the MCP server binds to. Endpoint is `http://host:9912/mcp` |
| `token_env` | string | — | Env var name holding the MCP bearer token. Default env var is `ALERTINT_MCP_TOKEN` |

Clients authenticate with `Authorization: Bearer <token>`. See
[MCP clients](../integrations/mcp-clients.md) for copy-paste client
configs.

## `prometheus`

Optional read connector. When enabled it adds live metric values to LLM
triage prompts and exposes PromQL tools over MCP. See
[Prometheus](../integrations/prometheus.md) for details.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Activate the Prometheus connector |
| `base_url` | string | — | Prometheus HTTP API base URL, e.g. `http://localhost:9090` |
| `bearer_token_env` | string | — | Optional env var name holding a bearer token for Prometheus |
| `timeout_seconds` | int | `10` | Timeout for Prometheus HTTP requests |
| `default_range_minutes` | int | `60` | Default lookback window for range queries |

Set `bearer_token_env` only when your Prometheus requires authentication
— for example, when it sits behind an auth proxy or ingress that expects
an `Authorization: Bearer <token>` header. Name the env var that holds
that token and export it before starting the agent. A plain,
unauthenticated Prometheus needs only `base_url`.

## `rules`

The embedded baseline rule pack always loads. `local_pack_dir` optionally
adds one local pack directory whose rules and templates override baseline
entries with the same id or name. The directory must follow the standard
pack layout (`pack.yaml`, `rules/*.yaml`, `templates/*.md`); see
`examples/rules/` in the repo for a working starter pack.

| Field | Type | Default | Description |
|---|---|---|---|
| `local_pack_dir` | string | — | Optional path to a local rule pack directory. Must exist and contain `pack.yaml`. |

## `log_level`

One of `debug`, `info`, `warn`, `error`. Default: `info`.

## `log_format`

How log records are rendered. One of `auto`, `console`, `json`. Default:
`auto`.

| Value | Behavior |
|---|---|
| `auto` | Resolves to `console` when the log stream (stderr) is a terminal, `json` otherwise — so an interactive run is readable while a container or pipe stays machine-parseable. |
| `console` | One human-readable, colored line per record (`HH:MM:SS LEVEL message · key=value …`). Color is emitted only on a TTY with `NO_COLOR` unset; redirected to a file it is plain text. |
| `json` | One compact JSON object per record, for log shipping and aggregation. The stdout JSON finding line is unaffected by this setting. |

> The legacy `text` format (slog's raw `key=value`) was **removed**. It is not
> aliased — setting `log_format: text` fails loudly at startup rather than
> silently re-rendering as `console` and breaking a `key=value` parser.

Resolution keys off **stderr** (the log stream), not stdout, so a redirect
like `alertint serve > out.txt` still shows the colored action trail on your
terminal. To capture findings as machine-readable JSON for piping, run with
`--log-level=debug` — see [`notify.stdout`](#notify). At `info` (any format) the
finding appears as a one-line summary in the trail plus a `notified` line.

When the colored console stream is captured and replayed to a terminal — e.g.
`docker logs` / `docker compose logs`, where the container's stderr is not a
TTY — set `CLICOLOR_FORCE=1` in the environment to force color on anyway.
`NO_COLOR` still overrides it.

### Level × format

The two axes are orthogonal — level controls *how much* is logged, format
controls *how it is rendered*:

| | `console` | `json` |
|---|---|---|
| `info` (default) | clean one-line action trail — the live-watch view | compact JSON for shipping |
| `debug` | action trail plus extra detail lines | full verbose JSON for troubleshooting |

### Precedence and overrides

The `--log-level` and `--log-format` CLI flags override the config values,
which override the built-in defaults (`info` / `auto`):

```text
CLI flag  >  config (log_level / log_format)  >  built-in default
```

An unset flag (the default) falls through to config, so the flags are for
one-off overrides — e.g. `alertint serve --config alertint.yaml --log-format json`.

## Full example

```yaml
alertmanager:
  enabled: true
  webhook_addr: "0.0.0.0:9911"
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN

storage:
  sqlite_path: /var/lib/alertint/alertint.db

llm:
  provider: anthropic
  api_key_env: ANTHROPIC_API_KEY
  model: claude-haiku-4-5-20251001

correlator:
  window_seconds: 90
  min_alerts: 1
  group_labels:
    - alertname
    - cluster
    - namespace
    - service

notify:
  stdout: true
  slack:
    enabled: true
    bot_token_env: SLACK_BOT_TOKEN
    channel: "#alerts"

mcp:
  enabled: true
  addr: "0.0.0.0:9912"
  token_env: ALERTINT_MCP_TOKEN

rules:
  local_pack_dir: /etc/alertint/rules

prometheus:
  enabled: true
  base_url: http://localhost:9090
  bearer_token_env: PROMETHEUS_BEARER_TOKEN
  timeout_seconds: 10
  default_range_minutes: 60

log_level: info
log_format: auto
```

## Integration health

At startup the agent probes every **enabled** integration (Prometheus via
a trivial instant query, Slack via `auth.test`) and logs one line per
integration:

```text
15:04:05 INFO  integration health: OK · integration=prometheus detail=http://prometheus:9090
15:04:05 WARN  integration health: FAILED · integration=slack detail=#alerts err=invalid_auth
```

(shown in the default `console` format; with `log_format: json` the same
records render as one JSON object per line.)

`GET /health` includes the same statuses (cached for 60 s). The top-level
`status` field reflects only agent liveness — a failing integration is
informational and never makes an orchestrator restart the agent:

```json
{"status":"ok","integrations":[{"name":"prometheus","detail":"http://prometheus:9090","ok":true,"checked_at":"..."}]}
```
