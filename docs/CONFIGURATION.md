# Configuration Reference

All configuration is in YAML. Start from `config.example.yaml` at the repo root.

Secrets are **never** stored inline. Fields named `*_env` hold the **name** of the environment variable; the value is read at startup.

---

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

---

## `storage`

| Field | Type | Default | Description |
|---|---|---|---|
| `sqlite_path` | string | `./alertint-agent.db` | Path to the SQLite database file. The directory must be writable. |

---

## `llm`

| Field | Type | Default | Description |
|---|---|---|---|
| `provider` | string | `anthropic` | Only `anthropic` is supported today |
| `api_key_env` | string | — | **Required.** Env var name holding the Anthropic API key |
| `model` | string | `claude-haiku-4-5-20251001` | Anthropic model ID |

---

## `correlator`

| Field | Type | Default | Description |
|---|---|---|---|
| `window_seconds` | int | `90` | Alerts sharing the same group key within this window form one incident |
| `min_alerts` | int | `2` | Minimum alerts before the incident is dispatched to the skill. Set to `1` for single-alert triage. |
| `group_labels` | []string | `[alertname, cluster, namespace, service]` | Label names used to compute the group key. Two alerts are correlated when all of these labels match. |

---

## `notify`

| Field | Type | Default | Description |
|---|---|---|---|
| `stdout` | bool | `true` | Emit one JSON line per finding to stdout. Recommended to leave on. |
| `slack.enabled` | bool | `false` | Post a Blocks message to a Slack channel via the bot-token API (thread-updated on resolve) |
| `slack.bot_token_env` | string | — | Required when `slack.enabled: true`. Env var name holding the Slack bot token (`xoxb-…`, requires the `chat:write` scope) |
| `slack.channel` | string | — | Required when `slack.enabled: true`. Channel name (e.g. `#alerts`) or ID (e.g. `C1234567890`) |

---

## `mcp`

When enabled, `alertint serve` starts a second HTTP listener — a Streamable HTTP MCP server — that AI coding agents (Claude Code, Cursor, Windsurf) connect to for read-only incident, alert, evidence, audit, and Prometheus tools.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Start the MCP HTTP server inside `serve` |
| `addr` | string | `"0.0.0.0:9912"` | TCP address the MCP server binds to. Endpoint is `http://host:9912/mcp` |
| `token_env` | string | — | Env var name holding the MCP bearer token. Default env var is `ALERTINT_MCP_TOKEN` |

Clients authenticate with `Authorization: Bearer <token>`. See [`examples/mcp-clients/`](../examples/mcp-clients/) for copy-paste client configs.

---

## `prometheus`

Prometheus configuration enables the read-only Prometheus MCP tools for deeper metric context. It is optional.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `false` | Enables read-only Prometheus MCP tools |
| `base_url` | string | — | Prometheus HTTP API base URL |
| `bearer_token_env` | string | — | Optional env var name holding a bearer token for Prometheus |
| `timeout_seconds` | int | `10` | Timeout for Prometheus HTTP requests |
| `default_range_minutes` | int | `60` | Default range used by helper examples and MCP query guidance |

Config shape:

```yaml
prometheus:
  enabled: false
  base_url: http://localhost:9090
  bearer_token_env: PROMETHEUS_BEARER_TOKEN
  timeout_seconds: 10
  default_range_minutes: 60
```

---

## `rules`

The embedded baseline rule pack always loads. `local_pack_dir` optionally adds
one local pack directory whose rules and templates override baseline entries
with the same id or name. The directory must follow the standard pack layout
(`pack.yaml`, `rules/*.yaml`, `templates/*.md`) described in
[`rules-spec.md`](rules-spec.md); see [`examples/rules/`](../examples/rules/)
for a working starter pack.

| Field | Type | Default | Description |
|---|---|---|---|
| `local_pack_dir` | string | — | Optional path to a local rule pack directory. Must exist and contain `pack.yaml`. |

---

## `log_level`

One of `debug`, `info`, `warn`, `error`. Default: `info`.

---

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
  enabled: false
  addr: "0.0.0.0:9912"
  token_env: ALERTINT_MCP_TOKEN

rules:
  local_pack_dir: /etc/alertint/rules

prometheus:
  enabled: false
  base_url: http://localhost:9090
  timeout_seconds: 10
  default_range_minutes: 60

log_level: info
```

---

## Integration health

At startup the agent probes every **enabled** integration (Prometheus via a
trivial instant query, Slack via `auth.test`) and logs one line per
integration:

```
level=INFO  msg="integration health: OK"     integration=prometheus detail=http://prometheus:9090
level=WARN  msg="integration health: FAILED" integration=slack      detail=#alerts err="invalid_auth"
```

`GET /health` includes the same statuses (cached for 60 s). The top-level
`status` field reflects only agent liveness — a failing integration is
informational and never makes an orchestrator restart the agent:

```json
{"status":"ok","integrations":[{"name":"prometheus","detail":"http://prometheus:9090","ok":true,"checked_at":"..."}]}
```
