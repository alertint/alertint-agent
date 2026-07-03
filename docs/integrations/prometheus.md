---
title: "Prometheus"
description: "Connect Alertmanager as the alert source and Prometheus for live metric context."
section: "Integrations"
order: 1
slug: "prometheus"
---

# Prometheus

**AlertINT** integrates with the Prometheus ecosystem in two places:
**Alertmanager** is the alert source — it forwards a webhook copy of every
alert to the agent — and the optional **Prometheus connector** enriches
LLM triage with live metric values at incident time and powers PromQL
tools for MCP-driven investigation. The connector only issues queries; it
never writes metrics, creates recording rules, or modifies Prometheus
state.

Prometheus is the **recommended first evidence source**: if you run
Alertmanager, you almost certainly run Prometheus, and connecting it is
what lifts findings past the metadata-only confidence cap — with live
metric values, the triage argues from evidence instead of annotations
alone.

## Alertmanager — the alert source

Add an `alertint-agent` receiver to your `alertmanager.yml` and route
alerts to it. A complete minimal config ships in the repo as
`examples/alertmanager.yml`:

```yaml
route:
  receiver: alertint-agent
  group_by: [alertname, cluster, namespace, service]
  group_wait: 10s
  group_interval: 30s
  repeat_interval: 4h

receivers:
  - name: alertint-agent
    webhook_configs:
      - url: "http://<agent-host>:9911/webhook/alertmanager"
        send_resolved: true
        http_config:
          authorization:
            credentials_file: /etc/alertmanager/alertint_token
```

Notes:

- The bearer token must match the value of the env var named by
  `alertmanager.webhook_token_env` in the agent config (default
  `ALERTINT_WEBHOOK_TOKEN`). Prefer `credentials_file` over an inline
  credential so the token is not stored in `alertmanager.yml`.
- `send_resolved: true` is required for resolution tracking — it lets
  **AlertINT** close incidents and update Slack messages when alerts recover.
- To keep your existing paging intact, add `alertint-agent` as a child
  route with `continue: true` instead of replacing your top-level
  receiver.

## Prometheus connector — live metric context

### How it works

When an incident is ready for analysis, **AlertINT** queries
`{instance="X"}` at the incident start time for each unique `instance`
label in the alert group. Up to 10 non-system metric values per instance
are appended to the LLM prompt as a *Live metrics* section. The model uses
those values to calibrate severity and confidence — actual numbers take
precedence over text annotations.

### Configuration

```yaml
prometheus:
  base_url: http://localhost:9090            # setting this turns the connector ON
  # enabled: false                           # uncomment to force OFF despite base_url
  bearer_token_env: PROMETHEUS_BEARER_TOKEN  # optional
  timeout_seconds: 10                        # default
  default_range_minutes: 60                  # default
```

Enablement is presence-based: setting `base_url` turns the connector on
automatically; an explicit `enabled: false` forces it off.

| Field | Description |
|---|---|
| `enabled` | Optional. Omitted = on when `base_url` is set; `false` forces off. |
| `base_url` | Base URL of your Prometheus instance, e.g. `http://localhost:9090`. |
| `bearer_token_env` | Optional. Name of the env var holding the Prometheus bearer token. |
| `timeout_seconds` | HTTP timeout for Prometheus queries. Default: `10`. |
| `default_range_minutes` | Default lookback window for range queries. Default: `60`. |

### MCP tools

When Prometheus is enabled, two additional tools become available to your
MCP client:

| Tool | Description |
|---|---|
| `prometheus_query` | Instant PromQL query. Parameters: `expr` (required), `time` (optional ISO 8601). |
| `prometheus_query_range` | Range PromQL query with auto-stepped resolution. Parameters: `expr`, `start`, `end` (ISO 8601), `step` (optional). |

### Example queries

Ask your agent in natural language — **AlertINT** handles the PromQL via MCP:

```text
Query CPU usage for instance api-1 right now.
Show me the error rate for the last 30 minutes.
What was the latency trend during this incident?
```

Or pass PromQL directly to the `prometheus_query` tool:

```text
cpu_usage_percent{instance="api-1"}
rate(http_errors_total[5m])
```
