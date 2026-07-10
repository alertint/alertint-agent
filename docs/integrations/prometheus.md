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

When an incident is ready for analysis, **AlertINT** builds a generic
PromQL selector from the alert group's shared labels — the same
allowlist logs use (`namespace`, `service`, `job`, `pod`, `container`,
`instance`) — and queries it at the incident start time. This is what
makes Kubernetes-style alerts (labeled by `namespace`/`pod`/`container`,
often with no `instance` at all) get live metrics instead of falling
back to annotations-only: the old behavior queried `{instance="X"}`
alone, which most K8s alerting rules never set.

Two refinements keep the selector from missing evidence:

- **Per-instance supplement.** Any alert that does carry `instance`
  keeps at least that broad per-instance scope as an extra query, even
  when the shared selector narrows it away — non-Kubernetes stacks see
  the same coverage as before.
- **Physical-core retry.** If the full selector matches zero series
  (a logical label like `service` or `job` that an alerting rule
  attaches but no series actually has), AlertINT retries once with only
  the physical-identity keys (`namespace`, `pod`, `container`,
  `instance`) before concluding the query is genuinely empty.

Up to 10 non-system metric series are kept per query, ranked by how many
labels they share with the firing alerts (a series carrying the same
`pod` as a member alert outranks an unrelated series in the same
namespace) and appended to the LLM prompt as a *Live metrics* section.
The model uses those values to calibrate severity and confidence — actual
numbers take precedence over text annotations.

### Evidence line

Every finding notification carries a per-source evidence summary — how
many metrics, log lines, changes, and Sentry issues fed the triage, e.g.
`Prometheus 21 metrics · Loki 0 lines · Changes 2 · Sentry unreachable`.
A connector that could not be reached renders `unreachable`, distinct
from a genuine `0`, so a misconfigured or down connector is visible on
every card instead of silently degrading confidence. See
[Slack notifications](../notifications/slack.md#message-structure) for
where it appears on the card.

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

The connector speaks the standard Prometheus HTTP query API
(`/api/v1/query` and `/api/v1/query_range`), so anything implementing
that API works as `base_url`. A **Thanos Querier** is a drop-in — same
requests, same responses, same [authentication](#authentication) story
(Thanos likewise has no built-in auth) — and extends query reach to the
full retention window across all connected Prometheus instances. Note
its default HTTP port is 10902, not 9090, and point `base_url` at the
Querier component, not a Sidecar or Store Gateway.

| Field | Description |
|---|---|
| `enabled` | Optional. Omitted = on when `base_url` is set; `false` forces off. |
| `base_url` | Base URL of your Prometheus instance, e.g. `http://localhost:9090`. |
| `bearer_token_env` | Optional. Name of the env var holding the Prometheus bearer token — see [Authentication](#authentication) for when you need one and where it comes from. |
| `timeout_seconds` | HTTP timeout for Prometheus queries. Default: `10`. |
| `default_range_minutes` | Default lookback window for range queries. Default: `60`. |

### Authentication

Prometheus itself has **no bearer-token authentication** — there is
nothing to obtain from Prometheus. A bearer token only exists when
something *in front of* Prometheus checks it, so start by identifying
your setup:

```bash
curl "http://<prometheus-host>:9090/api/v1/query?query=up"
```

**Answers without credentials — plain Prometheus.** The default for
most self-hosted setups (including a vanilla kube-prometheus-stack
inside the cluster network). Omit `bearer_token_env`; `base_url` is the
whole configuration.

**Rejected, and you run a reverse proxy** (nginx, Traefik,
oauth2-proxy, …) **in front of Prometheus.** The token is one you make
up, exactly like the agent's own webhook tokens:

1. Generate a long random secret (any generator works).
2. Configure the proxy to require it as `Authorization: Bearer <secret>`.
3. Set `bearer_token_env: PROMETHEUS_BEARER_TOKEN` in the agent config
   and export `PROMETHEUS_BEARER_TOKEN=<secret>` in the agent's
   environment.

**Rejected, and the cluster's monitoring stack is managed** (OpenShift
cluster monitoring, or any Prometheus fronted by kube-rbac-proxy). The
token is a ServiceAccount token issued by the cluster:

1. Create a ServiceAccount and grant it metrics-read permission — on
   OpenShift, the `cluster-monitoring-view` cluster role.
2. Mint a token: `kubectl create token <sa> -n <namespace>
   --duration=8760h`. The default duration is one hour — too short,
   because the agent reads the token once at startup.
3. Point `base_url` at the *authenticated* query endpoint — on
   OpenShift that is Thanos Querier on port 9091, not Prometheus
   directly — and wire the token through `bearer_token_env` as above.

Whatever the source, verify the pair before starting the agent:

```bash
curl -H "Authorization: Bearer $PROMETHEUS_BEARER_TOKEN" \
  "<base_url>/api/v1/query?query=up"
```

The token is read once at `serve` startup; after rotating it, update
the env var and restart the agent.

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
