---
title: "Loki"
description: "Enrich triage prompts with recent log lines from Grafana Loki or Grafana Cloud, and query logs over MCP."
section: "Integrations"
order: 2
slug: "loki"
---

# Loki

The optional **Loki connector** enriches LLM triage with the most relevant
recent log lines at incident time, and exposes a read-only `loki_query_range`
tool so an investigating AI agent can drill deeper over MCP. It works with both
self-hosted **Loki** and **Grafana Cloud Logs** — the same backend, different
auth. Like the Prometheus connector it only ever issues queries; it never
writes, tails, or streams logs.

## Map your labels (read this first)

The single most common first-run failure is a **label-namespace mismatch**, so
fix it before anything else.

Alert labels are **not** Loki stream labels. They come from different systems:

| Where | Vocabulary | Typical keys |
|---|---|---|
| **Alert labels** (Prometheus/Alertmanager) | what the correlator and rules speak | `job`, `instance`, `service`, `namespace` |
| **Stream labels** (Loki, set by Promtail/Alloy/OTel) | what Loki indexes log streams by | `namespace`, `app`, `container`, `pod` |

So `service` is frequently `app`, and `job` / `instance` often have **no**
stream-label equivalent at all. AlertINT builds a generic selector from the
incident's shared alert labels (intersected with the allowlist
`namespace, service, job, pod, container, instance`), then the Loki provider
**translates** it into LogQL using your `label_map`:

```yaml
logs:
  loki:
    label_map:
      service: app       # rename alert label `service` → stream label `app`
      instance: ""        # drop: no Loki stream-label equivalent
```

- A key mapped to a new name is **renamed**.
- A key mapped to `""` is **dropped**.
- A key not in `label_map` passes through unchanged.

If no label survives translation, or the translated selector matches no
streams, the prompt records the gap (it never pretends logs were healthy) and
the agent logs an info breadcrumb naming the exact query it ran:

```text
acutetriage: logs: query returned no lines — check label_map / line_filter  source=loki  query={namespace="prod",app="api"}
```

That breadcrumb is your signal that enrichment is wired but the selector or
schema doesn't match — almost always a missing `label_map` entry.

### Find your real stream-label keys

Use whichever you have:

```bash
# logcli (self-hosted or Grafana Cloud)
logcli labels
logcli labels app          # values for a given label
```

Or in Grafana: **Explore → (Loki data source) → Label browser**, which lists the
stream-label keys and values Loki actually has.

## How enrichment works

When an incident is ready for analysis, AlertINT:

1. Builds the generic selector from the incident's shared alert labels.
2. Has the Loki provider translate it to a LogQL matcher via `label_map` and
   append the `line_filter`.
3. Runs an **error-biased filtered** range query first
   (`direction=backward`, newest `max_lines`). If that returns zero lines it
   issues **one** unfiltered fallback so apps whose format doesn't match the
   regex still get newest-N lines.
4. Merges lines across all matching streams, sorts them **newest-first**, caps
   them, and appends a *Recent logs* section to the prompt.

The exact lines the model saw are **persisted with the finding** and replayed
verbatim by the `alertint_get_evidence_pack` MCP tool — even after Loki
retention has rotated the source lines.

## Configuration

```yaml
logs:
  enabled: true
  provider: loki
  timeout_seconds: 10         # TOTAL budget for the whole fetch (filtered + fallback)
  default_range_minutes: 15   # look-back window before the first alert
  max_lines: 50               # backend query limit
  loki:
    base_url: http://loki:3100
    auth:
      mode: none              # none | bearer | basic
    line_filter: '|~ "(?i)(error|warn|fatal|panic|fail)"'  # default; "" disables
    label_map:
      service: app
      instance: ""
```

| Field | Description |
|---|---|
| `enabled` | Set to `true` to activate the Loki connector. |
| `provider` | Only `loki` in v1. |
| `timeout_seconds` | Total budget for the whole fetch (both passes share it). Default `10`. |
| `default_range_minutes` | Look-back window before the first alert. Default `15`. |
| `max_lines` | Maximum lines per query. Default `50`. |
| `loki.base_url` | Loki base URL, e.g. `http://loki:3100` or a Grafana Cloud `logs-prod-*.grafana.net` URL. |
| `loki.auth.mode` | `none`, `bearer`, or `basic`. Default `none`. |
| `loki.org_id` | Optional `X-Scope-OrgID` for self-hosted multi-tenant Loki. Leave empty for Grafana Cloud. |
| `loki.line_filter` | LogQL line filter appended to the matcher. Default error-biased; set `""` to disable. |
| `loki.label_map` | Alert-label key → stream-label key. `""` drops a key. See [Map your labels](#map-your-labels-read-this-first). |

Secrets are never inline — `*_env` fields name the env var holding the value.

### Self-hosted Loki (no auth)

```yaml
logs:
  enabled: true
  provider: loki
  loki:
    base_url: http://loki:3100
    auth:
      mode: none
    label_map:
      service: app
```

### Self-hosted Loki (bearer token)

```yaml
logs:
  enabled: true
  provider: loki
  loki:
    base_url: https://loki.internal.example.com
    auth:
      mode: bearer
      token_env: LOKI_BEARER_TOKEN
```

### Grafana Cloud Logs (basic auth)

For Grafana Cloud, `username` is your numeric instance/user ID and the password
is an Access Policy token with the `logs:read` scope.

```yaml
logs:
  enabled: true
  provider: loki
  loki:
    base_url: https://logs-prod-006.grafana.net
    auth:
      mode: basic
      username: "123456"
      password_env: GRAFANA_CLOUD_LOKI_TOKEN
    label_map:
      service: app
```

#### Get the values from the Portal, not the Grafana data source

Two traps snag almost everyone here. Avoid both:

1. **Two different websites.** Your **Grafana instance** (`https://<stack>.grafana.net`)
   is where you build dashboards. Your **Grafana Cloud Portal** (`https://grafana.com`)
   is where stacks, tokens, and connection details live. The Loki URL/User and the
   token both come from the **Portal**, not the instance.
2. **Two different Loki data sources.** In the instance under **Connections →
   Data sources** you'll see more than one Loki. One is your **application Loki**
   (`grafanacloud-<stack>-logs`, URL `https://logs-prod-NNN.grafana.net`); another
   is **Usage Insights** (`…-usage-insights`, URL `https://insight-logs-…`). They
   are different datasources — a token scoped to your stack's Loki returns
   `401 "the token is not authorized to query this datasource"` against the
   insights one. **You want the `logs-prod-…` host, not `insight-logs-…`.**

The reliable path for all three values:

| Config field | Where to find it |
|---|---|
| `base_url` | **Grafana Cloud Portal → your stack → Loki → "Send Logs"** (sometimes a small "Details"/settings link on the Loki tile). Shows the URL, e.g. `https://logs-prod-012.grafana.net`. It serves both query and push. |
| `auth.username` | The numeric **User** on that same "Send Logs" page, e.g. `1652330`. (Do **not** assume the number from a data-source page — that may be the insights instance.) |
| password (the token) | **Create one yourself:** Grafana Cloud Portal → **Security → Access Policies → Create access policy** (realm = your stack), scopes `logs:read` (add `logs:write` if you'll also push logs) → **Add token** and copy it (shown once, `glc_…`). Put it in the env var named by `password_env`. This is **not** the `Configured`/locked password shown on the instance's data-source page — that one is the Grafana instance's own provisioned secret, which you can neither read nor reuse. |

The read and write endpoints share the same host, so this one `base_url` works
for both enrichment (reads) and pushing test logs (writes). Leave `org_id`
empty — for Grafana Cloud the basic-auth `username` already selects the tenant,
so no `X-Scope-OrgID` is sent.

Quick sanity check before wiring the agent (a `200`, even with empty `data`,
means you're good — a `401` means wrong host, wrong user, or a token missing
`logs:read`):

```bash
curl -sG -u "<USER>:<glc_token>" \
  "https://logs-prod-NNN.grafana.net/loki/api/v1/query_range" \
  --data-urlencode 'query={app="worker"}' --data-urlencode 'limit=5' \
  -w '\nHTTP %{http_code}\n'
```

## MCP tool

When Loki is enabled, one additional read-only tool becomes available to your
MCP client:

| Tool | Description |
|---|---|
| `loki_query_range` | Range-query Loki with native **LogQL**. Parameters: `query` (required), `start`, `end` (RFC3339), `limit`, `direction` (`backward`/`forward`). |

The tool is named after the backend (`loki_query_range`) because it exposes
LogQL directly — the full power of the backend, not a reduced subset. `start`
defaults to now minus `default_range_minutes`.

### Example queries

Ask your agent in natural language — AlertINT handles the LogQL via MCP:

```text
Show me the error logs for service api in the last 30 minutes.
What did the database pod log right before the incident?
Grep the api logs for "connection refused" around the incident window.
```

Or pass LogQL directly to the `loki_query_range` tool:

```text
{app="api"} |= "panic"
{namespace="prod",app="api"} |~ "(?i)timeout"
```
