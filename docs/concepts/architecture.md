---
title: "Architecture"
description: "One self-hosted binary sits between Alertmanager and your AI agent, and turns raw alerts into context worth investigating."
section: "Concepts"
order: 1
slug: "architecture"
---

# Architecture

One self-hosted binary sits between Alertmanager and your AI agent, and
turns raw alerts into context worth investigating. Everything below runs
inside a single `alertint serve` process with local SQLite state.

```text
Alertmanager ──webhook──▶ ingest ──▶ correlate ──▶ AI synthesis ──▶ notify (stdout / Slack)
                                          │
                                          ▼
                              local state (SQLite)
                                          ▲
AI agent (Claude Code, …) ◀──MCP──▶ MCP server ──▶ Prometheus (PromQL)
```

## Phase 1 — Ingest

### 1. Webhook transmission

Alertmanager fires a POST to the **AlertINT** webhook receiver over HTTP(S).
The payload is the standard Alertmanager webhook JSON — no custom format
required.

- **Protocol:** HTTP POST, Alertmanager webhook payload (version 4)
- **Auth:** Bearer token (env var named by `alertmanager.webhook_token_env`,
  default `ALERTINT_WEBHOOK_TOKEN`)

### 2. Persistence and deduplication

Received alerts are written to local state (SQLite). Duplicate firings of
the same alert fingerprint are collapsed — one record per logical alert.

- **Storage:** local SQLite, configurable path
- **Dedup key:** Alertmanager alert fingerprint

### 3. Correlation

Alerts that fire within a configurable time window and share common label
dimensions (`alertname`, `cluster`, `namespace`, `service` by default) are
grouped into a single incident record. Grouping is deterministic and
re-evaluated as new alerts arrive.

- **Grouping keys:** `correlator.group_labels`
- **Window:** `correlator.window_seconds`, default 90 s

### 4. AI synthesis

Once an incident's window closes, **AlertINT** builds an evidence pack (shared
labels, timeline, annotations — optionally enriched with live Prometheus
metric values) and sends it to the configured LLM (Anthropic Claude). The
model returns a structured finding: probable cause, severity assessment,
confidence, and suggested next checks. The finding is stored locally
alongside the incident.

- **Model:** Anthropic Claude (`claude-haiku-4-5-20251001` by default)
- **Auth:** `ANTHROPIC_API_KEY` env var
- **Output:** structured finding, persisted in local state

### 5. Outbound notification

The finding is emitted as one JSON line on stdout and, when configured,
posted to a Slack channel. When all alerts recover, **AlertINT** updates the
original Slack message in-place (🔴 → ✅) and posts a short resolution
note in the thread.

- **Method:** stdout (always available) and Slack Bot Token API
  (`chat.postMessage` / `chat.update`)

## Phase 2 — Investigate

### 6. Agent entry via MCP

An engineer opens their MCP-capable AI client (Claude Code, Cursor,
Windsurf, or any MCP-compatible tool) pointed at the **AlertINT** MCP server,
which runs as part of the same binary — no separate daemon.

- **Transport:** Streamable HTTP, `http://host:9912/mcp`
- **Auth:** Bearer token (env var named by `mcp.token_env`)

### 7. Evidence query

The agent calls **AlertINT** MCP tools to list recent incidents, retrieve
alert payloads, evidence packs, and stored findings. All data is served
from local state — no external calls at this stage.

- **MCP tools:** `alertint_list_incidents`, `alertint_get_incident`,
  `alertint_search_alerts`, `alertint_get_evidence_pack`,
  `alertint_verify_audit`

### 8. Telemetry context

The agent issues PromQL queries through **AlertINT** MCP tools. **AlertINT**
proxies the query to the configured Prometheus instance and returns the
result — CPU, memory, latency, error rate, or any metric stored in
Prometheus, scoped to the incident time window.

- **MCP tools:** `prometheus_query`, `prometheus_query_range`
- **Backend:** Prometheus HTTP API (queries only)

### 9. Decision point

The agent synthesizes alert payloads, the stored finding, and live metric
context into a response. The engineer decides the next action — re-query,
escalate, or begin remediation — with full context already in the
conversation. **AlertINT**'s role ends at providing context; the next step is
engineer-controlled.

## MCP-first investigation

The MCP server is the primary way you and your agent interact with
**AlertINT** — there is no web UI. Typical prompts:

```text
List recent AlertINT incidents.
Open the latest critical incident and summarize the evidence.
Show the alert labels and annotations for this incident.
Query Prometheus for CPU and memory around the incident window.
Compare the finding with the metric trend and suggest next checks.
```

## Incident lifecycle

```text
collecting  →  ready  →  (skill running)  →  analyzed
                                          →  failed
```

- `collecting`: window is open, alerts arriving
- `ready`: window expired, incident dispatched to the triage skill
- `analyzed`: LLM output persisted
- `failed`: LLM call or persistence error (logged; retry is on the roadmap)

## Audit log

Every action appends a hash-chained row to the local audit log:

```text
hash = SHA256( ts FS actor FS kind FS canonical_json(payload) FS prev_hash )
```

`FS` is the ASCII unit separator `0x1f`. Each row's hash covers the
previous row, so any tampering is detectable with `alertint verify-audit`
or the `alertint_verify_audit` MCP tool.

## Design constraints

- **No silent config drift** — unknown YAML keys are rejected at load time.
- **No inline secrets** — all secret values come from env vars named by
  config fields.
- **No 5xx to Alertmanager** — ingress always returns 2xx or 4xx; errors
  are logged, not propagated upstream.
- **Single binary, SQLite state** — no external dependencies to install.
- **MCP-first investigation** — local context is exposed through the MCP
  server; there is no web UI.
