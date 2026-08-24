---
title: "Architecture"
description: "One self-hosted binary sits between your monitoring stack and your AI agent, and turns raw alerts into context worth investigating."
section: "Concepts"
order: 1
slug: "architecture"
---

# Architecture

Everything below runs inside a single `alertint serve` process with local
SQLite state — one binary, one config file, no external dependencies to
install.

Two feedback loops close on the triage step, and both are why the same
condition doesn't get the same wrong answer twice: the **verification round**
makes each analysis falsify its own draft before the finding persists, and an
operator **verdict** captured over MCP steers the next triage of that failure
group.

## Phase 1 — Ingest and triage

### 1. Webhook transmission

Alerts arrive over HTTP(S) from any of the first-class alert sources, each on
its own receiver, all mounted on the same listen address
([`receivers.address`](../getting-started/configuration.md#receivers), default
`:9911`) and each authenticated with its own bearer token:

| Source | Route | Payload |
|---|---|---|
| [Alertmanager](../getting-started/quickstart.md) | `POST /webhook/alertmanager` | Alertmanager webhook JSON (version 4) |
| [Zabbix](../integrations/zabbix.md) | `POST /webhook/zabbix` | Zabbix `PROBLEM` / `RESOLVED` events |
| [Change events](../integrations/changes.md) | `POST /webhook/change` | Deploys, config edits, flag flips |

The first two are **alert** sources and feed the same pipeline end to end —
a Zabbix shop gets correlated, triaged incidents exactly the way an
Alertmanager shop does. Change events are not alerts: they feed the *what
changed right before this?* plane that triage reads at analysis time, and can
also be polled from [Sentry](../integrations/sentry.md) releases and deploys
instead of pushed.

- **Auth:** Bearer token per receiver (env vars named by
  `alertmanager.webhook_token_env`, `zabbix.ingress.webhook_token_env`,
  `changes.ingress.webhook_token_env`)
- **No custom format required** on any of them

### 2. Persistence and deduplication

Received alerts are written to local state (SQLite). Duplicate firings of
the same alert fingerprint are collapsed — one record per logical alert.

- **Storage:** local SQLite, configurable path
- **Dedup key:** alert fingerprint

### 3. Correlation

Alerts that fire within a configurable time window and share a Receiver
grouping identity are grouped into one Incident. Alertmanager supplies its v4
webhook `groupLabels`, rendered deterministically as sorted `key=value` pairs;
Zabbix supplies the technical `host`. A non-empty
`correlator.group_labels` list overrides that Receiver identity for operators
who want AlertINT to group on a different label set. If the selected identity
has no value, AlertINT falls back to alertname and then fingerprint, so the
Incident group key is never empty. The [rule engine](../rules-spec.md) runs
here too: storm collapse, known-issue short-circuits, and prompt selection.

- **Grouping identity:** Receiver default; optional `correlator.group_labels` override
- **Window:** `correlator.window_seconds`, default 90 s

### 4. Memory

Before spending an analysis, **AlertINT** checks whether it has seen this
condition before. A re-fire of an already-analyzed group key inside the
collapse horizon attaches as an **occurrence** — the Slack card edits in
place, no second LLM call. A genuinely new incident whose key matches a past
analysis gets the prior finding **recalled** into its prompt as a past
hypothesis, never as evidence. See [incident
memory](incident-memory.md).

- **Collapse:** occurrence attach, no LLM call; re-judgment only on an
  escalation trigger
- **Recall:** distilled prior findings, recurrence count, cadence

### 5. Evidence pack

Once an incident's window closes, **AlertINT** builds an evidence pack:
shared labels, timeline, and annotations, enriched — where the matching
connector is configured — with live Prometheus metric values, recent
[Loki](../integrations/loki.md) log lines, overlapping change events,
[Sentry](../integrations/sentry.md) exceptions with `file:line`, and
[Zabbix](../integrations/zabbix.md) operator context (runbook, trigger
dependencies, flap history, host CMDB and maintenance state, other open
problems). Every connector is read-only and optional; the pack degrades to
labels and annotations when none is configured.

### 6. AI triage — the draft

The evidence pack goes to the configured LLM. The model returns a structured
draft: probable cause, severity assessment, confidence, and suggested next
checks — plus a short list of read-only checks it thinks would challenge its
own conclusion.

- **Model:** Anthropic Claude (`claude-sonnet-5` by default; `claude-haiku-4-5` as the lower-cost option), or any
  [OpenAI-compatible endpoint](../integrations/openai-compatible.md) you host
- **Auth:** `ANTHROPIC_API_KEY` env var (or the local endpoint's key)

### 7. Verification round

The draft is not the finding. **AlertINT** gathers **contrast evidence** —
facts chosen to disprove the draft — and asks the model to re-judge against
what it finds. A deterministic floor runs on every judged triage regardless
of what the model asked for (peer-scope up ratio and other incidents in
window on Prometheus installs; host reachability and host-group neighbors on
Zabbix installs), plus up to `max_queries` model-chosen read-only checks. A
round that can't finish marks the finding `⚠ unverified` and can never raise
confidence. See [verification round](verification-round.md).

- **Cost:** two LLM calls per judged incident, the second reading the first's
  prompt-cache prefix at ~0.10× input price
- **Kill-switch:** `triage.verification.enabled: false` restores single-call triage

### 8. Outbound notification

The final finding — the post-verification judgment, not the draft — is
emitted as one JSON line on stdout and, when configured, posted to a Slack
channel. When all alerts recover, **AlertINT** updates the original Slack
message in-place (🔴 → ✅) and posts a short resolution note in the thread.

- **Method:** stdout (always available) and Slack Bot Token API
  (`chat.postMessage` / `chat.update`)

## Phase 2 — Investigate

### 9. Agent entry via MCP

An engineer opens their MCP-capable AI client (Claude Code, Cursor,
Windsurf, or any MCP-compatible tool) pointed at the **AlertINT** MCP server,
which runs as part of the same binary — no separate daemon.

- **Transport:** Streamable HTTP, `http://host:9912/mcp`
- **Auth:** Bearer token (env var named by `mcp.token_env`)

### 10. Evidence query

The agent calls **AlertINT** MCP tools to list recent incidents, retrieve
alert payloads, evidence packs, correlated change events, and stored
findings. All data is served from local state — no external calls at this
stage.

- **MCP tools:** `alertint_list_incidents`, `alertint_get_incident`,
  `alertint_search_alerts`, `alertint_get_evidence_pack`,
  `alertint_recent_changes`, `alertint_verify_audit`

### 11. Telemetry context

The agent queries the same backends the evidence pack drew from, scoped to
the incident window — metrics, logs, and Zabbix history — through
**AlertINT**, which proxies each query and returns the result. Queries only:
nothing here writes, tails, or mutates.

- **MCP tools:** `prometheus_query`, `prometheus_query_range`,
  `loki_query_range`, `zabbix_metric_history`, `zabbix_host_problems`
- **Backends:** Prometheus HTTP API, Loki, Zabbix JSON-RPC — read paths only

### 12. Capture a verdict — closing the loop

When the investigation lands somewhere the machine didn't, the agent writes
it back. `alertint_incident_capture_verdict` records a **confirmation** or a
**correction** against the incident; `alertint_incident_annotate` leaves a
note for the next investigator. Both are additive and audit-chained — they
never edit or delete what came before.

A captured correction is not taken as fact: on the next triage of that
failure group its evidence runs as verification checks and the model must
rule `supported`, `contradicted`, or `unverifiable` before the corrected
cause is adopted. Live evidence can retire a stale correction; the calendar
can't. See [operator verdicts steer the next
triage](incident-memory.md#operator-verdicts-steer-the-next-triage).

- **MCP tools:** `alertint_incident_capture_verdict`, `alertint_incident_annotate`
- **Effect:** steering on the next triage of the same group key — the only
  write path in the product, and it writes to **AlertINT**'s own state, never
  to your infrastructure

### 13. Decision point

The agent synthesizes alert payloads, the stored finding, and live context
into a response. The engineer decides the next action — re-query, escalate,
or begin remediation — with full context already in the conversation.
**AlertINT**'s role ends at providing context; the next step is
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
That root cause is wrong — it was the cache rollout. Capture that as a correction.
```

## Incident lifecycle

```text
collecting  →  ready  →  (skill running)  →  analyzed
                 ↑              │
                 └── retry ─────┘  →  failed (after 5 attempts)
```

- `collecting`: window is open, alerts arriving
- `ready`: window expired, incident dispatched to the triage skill. If the
  skill errors (LLM endpoint down, connector failure, persistence error) the
  incident stays here and is re-dispatched with backoff — 30 s, 2 min, 8 min,
  32 min — from the correlator's flush ticker
- `analyzed`: LLM output persisted
- `failed`: every attempt errored; the incident is closed out (logged as
  `triage exhausted`, audited as `incident.triage_exhausted`, and written to
  the stdout notifier as one `{"kind":"triage_exhausted",…}` line — no Slack
  card, so an LLM outage never becomes one card per stuck incident). A later firing
  of the same group opens a fresh incident. Retry state lives in memory, so
  on startup an incident still in `ready` is dispatched once more if it has
  been ready for less than an hour — a restart mid-triage or mid-backoff does
  not strand it. Older ones are closed out as `failed` without a triage call
  (audited with reason `startup_retry_window_expired`, one summary log line),
  so an upgrade over a backlog of stuck incidents does not become an LLM burst

A recurrence of an `analyzed` incident attaches as an occurrence rather than
minting a new row — the lifecycle above describes one incident, not one
firing.

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
- **No 5xx to a sender** — ingress always returns 2xx or 4xx; errors are
  logged, not propagated upstream to Alertmanager or Zabbix.
- **Single binary, SQLite state** — no external dependencies to install.
- **Read-only outward** — every connector issues queries only. The single
  write path is an operator verdict, and it writes to **AlertINT**'s own
  state.
- **MCP-first investigation** — local context is exposed through the MCP
  server; there is no web UI.
