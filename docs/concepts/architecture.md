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

**AlertINT** is a two-level system. **Incidents** (L1) are the durable acute
analysis unit — one correlated burst of alerts, triaged once. **Situations**
(L2) are the durable operational aggregate — the proactive controller that
owns Attention, lifecycle, and the one evolving Slack thread per episode.
Every Incident belongs to exactly one Situation; the Situation controller,
not any individual Incident, decides whether and when acute L1 analysis runs
and whether and when Slack gets a poke. This is a hard cutover: there is no
runtime toggle between an "Incident-notifies" mode and a "Situation-notifies"
mode, and the Situation controller is the only Slack writer in this build.

Two feedback loops close on the triage step, and both are why the same
condition doesn't get the same wrong answer twice: the **verification round**
makes each analysis falsify its own draft before the finding persists, and an
operator **verdict** captured over MCP steers the next triage of that failure
group. A third loop closes at the Situation level: an operator **judgment**
or a reusable **Expected-behaviour envelope** steers the existing Situation
root directly, without minting a new one.

## Phase 1 — Ingest and triage (Incident, L1)

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

Received alerts are written to local state (SQLite) as one atomic transaction
containing the latest Alert projection, an immutable delivery record (the
Situation evidence ledger, readable in full through
`alertint_situation_evidence_get`), and a pending dispatch row. Duplicate
firings of the same alert fingerprint collapse onto the same projection; the
immutable delivery ledger still keeps every accepted delivery, in order,
distinct from that latest-wins view.

This is a durability boundary, not just a dedup step: if the transaction
cannot commit, ingress returns `503` so the source retries, deliberately
narrowing the older "AlertINT never 5xxs a sender" contract — durability
failure is not acceptance. A syntactically or authentication-invalid request
still fails `4xx`, as before; only the write-durability case became `503`.

- **Storage:** local SQLite, configurable path
- **Dedup key:** alert fingerprint (projection); the delivery ledger itself is
  append-only and never deduplicated
- **Acceptance contract:** `4xx` for a client error (bad auth, bad payload);
  `503` only when the accepting transaction itself could not be persisted

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

### 8. L1 finding — durable evidence, not a notification

The final acute finding — the post-verification judgment, not the draft — is
persisted as durable Incident evidence. It does **not** post to Slack and
does **not** decide Attention by itself: L1 findings feed the Situation
controller (below), which alone decides whether the episode gets a Slack poke
and when. An Incident whose Situation never requested acute analysis carries
`acute_finding_status=not_requested`, visible over MCP with its reason —
this is expected for the majority of Incidents, not a failure.

- **Gate states:** `not_requested` \| `planned` \| `running` \| `complete` \|
  `blocked` \| `exhausted` — an omitted finding is never ambiguous
- **Why:** the Situation controller (Phase 1.5) may already have published a
  fact-grounded notification before L1 finishes, may decide L1 has no
  decision value for an unchanged material fact set, or may still be running
  it asynchronously

## Phase 1.5 — The Situation controller (L2)

Every Incident attaches to exactly one Situation — the durable operational
aggregate that owns Attention, lifecycle, and the one evolving Slack thread
per episode. This is always on: there is no config flag that disables it, and
after this cutover it is the only code path that writes to Slack.

### Attachment and reconciliation

An Incident attaches to the existing `active` or `recovery_pending` Situation
with an exact matching group key, or opens a new one. Attachment increments
the Situation's `input_version`, unions in a typed due reason (e.g.
`incident_created`, `new_symptom`, `alert_refired`, `alert_resolved`,
`operator_judgment`, `envelope_changed`, `manual_reassessment`), and moves
`next_assessment_at` earlier — never later. A pool of workers
(`situations.workers`, default 2) claims due Situations by priority — a
deterministic urgent/critical anchor first, then a material change to an
already-published Situation, then a new symptom or envelope concern, then a
recovery/deadline boundary, then an ordinary observing checkpoint — and
reconciles one at a time under a lease
(`situations.lease_seconds`/`lease_heartbeat_seconds`).

One reconciliation attempt: build a deterministic snapshot from current
facts, evaluate the fixed Attention/Interruption-priority floors and any
applicable Expected-behaviour envelope, publish immediately if the facts
already provide sufficient reason, decide whether acute L1 analysis has
decision value (the B+ gate, below), optionally propose and validate an
Assessment, then persist and deliver whatever Slack effect is allowed.

**Known gap:** the Reconcile loop does not yet call out to the connector
observation runner. All seven read-only observation executors
(Prometheus/Zabbix metrics, Loki, Sentry, change events, and the rest of the
typed capability catalog) are implemented, wired, and tested end to end
through `internal/observation`'s runner — but nothing in the controller's
Reconcile path invokes it yet. Only delivery-derived symptom facts and
`store_read` facts (the durable state already in SQLite) reach a Situation
snapshot in this build; live connector reads do not.

### The B+ gate — acute analysis is requested, not automatic

L1 is requested only when focused acute analysis could materially change
causality, explanation, operator ownership, a novel or changed symptom,
conflicting facts, an envelope-violation mechanism, a new semantic
signature, the next useful bounded observation, or a manual reassessment. It
is skipped when a trustworthy Assessment already covers an unchanged
material fact hash — a new Incident identity or an unchanged alert name
alone never proves an unchanged fact set. Skips persist their reason. L1
never blocks an initial notification already grounded by sufficient
deterministic facts, and a later L1 result only triggers L2 reassessment
when it actually changes the material fact hash.

### Lifecycle and Attention

```text
active
  -> recovery_pending
       -> active       (refire or contradictory evidence)
       -> recovered    (grace expires cleanly)

active | recovery_pending
  -> closed_unknown
```

`recovery_pending` is persisted state, not an Attention level: when current
member Alerts resolve, the controller stamps `recovery_observed_at` and
`grace_until`, pauses firing-only probes, and keeps watching for a clean
recovery — while preserving the prior Attention for audit and refire
handling. A refire clears the recovery fields, returns to `active`, and
reassesses. Clean grace expiry sets `recovered` with terminal Attention
`observe`. `closed_unknown` is only ever set with a structured reason
(`observation_deadline` \| `resolution_missing` \| `source_unavailable` \|
`budget_exhausted`) — attempt or LLM budget exhaustion alone never closes a
Situation while a fresh, authoritative firing state remains current; it
parks work and waits for a named reconsider event instead. A later firing
after a terminal Situation always opens a new linked one
(`previous_situation_id`) — a terminal Situation is never reopened.

Recovery grace is source-aware in the config schema
(`situations.recovery_grace`: a fixed window for webhook sources, twice the
poll interval clamped to a configured range for polling sources, the longest
applicable window for a multi-source Situation) but **in this build every
Situation actually uses the flat webhook default**
(`recovery_grace.webhook_seconds`, 120s) — production wiring always calls the
calculation with no per-source classification supplied, because no caller
yet distinguishes a webhook-delivered source from a polling one.

### Operator steering: judgments and Expected-behaviour envelopes

`alertint_situation_judgment_record` captures the operator's current
judgment (`expected_this_episode` \| `unexpected` \| `inconclusive`) against
the exact fact/symptom/impact view judged, with required confirmation and
attribution. `alertint_expected_behavior_confirm` promotes a confirmed
judgment into a reusable, versioned envelope — scoped to an exact group and
source/trigger identity, with an omitted condition always meaning
unknown/not authorized rather than unlimited (an absent duration does not
authorize arbitrary duration). `alertint_expected_behavior_revoke` retires
one and immediately reschedules every active Situation that has ever
evaluated it.

**Known gap:** envelope *evaluation* is not yet wired into the Reconcile
loop. The full envelope lifecycle — confirmation, versioning, matching
logic, schedule/DST resolution, violation detection, invalidation, and
revocation — works correctly and is fully tested when driven over MCP; only
its automatic evaluation as part of an ordinary reconciliation attempt does
not fire in production yet.

### Slack: one root, one thread, viewer-local time

A Situation receives its immutable public handle and one Slack root only
when it is first published. Every promised update states why attention is
warranted, what runs next, who acts, and the next update time in both
relative (`Next update in 5 minutes`) and viewer-local absolute form, using
Slack's own date markup so each observer sees their own device's timezone
while the canonical instant stored everywhere else stays UTC. See
[Slack](../notifications/slack.md) for the full contract, including the root
state table, the non-broadcast-vs-broadcast thread rule, and idempotent
delivery.

The existing `notify.slack.min_severity` remains a compatibility name, but in
Situation mode it compares against a deterministic Interruption priority
(`low` \| `medium` \| `high` \| `critical`) derived from the validated
reason, Attention, and action contract — never against Alert severity or an
L2-generated field. `critical` always passes this outward floor. Today the
mapping from the configured `low`/`medium`/`high` string onto that priority
ladder is intentionally permissive: `warning` maps to `medium`, and any
unrecognized or unset value keeps the most permissive `low` floor rather
than silently withholding pokes.

### The funnel

`alertint funnel --since <UTC> --until <UTC>` (also exposed as the
`alertint_poke_funnel_get` MCP tool) reports local compression for a window:
accepted deliveries, distinct source episodes, Incidents, Situations, root
creates/edits, non-broadcast and broadcast thread replies, envelope reviews,
health pokes, and total main-channel pokes. Delivery and source-episode
counts are reported separately so webhook retries and recovery deliveries
are never misrepresented as avoided operator interruptions. **The funnel
measures AlertINT-local compression only** — it does not and cannot know how
many messages an external path (for example Zabbix's own direct Slack
integration) would otherwise have sent; that comparison is only observable
from the operator's separate path, alongside the funnel numbers.

### Situation controller: known gaps

Summarizing the honesty carries called out above, in one place:

1. **Connector observation is not yet wired into Reconcile.** All seven
   observation executors (Prometheus/Zabbix metrics/Loki/Sentry/change
   events) are implemented, wired, and tested through the runner, but the
   Reconcile loop never calls it. Only delivery-derived symptom facts and
   `store_read` facts reach a snapshot today.
2. **Expected-behaviour envelope evaluation is not yet wired into any
   production reconcile path.** Envelopes, judgments, confirmation, and
   revocation all work correctly over MCP; automatic evaluation during
   reconciliation does not fire yet.
3. **Recovery grace is a flat webhook-default in production.** No caller
   classifies a source as webhook versus polling, so every Situation uses
   `recovery_grace.webhook_seconds` regardless of how its source actually
   delivers.
4. **`notify.slack.min_severity` uses a permissive Interruption-priority
   mapping.** `warning` maps to `medium`, `unknown`/unset maps to `low`, and
   `critical` always passes — this floor never withholds a critical poke.

None of these change what is durably persisted, what MCP can read, or the
correctness of the parts that are wired; they change what data reaches a
Situation's automatic facts and how finely the outward Slack floor and
recovery timing can be tuned per source today.

## Phase 2 — Investigate

### 9. Agent entry via MCP

An engineer opens their MCP-capable AI client (Claude Code, Cursor,
Windsurf, or any MCP-compatible tool) pointed at the **AlertINT** MCP server,
which runs as part of the same binary — no separate daemon.

- **Transport:** Streamable HTTP, `http://host:9912/mcp`
- **Auth:** Bearer token (env var named by `mcp.token_env`)

### 10. Evidence query

The agent calls **AlertINT** MCP tools to list recent incidents and
Situations, retrieve alert payloads, evidence packs, correlated change
events, and stored findings. All data is served from local state — no
external calls at this stage. Every Situation is visible, including one that
was never published to Slack and one that has already gone terminal;
`alertint_situation_get` leads a terminal read with a status banner.

- **Incident/evidence MCP tools:** `alertint_list_incidents`,
  `alertint_get_incident`, `alertint_search_alerts`,
  `alertint_get_evidence_pack`, `alertint_recent_changes`,
  `alertint_verify_audit`
- **Situation MCP tools:** `alertint_situation_list`, `alertint_situation_get`,
  `alertint_situation_evidence_get`, `alertint_semantic_profile_get`,
  `alertint_poke_funnel_get` — see [MCP clients](../integrations/mcp-clients.md)
  for the complete table, including the confirmed write tools below

### 11. Telemetry context

The agent queries the same backends the evidence pack drew from, scoped to
the incident window — metrics, logs, and Zabbix history — through
**AlertINT**, which proxies each query and returns the result. Queries only:
nothing here writes, tails, or mutates.

- **MCP tools:** `prometheus_query`, `prometheus_query_range`,
  `loki_query_range`, `zabbix_metric_history`, `zabbix_host_problems`
- **Backends:** Prometheus HTTP API, Loki, Zabbix JSON-RPC — read paths only

### 12. Capture a verdict or steer a Situation — closing the loop

When the investigation lands somewhere the machine didn't, the agent writes
it back. `alertint_incident_capture_verdict` records a **confirmation** or a
**correction** against the incident; `alertint_incident_annotate` leaves a
note for the next investigator. At the Situation level,
`alertint_situation_judgment_record` records the operator's current judgment
(`expected_this_episode` \| `unexpected` \| `inconclusive`), and
`alertint_expected_behavior_confirm` promotes a confirmed judgment into a
reusable envelope so the same expected workload doesn't need re-confirming
on every later Situation; `alertint_expected_behavior_revoke` retires one.
Every write here is additive and audit-chained, requires explicit
confirmation plus an asserted operator identity, and never edits or deletes
what came before.

A captured correction is not taken as fact: on the next triage of that
failure group its evidence runs as verification checks and the model must
rule `supported`, `contradicted`, or `unverifiable` before the corrected
cause is adopted. Live evidence can retire a stale correction; the calendar
can't. See [operator verdicts steer the next
triage](incident-memory.md#operator-verdicts-steer-the-next-triage).

- **Incident MCP tools:** `alertint_incident_capture_verdict`,
  `alertint_incident_annotate`
- **Situation MCP tools:** `alertint_situation_reassess`,
  `alertint_situation_judgment_record`, `alertint_expected_behavior_list`,
  `alertint_expected_behavior_confirm`, `alertint_expected_behavior_revoke`,
  `alertint_semantic_profile_correct`
- **Effect:** steering on the next triage of the same group key, or directly
  on the existing Situation root — the only write paths in the product, and
  they write to **AlertINT**'s own state, never to your infrastructure

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
List open AlertINT Situations.
Open the latest critical Situation and summarize the evidence.
Show the alert labels and annotations for this incident.
Query Prometheus for CPU and memory around the incident window.
Compare the finding with the metric trend and suggest next checks.
That root cause is wrong — it was the cache rollout. Capture that as a correction.
Record my judgment: this Situation is expected this episode, I confirm it.
```

## Incident lifecycle (L1)

The Incident record itself still moves through its own correlation-window
lifecycle, unchanged by the Situation controller:

```text
collecting  →  ready  →  (processing)  →  analyzed
                                       →  failed
                      →  resolved
```

- `collecting`: window is open, alerts arriving
- `ready`: window expired, incident available for correlation and Situation
  attachment — this no longer means the acute-triage skill runs
  automatically
- `processing` → `analyzed`: the acute-triage skill ran and persisted a
  finding
- `failed`: the LLM call or persistence errored (logged)
- `resolved`: every member alert recovered

A recurrence of an `analyzed`-or-later incident attaches as an occurrence
rather than minting a new row — the lifecycle above describes one incident,
not one firing.

Separately, each Incident carries its own **acute-analysis gate state**
(`not_requested` \| `planned` \| `running` \| `complete` \| `blocked` \|
`exhausted`), decided by the Situation controller's B+ gate (see [Phase
1.5](#phase-15-the-situation-controller-l2)) and visible per member Incident
on `alertint_situation_get`. This is a distinct concept from the correlation
lifecycle above: it answers "did focused acute analysis actually run for
this Incident, and why or why not" — not "has the correlation window
closed." `not_requested` is the common case, not a failure — most Incidents
never need a focused acute finding because their Situation already published
from deterministic facts, or an existing trustworthy Assessment already
covers the same material fact set. `blocked`/`exhausted` mean the model call
or persistence failed within budget; the Situation controller retries
independently within its own budget.

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
- **Durable acceptance, not "no 5xx"** — a client error (bad auth, an invalid
  payload) still returns `4xx`, exactly as before. What changed with the
  Situation controller: if the atomic projection + delivery + dispatch
  transaction cannot be persisted, ingress now returns `503` so the source
  retries, because accepting a delivery AlertINT then loses is worse than a
  visible retry. This deliberately narrows the older blanket "never 5xx a
  sender" contract to the one case where acceptance genuinely didn't happen.
- **Single binary, SQLite state** — no external dependencies to install.
- **Read-only toward every operated system, always** — every connector
  (Prometheus, Loki, Zabbix, Sentry) issues queries only; no AlertINT code
  path acknowledges, silences, remediates, or otherwise mutates anything it
  monitors. This boundary is unchanged by the Situation controller. The
  several write paths that do exist — an Incident verdict/annotation, a
  Situation judgment, an Expected-behaviour envelope confirmation/revocation,
  a semantic-profile correction — are all additive, audit-chained, and land
  only in **AlertINT**'s own local state, never in your infrastructure.
- **MCP-first investigation** — local context is exposed through the MCP
  server; there is no web UI.
