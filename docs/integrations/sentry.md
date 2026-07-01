---
title: "Sentry"
description: "Poll Sentry releases and deploys as change events, enrich triage with the firing exceptions and their file:line, and investigate both over MCP."
section: "Integrations"
order: 4
slug: "sentry"
---

# Sentry

The optional **Sentry connector** turns your Sentry **releases and deploys** into
change events, so the most common root-cause answer — *something just shipped* —
is already in front of the LLM when an incident is triaged, and one MCP call away
when an engineer picks up the thread.

Unlike a deploy webhook, Sentry has no release/deploy push: releases and deploys
are **pull-only**. AlertINT runs inside your own network, so the
trust-boundary-aligned shape is the same outbound HTTPS polling used by the
Prometheus and Loki connectors — a background poller lists new deploys on an
interval and records each as a change event. It feeds the same change plane as
the [change-events webhook](changes.md): polled Sentry deploys and pushed CI
deploys land side by side and are surfaced together.

Read-only by design: AlertINT only issues `GET` requests against Sentry. It never
writes, mutates, resolves issues, or touches Seer — read-only is structural, not
a setting.

The connector plays **two read-only roles over one shared connection and token**:
a **Change source** — the release/deploy poller documented next — and an **Error
source** that enriches triage with the actual exception, its `file:line`, and its
blast radius ([jump to it](#error-source--issue-enrichment-at-triage)). Enable
either independently, or both.

## Enable it

```yaml
sentry:
  base_url: https://sentry.io          # host root (see "Base URL" below)
  org: my-org-slug                     # your Sentry organization slug
  token_env: SENTRY_AUTH_TOKEN         # env var holding the token (never inline)
  timeout_seconds: 10                  # default
  releases:
    enabled: true
    poll_interval_seconds: 60          # default
    initial_lookback_minutes: 60       # first run seeds the watermark this far back
    release_scan_horizon_days: 30      # how old a release can be and still have new deploys detected
    projects: ["checkout", "payments"] # optional; omit for org-wide

changes:
  enrichment:
    enabled: true                      # REQUIRED to surface changes at triage + over MCP
    window_minutes: 120
    max_events: 10
  retention_days: 30                   # Sentry changes are pruned by this, like all changes
```

| Field | Description |
|---|---|
| `base_url` | Sentry host root, e.g. `https://sentry.io` (see [Base URL](#base-url)). AlertINT appends the API path. |
| `org` | Your Sentry organization slug. |
| `token_env` | Name of the env var holding the auth token — never inline. |
| `timeout_seconds` | HTTP timeout for Sentry calls. Default `10`. |
| `releases.enabled` | Set `true` to run the release/deploy poller (the **Change source**). |
| `releases.poll_interval_seconds` | How often to poll for new deploys. Default `60`. |
| `releases.initial_lookback_minutes` | On first run, seed the watermark this far back. Default `60`. |
| `releases.release_scan_horizon_days` | Oldest a release can be and still have new deploys detected. Default `30`. |
| `releases.projects` | Optional list of project slugs to scope polling. Omit for org-wide. |

The `changes.*` keys above are the shared change plane, not Sentry-specific — see
the [change-events configuration](../getting-started/configuration.md#changes).
The poller writes change events; **`changes.enrichment` is what surfaces them**
at triage time and over MCP. Enable both. Sentry changes are ordinary change
rows, so they are pruned by the shared `changes.retention_days` — there is no
Sentry-specific retention.

Disabled by default. With both `sentry.releases` and `sentry.issues` disabled (or
the `sentry` block omitted) no poller starts, no client is built, and AlertINT
makes no Sentry calls at all.

## The token and scope

Create an **Internal Integration** in Sentry
(*Settings → Developer Settings → Internal Integration*) and give it the single
read scope the poller needs:

| Scope | Why |
|---|---|
| `project:read` | List releases and their deploys (the **Change source**). Sufficient for release/deploy polling on its own. |
| `event:read` | List issues and read an issue's latest event — the exception type and stacktrace `file:line` (the **Error source**). Add this scope when `sentry.issues` is enabled. |

Supply the token through the named environment variable, never inline in config:

```bash
export SENTRY_AUTH_TOKEN="sntrys_..."
```

The token is org-scoped. Sentry rate limits are per-identity, not per-token, and
the poller's default 60s interval with a small per-cycle call count stays well
under them.

## Base URL

`base_url` is the **host root**, matching the Prometheus and Loki convention —
AlertINT appends the API path itself.

| Deployment | `base_url` |
|---|---|
| Sentry SaaS (US) | `https://sentry.io` |
| Sentry SaaS (EU) | `https://de.sentry.io` |
| Self-hosted | `https://sentry.your-company.internal` |

## How it works

Each cycle the poller lists recent releases (newest first, stopping past
`release_scan_horizon_days`) and, for any release with deploy activity newer than
its watermark, lists that release's deploys per project:

- **One change per newly-seen deploy.** A release deployed to `staging` and
  `production` produces two change events, each carrying its own `environment`
  label and finish time.
- **A release with no deploys** records a single `release` change.
- **Never re-emitted.** A SQLite watermark, advanced in the same transaction as
  the change insert, means a deploy is recorded exactly once — across poll cycles
  and across restarts.
- **Failure-isolated.** A failed cycle (rate limit, network, 5xx) is logged and
  skipped; the next tick retries. A `sentry` health check reports reachability in
  the console log and at `GET /health`.

Labels are the raw Sentry `project` and `environment`. They match an incident's
shared alert labels the same way pushed change events do — and even when nothing
matches, recent Sentry deploys still surface at triage, ranked after matched
changes (see [change events](changes.md)).

## What you'll see in triage

Sentry deploys render in the prompt as part of the **Recent changes** block,
most-relevant-first, each with a `Δ6m before incident start` hint and a link back
to the release in Sentry. They are also queryable after the fact over MCP — see
[MCP tools](#mcp-tools).

## Error source — issue enrichment at triage

Beyond polling deploys, the Sentry connector answers a second question at triage
time: *which application errors are firing for this service right now, and is any
of them new?* This is the **Error source** — a bounded, read-only query run once
per incident that reaches LLM analysis, contributing a distilled **`sentry`
section** to the triage prompt alongside metrics, changes, and logs. Where the
Change source names what *shipped*, the Error source names the **exception** — the
one signal that points an AI coding agent straight at a `file:line`.

For each incident it makes **one issue search plus at most `max_issues` event
detail fetches** — `1 + K` Sentry calls total, regardless of how many events
Sentry recorded — and renders the highest-signal issues:

- **Exception + `file:line`** — the exception type and the deepest in-app stack
  frame, so the model (and your coding agent) can jump straight to the line.
- **Blast radius** — severity level, affected-user count, and the in-window event
  rate, to calibrate severity.
- **NEW vs chronic** — an issue first seen *inside* the incident window is flagged
  **NEW** (a likely cause); one first seen earlier is **chronic** (more likely a
  symptom).

It is **query-at-triage**, not a poller: it runs in the triage evidence fan-out,
never per Sentry event, and a known-issue rule short-circuit skips it along with
the rest of the fan-out. The distilled result is persisted with the finding, so
the evidence pack replays exactly what the LLM saw and the read-only incident
evidence MCP tool exposes it — no extra query. A successful search that matches
**no** issues is itself recorded as a signal: evidence the incident is likely not
application-code-driven.

### Enable the Error source

```yaml
sentry:
  base_url: https://sentry.io
  org: my-org-slug
  token_env: SENTRY_AUTH_TOKEN
  issues:
    enabled: true
    lookback_minutes: 30        # W = [first_alert − lookback, now]; reaches a precursor error
    max_issues: 3               # the K of the 1+K budget — how many top issues to render
    fetch_timeout_seconds: 15   # bounds the WHOLE 1+K fetch; on timeout the section degrades
    live_window_minutes: 60     # default look-back for the live sentry_issues_list MCP tool
    include_message: true       # include the exception message (default; see privacy below)
```

| Field | Description |
|---|---|
| `issues.enabled` | Set `true` to run issue enrichment at triage (the **Error source**). |
| `issues.lookback_minutes` | Window `W` back from the first alert; reaches a precursor error. Default `30`. |
| `issues.max_issues` | The `K` in the `1+K` call budget — how many top issues to render. Default `3`. |
| `issues.fetch_timeout_seconds` | Bounds the whole `1+K` fetch; on timeout the section degrades. Default `15`. |
| `issues.live_window_minutes` | Default look-back for the live `sentry_issues_list` MCP tool. Default `60`. |
| `issues.include_message` | Include the exception message across all surfaces. Default `true` (see privacy below). |

The Error source is **independent of the release poller**: enable `sentry.issues`
with `sentry.releases` off and AlertINT builds the shared client for triage
queries but starts no poller. Both roles share the connection (`base_url` / `org` /
`token_env`); add the `event:read` scope to the token for issue/event reads.

### Scoping

The query is **project-required, environment-optional**. The project slug is taken
**directly** from the incident's shared labels — the first of `service`,
`project`, `app`, `job` — and the environment from `environment` or `env` when
shared. A label value that matches no Sentry project surfaces as an explicit *no
issues for this scope* note (not a silent omission); an incident with no derivable
project is skipped with a logged reason rather than queried with a guess. Robust,
configurable label mapping across sources is a later step — for now the scope
rides your existing label vocabulary.

### What this connector sends to your LLM and stores

The Error source is **distilled at the source**: only a strict allowlist of
structured fields ever crosses Sentry's API boundary into the three surfaces — the
LLM prompt, the at-rest SQLite store, and the evidence-pack MCP tool:

- exception **type**, **culprit**, and the in-app **`file:line`**;
- severity **level**, **affected-user count**, **event rate**, first/last-seen
  **timestamps**, and the NEW flag;
- the exception **message**, *only* when `include_message: true` (the default).

It **never** fetches or stores local variables, request bodies, breadcrumbs, or
user/context entries — the privacy boundary is the **shape** of what is requested,
not a downstream scrubber. Setting `include_message: false` strips the exception
message from **all three** surfaces at once. All three sit inside your own trust
boundary — your BYO LLM, your local database, your locally-gated MCP server — the
same boundary your alert labels already flow through.

### Cross-source reconciliation

With two independent observers of the same system — infrastructure
(Alertmanager/Prometheus) and application errors (Sentry) — the signal neither
stream carries alone is the **reconciliation between them**. When the Error source
is enabled, AlertINT tags each analyzed incident with a zero-LLM cross-source
verdict and prepends **one neutral headline line** to the `sentry` section:

- **`matched`** — at least one *new-in-window* Sentry error coincides with the infra
  alert. Headline: *"Sentry: N new in-window error(s) correlated."* The corroborating
  issue ids are persisted with the finding.
- **`infra-only`** — the Error source looked and found no new error (zero issues, or
  only chronic ones). Headline: *"Sentry: no new in-window errors for this scope"*
  (with *"(M chronic present)"* appended when chronic issues exist).

The tag is **presented evidence, never a directive** — it states a count and lets the
model weigh it, rather than steering it toward or away from a cause class. It is
persisted with the finding (so the evidence pack and the incident-evidence MCP tool
replay it) and rides the Error source's enablement; there is **no separate flag**.
When Sentry is disabled, or the query degraded (rate-limited, timeout, unknown
project), **no tag and no headline** are emitted — so `infra-only` always means *"we
looked and found nothing new,"* never *"Sentry isn't configured."*

## MCP tools

The Sentry connector contributes three read-only MCP tools, one per role plus the
shared change-plane tool. The Change source's deploys are queryable through
`alertint_recent_changes`; the Error source adds two live issue tools that reach
**past** the triage-time `sentry` section — a **frozen snapshot** of the
top-`max_issues` issues as they looked when the incident was analyzed. The two
`sentry_*` tools register only when `sentry.issues` is enabled with a live client —
a releases-only deployment exposes neither.

| Tool | Answers |
|---|---|
| `alertint_recent_changes` | *What shipped near this incident?* Recent change events — including polled Sentry deploys — by label selector and window. Shared with the change-events connector; see [Change events → Investigate over MCP](changes.md#investigate-over-mcp). |
| `sentry_issues_list` | *What is erroring for this scope — live, beyond the triage cap, across statuses?* Lists distilled issues for an explicit `project` (+ optional `environment`), newest-relevant first. |
| `sentry_issues_trace` | *Show me the full stacktrace for these issue ids.* Returns every exception frame (`file:line`, function, `in_app`) per id, plus the latest event's timestamp — the real cause is sometimes a frame deeper than the one in-app line the snapshot carried. |

The agent reads `project` / `environment` straight from the incident's persisted
`sentry` enrichment (the evidence pack carries them as structured fields), so no
incident id or free-text parsing is involved. `sentry_issues_trace` accepts up to
**10** ids per call (e.g. the evidence pack's corroborating issue ids, or ids from
`sentry_issues_list`); an over-cap call is rejected, and an id that can't be fetched
returns a per-id error rather than failing the whole batch.

**Status filter.** `sentry_issues_list` takes a typed `status` ∈ `unresolved`
(default), `resolved`, `ignored` (Sentry's API token for *muted*). `resolved` /
`ignored` answer *"was this seen before and already handled?"* — the operator's own
live Sentry disposition. Because that is a **historical** lookup rather than a
"what's happening now" view, the recurring-this-window activity filter is applied
only to `unresolved`; a genuinely historical resolution still surfaces under
`resolved` / `ignored`.

**Window.** When `start` / `end` (RFC3339) are omitted, `sentry_issues_list` looks
back `sentry.issues.live_window_minutes` (default 60) from now — distinct from the
triage `lookback_minutes`, which is anchored to the incident.

**Same privacy boundary, widened by shape.** Both tools return only the distilled,
safe-by-shape view — the per-frame allowlist is exactly `filename` (relative),
`lineno`, `function`, and `in_app`. They **never** decode `abs_path`, local
variables, or source-context lines, nor request bodies, breadcrumbs, or user
context. A frame whose path is absolute (the `filename` key is itself absolute on
some non-Python SDKs) is dropped to empty rather than surfaced, so no
`/home/<user>/…` path leaks. The `include_message` toggle gates the exception
**value** on the live surface exactly as it does the persisted one. Every result
carries a constant `pii_notice` field stating that the full, PII-bearing event
stays in Sentry.

**Permalink.** `sentry_issues_list` surfaces Sentry's own issue URL **only when the
API response already carries it** — never constructed from base URL + org + id. On
a **self-hosted** Sentry that link carries your internal host; this is your own
agent reading your own Sentry, so the host is yours and there is no strip knob.

**Project scope is bounded by the token, not an allowlist.** These tools query any
project the configured Sentry token can read — the distilled, read-only surface is
safe by shape, so the token *is* the boundary (the same posture as
`prometheus_query`). Provision a **minimum-necessary, per-project Internal
Integration token** to bound which projects an agent can reach.

**Treat tool output as untrusted external data.** Issue culprits, frame function
names, and exception messages are attacker-influenceable (anyone who can trigger an
application error can plant text). AlertINT length-caps these verbatim strings, but
an agent consuming them should treat them as data, not instructions.

### Example queries

Ask your investigating agent in natural language — AlertINT routes to the Sentry
MCP tools:

```text
What's still erroring for checkout in prod right now?
Show me the full stacktrace for the corroborating issue on this incident.
Was this error for payments seen before and already resolved or muted?
```
