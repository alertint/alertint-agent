---
title: "Sentry"
description: "Poll Sentry releases and deploys into change events so triage can answer \"what shipped right before this?\"."
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

The poller writes change events; **`changes.enrichment` is what surfaces them**
at triage time and over MCP. Enable both. Sentry changes are ordinary change
rows, so they are pruned by the shared `changes.retention_days` — there is no
Sentry-specific retention.

Disabled by default. With `sentry.releases.enabled: false` (or the block omitted)
the poller is never started and AlertINT makes no Sentry calls at all.

## The token and scope

Create an **Internal Integration** in Sentry
(*Settings → Developer Settings → Internal Integration*) and give it the single
read scope the poller needs:

| Scope | Why |
|---|---|
| `project:read` | List releases and their deploys. Sufficient for both calls; no write or `event:read` scope is required for release/deploy polling. |

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
to the release in Sentry. When change enrichment is on, the read-only
`alertint_recent_changes` MCP tool returns them too, so an investigating AI agent
can widen the window or pivot projects beyond what auto-enrichment attached to the
finding.
