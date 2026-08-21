---
title: "Scope and limits"
description: "Where AlertINT does well, where it doesn't, and known weaknesses."
section: "Concepts"
order: 2
slug: "scope-and-limits"
---

# Scope and limits

**AlertINT** is deliberately focused. The boundaries below are design
decisions, not gaps — knowing them up front saves you from misconfigured
expectations.

## Design principles

- **Read-only by design** — **AlertINT** observes and reports. It never
  touches your infrastructure, so teams can adopt it without risk. Every
  write an agent can make — an incident verdict/annotation, a Situation
  judgment, an Expected-behaviour envelope confirmation/revocation, a
  semantic-profile correction — is feedback into AlertINT's own incident
  state: additive, audit-chained, and never a write toward an operated
  system. This boundary held through the proactive Situation controller
  unchanged.
- **Self-hosted and local** — your alert data and incident context stay on
  your machine.
- **Fair Source** — the runtime and all baseline and community packs are
  [Fair Source](https://fair.io) under the [FSL-1.1-ALv2](https://fsl.software)
  license: free to read, use, modify, and self-host at any scale, with each
  release converting to Apache 2.0 — full open source — two years after it
  ships. Paid tiers come later and sit *on top*, never inside the engine: a
  hosted control plane for teams (fleet management, SSO/RBAC, audit
  retention — *metadata only*, your alert data never leaves your network)
  and enterprise connectors.

## Today's boundaries

**AlertINT** triages — it doesn't act. It won't remediate, silence, or
re-route alerts, run scripts or runbooks, or page ticketing systems for
you. Several of these are natural future directions — remediation, if it
lands, will be gated behind explicit operator approval flows.

## Known weaknesses

### High-cardinality label churn

**Problem:** a high-cardinality label in the selected grouping identity (for
example `pod=web-68f9c-xk2pq`) creates one Incident per changing value rather
than grouping the fleet-wide event. This can come from Alertmanager's
`groupLabels` or from an explicit `correlator.group_labels` override.

**Workaround:** group the Alertmanager route on stable dimensions, or set an
explicit override containing stable labels such as `service`, `namespace`, or
`alertname`. AlertINT warns when a configured override matches none of an
alert's labels and falls back safely instead of creating an empty key.

### Flapping alerts

**Problem:** an alert that fires, resolves, and re-fires within the
correlation window is treated as separate alerts and may produce a
confusing evidence pack with both `firing` and `resolved` entries for the
same fingerprint.

**Workaround:** increase `correlator.window_seconds` to outlast typical
flap cycles, or set `repeat_interval` in Alertmanager to suppress
re-fires.

### LLM confidence calibration

**Problem:** the `confidence` field in a finding is the model's
self-reported confidence. It is not calibrated against historical
outcomes — 0.9 does not mean 90% accuracy; it means the model expressed
high certainty. Early in deployment, treat all findings as advisory
regardless of confidence value.

**Philosophy:** confidence is a signal for operator attention
prioritisation, not an automated gate. Human review before action is
expected.

### Single-alert incidents with `min_alerts > 1`

**Problem:** if an alert fires alone and `min_alerts` is set above 1, the
agent still creates an incident and marks it `ready` at the end of the
window. The triage skill runs on a single-alert evidence pack and may
produce a lower-quality analysis.

**Workaround:** set `min_alerts: 1` to always triage, or accept that
single-alert findings have less correlation context.

### Situation controller: known gaps in this release

The proactive Situation controller (see [Architecture](architecture.md)) is
fully wired for delivery ingestion, lifecycle, Slack, and MCP steering, but
ships with five known, honestly-scoped gaps rather than the spec's full
aspiration:

**Connector observation is not yet wired into Reconcile.** All seven
read-only observation executors (Prometheus/Zabbix metrics/Loki/Sentry/change
events) are implemented, wired, and tested end to end through
`internal/observation`'s runner, but the controller's Reconcile loop never
calls it. Only delivery-derived symptom facts and `store_read` facts (the
durable state already in SQLite) reach a Situation's deterministic snapshot
today.

**Expected-behaviour envelope evaluation is not yet wired into any
production reconcile path.** The full envelope lifecycle — confirmation,
versioning, matching, schedule/DST resolution, violation detection,
invalidation, revocation — works correctly and is fully tested when driven
over MCP. Only its automatic evaluation as part of an ordinary
reconciliation attempt does not fire in production yet, so a confirmed
envelope will not yet quiet a matching Situation on its own without an MCP
call recomputing it.

**Recovery grace is a flat webhook-default in production.** The config
schema (`situations.recovery_grace`) supports a source-aware window — a
fixed grace for webhook sources, twice the poll interval clamped to a range
for polling sources — but no caller currently classifies a delivery source
as webhook versus polling, so every Situation uses the flat
`webhook_seconds` default (120s) regardless of source.

**`notify.slack.min_severity` uses a permissive Interruption-priority
mapping.** `warning` maps to `medium`, an unrecognized or unset value maps to
the most permissive `low`, and `critical` always passes the floor — the
mapping favors not missing a poke over precise per-severity suppression.

**Semantic profiles are never inferred automatically.** The bounded, advisory
L0 inference (`internal/semanticprofile`) is implemented and tested, but no
production path calls it, so a profile head exists only where an operator
created one over MCP (`alertint_semantic_profile_correct`). Profiles are
advisory-only by design and can never raise Attention or force a poke; the
practical consequence of the gap is that the advisory widening of a
Situation's lifecycle-observation deadline — which would give a genuinely
slow source longer before its lifecycle is declared unobservable — never
engages on its own, so every Situation uses the deterministic tier default.

None of these change what is durably persisted, what MCP can read, or the
correctness of the parts that are wired — they narrow what data reaches a
Situation's automatic facts and how finely today's recovery timing,
lifecycle-observation horizon, and outward Slack floor can be tuned per
source.

### Deeper metric context is operator-driven

**Problem:** automatic Prometheus enrichment adds a snapshot of metric
values at incident time to the LLM prompt, but deeper investigation —
trends, comparisons, custom PromQL — happens through the MCP tools. The
connected agent or operator must still choose useful queries.

**Workaround:** start with simple service-level queries for CPU, memory,
latency, and error rate around the incident window. Automatic query
suggestions are on the roadmap.

## Where it's heading

The roadmap grows the same core rather than bolting on side products.
Currently being explored:

- Pattern / slow-burn rollups (repeated alerts over hours or days)
- More skills beyond acute triage
- Cost metering and budget caps
- SSO/RBAC and team fleet management (the planned hosted control plane)
- Pull-based Alertmanager reconciliation on startup
- A web UI

Missing something you need?
[Open a feature request](https://github.com/alertint/alertint-agent/issues)
— real-world use cases shape what gets built next, and we'd love to hear
yours.
