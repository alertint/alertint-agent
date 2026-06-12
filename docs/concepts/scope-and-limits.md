---
title: "Scope and limits"
description: "Where AlertINT does well, where it doesn't, and known weaknesses."
section: "Concepts"
order: 2
slug: "scope-and-limits"
---

# Scope and limits

These are deliberate boundaries, not missing features. Understanding where
the agent does well — and where it doesn't — saves you from misconfigured
expectations.

## Design principles

- **Read-only by design** — AlertINT observes and reports. It never
  touches your infrastructure, so teams can adopt it without risk.
- **Self-hosted and local** — your alert data and incident context stay on
  your machine.
- **Open-core** — the core runtime is open source; enterprise features
  come later, on top.

## What it does not do

- No remediation, silences, or routing changes.
- No Alertmanager, Kubernetes, or infrastructure writes.
- No script or runbook execution.
- No ticketing or paging integrations (PagerDuty, Jira, Linear).

Remediation actions, if added in the future, will require explicit
operator approval flows. This is a far-future direction, not something
AlertINT does today.

## Known weaknesses

### High-cardinality label churn

**Problem:** if your alerts use dynamic label values (e.g.
`pod=web-68f9c-xk2pq`) the correlator creates one incident per unique pod
name rather than grouping the fleet-wide event. The fixed-window group key
is an exact match on all configured `group_labels`.

**Workaround:** exclude high-cardinality labels from
`correlator.group_labels`. Use stable labels like `service`, `namespace`,
`alertname`.

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

### Deeper metric context is operator-driven

**Problem:** automatic Prometheus enrichment adds a snapshot of metric
values at incident time to the LLM prompt, but deeper investigation —
trends, comparisons, custom PromQL — happens through the MCP tools. The
connected agent or operator must still choose useful queries.

**Workaround:** start with simple service-level queries for CPU, memory,
latency, and error rate around the incident window. Automatic query
suggestions are on the roadmap.

## Out of scope today

The following are out of scope today and tracked on the roadmap:

- Pattern / slow-burn rollups (repeated alerts over hours or days)
- Multi-tenancy and RBAC
- Multiple LLM providers (only Anthropic today)
- Multiple skill types (only acute triage today)
- Pull-based Alertmanager reconciliation on startup
- Alertmanager API control, silences, or routing changes
- Kubernetes API integration
- PagerDuty, Jira, Linear, or ticketing integrations
- Cryptographic signing of audit rows (hash chain only today)
- Cost metering and per-org budget caps
- Web UI
