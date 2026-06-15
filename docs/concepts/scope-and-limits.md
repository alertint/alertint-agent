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
  touches your infrastructure, so teams can adopt it without risk.
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

## Where it's heading

The roadmap grows the same core rather than bolting on side products.
Currently being explored:

- Pattern / slow-burn rollups (repeated alerts over hours or days)
- More LLM providers and more skills beyond acute triage
- Cost metering and budget caps
- SSO/RBAC and team fleet management (the planned hosted control plane)
- Pull-based Alertmanager reconciliation on startup
- A web UI

Missing something you need?
[Open a feature request](https://github.com/alertint/alertint-agent/issues)
— real-world use cases shape what gets built next, and we'd love to hear
yours.
