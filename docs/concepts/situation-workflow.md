---
title: "Situation workflow"
description: "Follow an alert from durable receipt through investigation, expected maintenance, recovery, and recurrence."
section: "Concepts"
order: 2
slug: "situation-workflow"
---

# Situation workflow

A **Situation** is the operator's view of one episode in a failure group. It
can contain several acute Incidents and alerts, but has one current overview
and one history. The lifecycle describes what AlertINT knows about monitored
alerts; investigation describes work being done. Neither is a claim that the
whole service is healthy. For implementation detail, see
[Architecture](architecture.md#3a-situation-foundation-and-controller).

## From alert to operator view

1. **Receive.** Alertmanager or Zabbix sends an alert or a batch. AlertINT
   returns HTTP `204` only after the delivery and its pending dispatch are
   stored together. Invalid input gets `400`; storage failure gets a retryable
   `503`. A retry of the same delivery does not duplicate it.
2. **Group.** Related alerts join an Incident and its owning Situation. A
   later firing after a terminal Situation opens a new linked Situation;
   the old episode does not reopen.
3. **Observe.** Bounded checks collect current source evidence. A missing,
   unavailable, unsupported, or stale result is kept distinct from a source
   that authoritatively reports clear.
4. **Assess.** Source facts determine lifecycle. Acute Triage and Situation
   assessment run when due, within their recorded limits. A result based on
   superseded inputs cannot replace the current Finding.
5. **Present.** Slack has one main message per Situation, with meaningful
   changes in its thread. MCP exposes current state, evidence, and recorded
   history.

## Lifecycle: what happened to the monitored alerts?

| State | Operator meaning | Next step |
|---|---|---|
| Active | The episode is still open. Firing alerts, changed evidence, and investigation can affect the current assessment. | Keep monitoring and do only work that is actually due. |
| Confirming recovery | All required alerts have authoritative clearance, but the stored grace period is still running. | Observe through that period; a refire returns to Active. |
| Recovered | Monitored alerts stayed clear through the grace period. This Situation is terminal. | Tracking for this episode ends. |
| Closed unknown | Required source truth could not be established before the lifecycle deadline. Recovery was **not** proven. This Situation is terminal. | State the uncertainty and end tracking for this episode. |

An investigation failure cannot recover or close a Situation by itself. A
missing recovery event cannot be counted as clearance. After either terminal
outcome, a genuinely later firing starts a linked Situation with its own
assessment and operator decisions; the earlier Situation remains history.
There is no manual-close command in this workflow.

The short Slack orientation — **Observed**, **Investigating**, **Monitoring**,
**Confirming recovery**, then a terminal outcome — describes where the
Situation is *now*. It is not a checklist of steps completed. AlertINT can
skip an orientation or return to investigation when new work is justified.
Monitoring means watching alert changes, not that analysis succeeded or the
source problem is solved.

## Investigation: what work is actually happening?

Investigation belongs to an Incident inside the Situation. The controller
first decides whether current inputs need a new attempt. A request can be
queued without running yet; a running attempt has actually been claimed.
Exact prior coverage may justify a skip, but a skip is not a new Finding.
If an attempt fails, a recorded retry time may apply. If its schedule is
exhausted, no automatic retry is promised on that schedule, even if an alert
still fires. A compatible result becomes a Finding; changed inputs can make
an in-flight result stale.

Slack should name a real retry time or a specific limitation when either
changes the operator's next step. A **next status check** is not a promise
that another model call will run. Investigation and source monitoring can
continue independently, and neither creates a recovery event.

## Expected maintenance: an operator decision, not source recovery

For a current non-critical condition, an operator can mark one Situation
expected until a time. A reusable expected schedule can apply only when the
source rule and scope have sufficiently proven identity. The Finding stays
visible; monitoring, evidence collection, and already authorized
investigation continue. Unchanged repeated telemetry does not ask for the
same decision again.

Expiry, withdrawal, a changed condition or source rule, criticality, or
independent urgency stops expectedness and restores normal assessment. Slack
explains why. Missing or ambiguous proof never grants a reusable schedule.
Only authoritative source clearance followed by the existing grace period
can recover the Situation. See [MCP clients](../integrations/mcp-clients.md)
for the controls and history.

## What appears in Slack and MCP

The Slack root keeps the current title, lifecycle/status, then **Finding**
in that order. It also shows applicable operator context, the real next
checkpoint, and an alert summary. The thread records useful changes: a
finding, a material alert or urgency change, an expectedness decision
starting or ending with its reason, recovery confirmation, or a delivery-gap
recovery. Routine checks and repeated unchanged conditions stay quiet.
Technical schedule IDs and review details belong in MCP.

Use [MCP](../integrations/mcp-clients.md) current reads to answer “what is
true now?” and transition/judgment history to answer “what changed and why?”
An expired or withdrawn judgment in history is not current authority. A
current source configuration cannot be used to invent the version of an old
alert. See [Slack](../notifications/slack.md#situation-owned-slack) for the
full presentation contract.

## Example: nightly reconciliation

| Time | Event | What the operator sees |
|---|---|---|
| 22:07 | A firing CPU alert arrives. | One Situation root opens with current status; the Finding appears when investigation produces one. |
| 22:12 | John marks this non-critical condition expected until 23:00. | `Operator: Expected until 11:00 PM · John`; monitoring continues. |
| 22:30 | The same condition repeats unchanged. | No repeat request for John's decision. |
| 22:41 | The source rule changes. | The thread explains why the decision stopped applying; normal assessment resumes. |
| 22:50 | The source reports clear. | Confirming recovery begins; AlertINT waits through the stored grace period. |
| 23:20 | A later firing follows confirmed recovery. | A new linked Situation opens; it does not inherit expectedness. |

If Slack delivery fails, the Situation and notification intent remain durable.
Slack retries, while current state remains readable through MCP. An HTTP
`204` proves accepted work is on disk, not that investigation or Slack
delivery has finished.
