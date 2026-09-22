---
name: alertint-situation-investigation
description: Investigate and explain AlertINT Situations or Slack Situation cards through the configured AlertINT MCP server, using recorded lifecycle, evidence, and operator history before proposing authorized follow-up.
---

# AlertINT Situation investigation

Use AlertINT's MCP records to explain what is happening, why the Situation
changed, and what AlertINT will do next. Keep current state, historical
decisions, and new live observations distinct.

The canonical workflow and tool reference is the
[AlertINT MCP client guide](https://github.com/alertint/alertint-agent/blob/v0.14.0-rc1/docs/integrations/mcp-clients.md#explain-a-situation-from-records).

## Resolve the reference

- For a Situation ID or public handle, start with `alertint_get_situation`.
- For a Slack Situation card, use the Situation handle or ID shown by the card.
- For a legacy Incident reference, call `alertint_get_incident` first. Follow
  its owning Situation reference when present; otherwise explain the Incident
  from its own record and do not assume its ID is a Situation ID.
- Keep synthetic Drill records visible as drills. Investigate one when the
  operator deliberately requests the drill.

## Read recorded state before querying live systems

1. Read the current Situation with `alertint_get_situation`.
2. Read `alertint_list_situation_transitions` for the recorded sequence of
   lifecycle, attention, Finding, operator-contract, and recovery changes.
3. Inspect relevant member Incidents and persisted evidence with
   `alertint_get_incident`, `alertint_get_evidence_pack`, and
   `alertint_list_observation_runs`.
4. When expectedness matters, read the episode judgment history with
   `alertint_list_situation_judgments` and reusable schedule history with
   `alertint_list_expected_behavior_history`. Use
   `alertint_get_expected_behavior` for current schedule authority.
5. Read `alertint_get_delivery_state` only when notification delivery affects
   the question.

Treat captured observations as historical evidence. State when a result was
successful, empty, unavailable, unsupported, stale, expired, truncated, or
never queried. Never reconstruct missing history from current source
configuration.

Use live Prometheus, log, change, Sentry, or Zabbix reads only when the
question needs current or wider evidence. Carry the Situation's exact scope
and an explicit bounded time range into the query. Do not claim that a query
was automatically scoped or audited.

## Give a short operator brief

Default to:

- **Finding:** the strongest conclusion supported by the records. When none
  is supported, write **Finding: Insufficient evidence — [specific missing or
  failed evidence].**
- **Evidence:** the few record IDs, times, and observations that support or
  contradict the Finding.
- **Now:** current lifecycle, attention, alert state, and expectedness. Never
  equate expectedness with recovery or severity with confidence.
- **Next:** AlertINT's recorded automatic action and deadline. If none is
  recorded, say so; do not turn a proposed investigation into a scheduled
  action.

Then offer up to three numbered investigation options that can be executed
with tools present in this connection. Put the most useful option first and
omit filler. Choosing a read option authorizes that investigation. It does
not authorize a write.

## Check the MCP connection when needed

Run this check at first setup, when the operator asks, or after a connection
failure. Do not run it before every investigation.

1. Confirm MCP initialization and tool discovery.
2. Make one bounded AlertINT state read, such as
   `alertint_list_situations` with a small limit.
3. Report each relevant capability as:
   - **available/configured:** its conditional tool is present;
   - **queried successfully:** a needed bounded probe succeeded;
   - **failed:** authentication, connection, or probe failed, with a specific
     next step that reveals no secret;
   - **not checked:** configured or discoverable but not probed.

Log, change, Sentry, and Zabbix tools are registered only when their MCP
capability is configured. Their presence does not prove reachability, and
absence does not prove the whole underlying integration is absent.
Prometheus tools are always registered, so their presence does not establish
configuration or reachability. Probe a source only when the requested check
or investigation needs it.

## Writes require a separate operator decision

Never record a note, verdict, expected-until judgment, reusable schedule, or
semantic-profile correction without explicit operator authorization for that
write. Re-read current versions immediately before version-fenced writes,
preserve each tool's confirmation fields, and report the resulting record ID
and revision. Tool annotations are client hints, not an authorization system.

Expectedness suppresses repeated requests for the same operator action. It
does not stop monitoring or investigation, change lifecycle, fabricate a
Finding, or recover a Situation. Source clearance and the recorded grace
period determine recovery.
