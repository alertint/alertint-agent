---
title: "ntfy"
description: "Send selected Situation changes to your phone using ntfy.sh or your own ntfy server."
section: "Notifications"
order: 2
slug: "ntfy"
---

# ntfy

AlertINT sends selected material Situation changes to one ntfy topic. Use
[ntfy.sh](https://ntfy.sh) or your own server. ntfy can run alongside Slack or
as the only external notification destination. Situation decisions and
investigations are shared; sending notifications adds no LLM calls.

## Configuration

```yaml
notify:
  ntfy:
    enabled: true
    base_url: https://ntfy.sh
    topic: your-reserved-topic
    token_env: NTFY_TOKEN
    events:
      - first_notification
      - priority_escalated
      - operator_action_required
      - recovered
      - closed_uncertain
```

Put the access token in the named environment variable, never in YAML.
Omit `token_env` for a server/topic that allows anonymous publishing. A named
but empty or missing variable fails startup. Use an access-controlled topic
for production information: public topic names alone are not access control.

`base_url` defaults to `https://ntfy.sh`; it also accepts HTTP for a private
server. Topic names contain 1–64 letters, digits, underscores or hyphens.
URLs cannot contain embedded credentials, query parameters or fragments.
Redirects are rejected so credentials and incident content stay with the
configured endpoint. The server and topic identify one destination.

On Kubernetes, pass the token through a Secret using the chart's `extraEnv`
configuration. Set the corresponding fields under `config.notify.ntfy`.

## Select events

An omitted `events` list uses the five defaults below. An explicit list
replaces those defaults; `events: []` selects nothing. Unknown names fail
startup. Selection is independent of the Slack severity floor.

| Event | Default | Meaning |
|---|---|---|
| `first_notification` | On | First committed state with controller publication authority |
| `priority_escalated` | On | Increased committed interruption priority or attention |
| `operator_action_required` | On | A required operator action appears or materially changes |
| `recovered` | On | Recovery is confirmed after its stability period |
| `closed_uncertain` | On | Tracking ends without confirmed recovery |
| `investigation_started` | Off | Investigation begins executing |
| `investigation_completed` | Off | Investigation ends or yields materially changed findings |
| `coverage_degraded` | Off | A new recorded investigation limitation appears |
| `coverage_restored` | Off | A previously recorded investigation limitation clears |
| `recovery_pending` | Off | Clearance is observed, awaiting stability |
| `recovery_refired` | Off | A new firing interrupts recovery confirmation |
| `members_changed` | Off | Material scope or member changes |
| `operator_updated` | Off | An attributed operator update is recorded |

A committed change matching multiple selected events creates one message,
including annotations and controller journal entries committed together.
Routine reconciliations and message refreshes create none. There is no blanket
cooldown hiding a newly required action. Installation-wide health notices
(such as LLM provider availability) are outside this integration.

## Delivery and configuration changes

Delivery work is written atomically with the Situation transition to an
independent SQLite queue. Slack acknowledgements do not consume ntfy work.
The worker makes bounded HTTP requests outside database transactions. Valid
pending work retries with backoff and survives restart; HTTP rate-limit
`Retry-After` is honored. Configuration rejections block retained work until
restart with corrected configuration. Delivery outcomes are logged and audited.

The guarantee is **at-least-once external delivery**: if ntfy accepts a message
but its response is lost, a retry may display a duplicate. A retry keeps the
same notification identity and frozen content; external deduplication is not
assumed. Messages are ordered within a Situation.

Configuration changes take effect on restart:

- Changing `events` affects future changes, without historical backfill.
  Existing selected delivery work stays queued.
- Disabling ntfy pauses delivery. Pending work resumes when the same destination
  is enabled again, using the catch-up rules below.
- Rotating the token lets retained configuration-blocked work retry.
- Changing the server/topic retires undelivered work for the old destination
  with the recorded reason `destination_changed`. It is not forwarded to a
  different audience. Delivered records remain.

## Catch-up after an outage or pause

After failed or paused delivery, obsolete queued pushes for a Situation become
one catch-up notification describing its latest committed state. The original
selected events remain attached to the obligation; catch-up does not subscribe
to additional event categories. The original rows stay recorded as superseded
and link to their replacement.

For example, an operator-action notification delayed until after recovery says:

```text
ntfy delivery resumed · Recovered · S-104
Notifications were delayed while ntfy delivery was unavailable or paused.
This is the current committed Situation state.
```

It states recovery rather than repeating an obsolete action request. A Situation
that remains active reports the current required action. A catch-up is a recap
of already selected work: it can describe the current recovered state even if
`recovered` is not selected for new notifications. Full history remains in MCP.
Catch-up identities and content are frozen before sending and reused on retries.
If queued work becomes obsolete before its first attempt, a current-state
`ntfy queued update` replaces it without claiming an outage occurred. An
unchanged-state retry retains its original message and identity.

Messages are compact, bounded to 4,000 UTF-8 bytes and carry the Situation
identity, event time and uncertainty when available. Drills are labeled
`DRILL`; confirmed recovery and uncertain closure are distinct.

## Receive notifications

Install the ntfy app, subscribe to the configured server/topic and supply your
subscriber credentials. Allow notifications. For self-hosted Android delivery,
check that background/instant delivery is active; restrictive battery settings
can interfere with it. See [ntfy's Android/iOS guide](https://docs.ntfy.sh/subscribe/phone/).

Self-hosted instant iOS notifications require the server's upstream push setup;
see [ntfy's iOS configuration](https://docs.ntfy.sh/config/#ios-instant-notifications).
