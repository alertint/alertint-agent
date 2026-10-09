---
title: "ntfy"
description: "Connect AlertINT to an existing ntfy server and choose which Situation updates reach your phone."
section: "Notifications"
order: 2
slug: "ntfy"
---

# ntfy

Send Situation updates to [ntfy.sh](https://ntfy.sh) or your existing ntfy server. Works with or without Slack.

## 1. Configure AlertINT

In your AlertINT configuration, add `ntfy` to the existing `notify` section:

```yaml
notify:
  ntfy:
    enabled: true
    base_url: https://ntfy.sh
    topic: infrastructure-alerts
    token_env: NTFY_TOKEN
```

| Setting | What to use |
|---|---|
| `base_url` | Server URL, without the topic. Include any custom port; both AlertINT and your phone must reach it. |
| `topic` | Your topic name: 1–64 letters, digits, underscores or hyphens. |
| `token_env` | Environment variable holding an ntfy access token with **write** access to this topic. Omit for anonymous publishing. |

- Get an [access token](https://docs.ntfy.sh/publish/#access-tokens) from your ntfy web app's **Account** section or server administrator.
- Set `NTFY_TOKEN` in AlertINT's environment or secret store, **not in YAML**. A missing or empty named variable prevents startup.
- Use an access-controlled topic for incident details; a topic name alone does not restrict who can read it.
- Restart AlertINT after changing configuration or credentials.

## 2. Subscribe in ntfy

1. Install the [ntfy app](https://docs.ntfy.sh/subscribe/phone/) and add the **same server URL and topic**.
2. If authentication is required, add your subscriber **username/password** in the app's user settings. These are separate from AlertINT's publisher token; the subscriber needs **read** access.
3. Allow notifications. On Android, check instant delivery and battery restrictions; the phone must reach the server while the app is in the background.

Messages use Markdown inside the app; system notification previews may look simpler. For self-hosted iOS, your server needs [upstream push configured](https://docs.ntfy.sh/config/#ios-instant-notifications).

## 3. Choose updates (optional)

Omit `events` to use the five defaults marked **On**. To choose your own list, add it under `notify.ntfy`:

```yaml
events:
  - first_notification
  - operator_action_required
  - recovered
```

An explicit list replaces the defaults. `events: []` sends nothing; unknown names fail validation. Slack settings do not affect this selection.

| Event | Default · sends an update when… |
|---|---|
| `first_notification` | **On** · A Situation first needs attention. |
| `priority_escalated` | **On** · Priority or urgency increases. |
| `operator_action_required` | **On** · A required action appears or changes. |
| `recovered` | **On** · Recovery is confirmed after its stability period. |
| `closed_uncertain` | **On** · Tracking ends without confirmed recovery. |
| `investigation_started` | Off · Investigation starts. |
| `investigation_completed` | Off · Investigation finishes or findings change. |
| `coverage_degraded` | Off · An investigation limitation appears. |
| `coverage_restored` | Off · An investigation limitation clears. |
| `recovery_pending` | Off · Alerts clear; recovery confirmation is pending. |
| `recovery_refired` | Off · Alerts fire again before recovery is confirmed. |
| `members_changed` | Off · A Situation's scope or alerts change. |
| `operator_updated` | Off · An operator adds an update. |

## 4. Check delivery

With the phone subscribed, send a setup test. Replace the URL/topic and set `NTFY_TOKEN` in this terminal too; omit the Authorization header for anonymous publishing.

```bash
export NTFY_TOKEN='tk_your_access_token'
curl --fail-with-body \
  -H "Authorization: Bearer $NTFY_TOKEN" \
  -H 'Title: DRILL - AlertINT ntfy setup test' \
  -H 'Markdown: yes' \
  --data '**DRILL**: Setup test only.' \
  https://ntfy.sh/infrastructure-alerts
```

This checks ntfy and your phone. Then [run an AlertINT drill](../getting-started/quickstart.md#2-fire-a-drill) to check the integration: with default events, expect initial and recovered updates marked **DRILL**. Repeat with the screen locked. Restarting AlertINT alone sends no test message.

| Problem | Check |
|---|---|
| Startup/config error | Check event names and the token variable; validate with the command below. |
| HTTP 401/403 | Publisher token needs write access; app credentials need read access. Correct the credentials and restart AlertINT. |
| No notification | Check the exact server/topic, selected events and AlertINT's ntfy delivery logs. Try the curl test above. |
| Only arrives with the app open | Check server reachability, instant delivery and battery restrictions; self-hosted iOS also needs upstream push. |

Use your configuration file path:

```bash
alertint validate --config config.yaml
```

## What to expect

- Only selected Situation changes send pushes; routine refreshes do not. Several events in one change produce one message.
- Failed deliveries retry across restarts; rate limits delay delivery. After a pause/outage, an **ntfy delivery resumed** recap shows the current state instead of obsolete action requests. A retry can occasionally duplicate a message.
- Event changes affect future updates; already queued messages remain. Changing the server/topic does not forward old pending messages to the new destination.
