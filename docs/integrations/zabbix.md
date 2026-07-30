---
title: "Zabbix"
description: "Push Zabbix problem/resolution events into AlertINT as a first-class alert source."
section: "Integrations"
order: 7
slug: "zabbix"
---

# Zabbix

Zabbix pushes problem/resolution events to AlertINT over a webhook; a `zabbix`
receiver maps them to canonical alerts and hands them to the correlator. A
Zabbix shop gets correlated, triaged incidents the same way an Alertmanager
shop does — no Zabbix API access, no polling, no extra infrastructure.

**Version target:** Zabbix 7.0.x LTS; the contract below is verified against
the 7.0 macro documentation. This chunk is inbound-only — AlertINT never calls
the Zabbix API.

## What you get

- Zabbix `PROBLEM`/`RESOLVED` events become correlated, triaged incidents,
  the same pipeline Alertmanager alerts go through.
- Severity ranks correctly out of the box, including installs that renamed
  their severity display names.
- Per-host grouping with zero configuration. Tag a trigger with a `service`
  value to correlate across hosts for that condition.

## AlertINT config

```yaml
zabbix:
  ingress:
    enabled: false
    webhook_token_env: ALERTINT_ZABBIX_WEBHOOK_TOKEN   # bearer token Zabbix presents to /webhook/zabbix
```

The bearer token is supplied via the named environment variable, never inline:

```bash
export ALERTINT_ZABBIX_WEBHOOK_TOKEN="$(openssl rand -hex 24)"
```

See the [configuration reference](../getting-started/configuration.md#zabbix).

## Zabbix media type (copy-paste)

Create **Alerts → Media types → Create media type**, type **Webhook**, with
parameters:

| Parameter | Value |
|---|---|
| `url` | `http://<alertint-host>:9911/webhook/zabbix` |
| `token` | `<the value of ALERTINT_ZABBIX_WEBHOOK_TOKEN>` |
| `payload` | `{"event_id":"{EVENT.ID}","status":"{EVENT.STATUS}","severity":"{EVENT.SEVERITY}","nseverity":"{EVENT.NSEVERITY}","host":"{HOST.HOST}","host_visible":"{HOST.NAME}","trigger_id":"{TRIGGER.ID}","trigger_name":"{TRIGGER.NAME}","item_key":"{ITEM.KEY}","item_value":"{ITEM.VALUE}","tags":{EVENT.TAGSJSON},"clock":"{EVENT.DATE} {EVENT.TIME}","recovery_clock":"{EVENT.RECOVERY.DATE} {EVENT.RECOVERY.TIME}","generator_url":"{$ZABBIX_URL}/tr_events.php?triggerid={TRIGGER.ID}&eventid={EVENT.ID}"}` |

Script:

```javascript
var params = JSON.parse(value);
var req = new HttpRequest();
req.addHeader('Content-Type: application/json');
req.addHeader('Authorization: Bearer ' + params.token);
var resp = req.post(params.url, params.payload);
if (req.getStatus() >= 300) {
    throw 'alertint replied ' + req.getStatus() + ': ' + resp;
}
return 'OK';
```

Two setup subtleties:

- **`{EVENT.TAGSJSON}` must appear unquoted** in the `payload` parameter,
  exactly as shown above. Zabbix macro expansion runs before the script does,
  and `{EVENT.TAGSJSON}` already expands to a JSON array (`[]` if the trigger
  has no tags) — quoting it would turn a JSON array into a JSON string.
- **`{$ZABBIX_URL}`** is a user macro you define yourself (**Data collection →
  Macros**, or globally under **Users → API tokens** settings), holding your
  Zabbix frontend's base URL. It's only used to build `generator_url`, a
  clickable link back to the triggering event.

## Trigger action

**Alerts → Actions → Trigger actions → Create action.** Event source
*Triggers*; add an operation "Send message" via this media type to a service
user (not a person — this media type is machine-to-machine). Enable
**recovery operations** using the same media type so `RESOLVED` events flow
through and close out the incident.

## What lands on the incident

| Alert field | Source | Notes |
|---|---|---|
| Fingerprint | `event_id` | Namespaced `zabbix:<event_id>`, stable across the `PROBLEM`→`RESOLVED` pair, so the resolution dedups onto the same alert row. |
| Status | `status` | `PROBLEM` → firing, `RESOLVED` → resolved. |
| Timestamps | receipt time | `StartsAt`/`EndsAt` are stamped when AlertINT receives the webhook, never parsed from `clock`/`recovery_clock` — those expand in the Zabbix server's own timezone with no UTC offset in the string, which would silently skew timestamps that anchor enrichment windows. The raw `clock`/`recovery_clock` strings still ride along as annotations for reference. |
| `alertname` label | `trigger_name` | Aligns with Alertmanager's grouping vocabulary. |
| `host` label | `host` | The technical host name (`{HOST.HOST}`) — the correlator's per-host identity. |
| `severity` label | `severity` | Verbatim, with a fallback — see below. |
| `zabbix_trigger_id` label | `trigger_id` | Stable across firing episodes of the same condition — safe for grouping. |
| tag labels | `tags[]` | Each `{tag: value}` becomes a label, key sanitised to `[a-zA-Z0-9_]`. A tag colliding with a core label name is dropped; the core label wins. |
| `zabbix_event_id`, `host_visible`, `trigger_name`, `item_key`, `item_value`, `generator_url`, `clock`, `recovery_clock` annotations | as named | Display/debug context, never used for grouping. |

## Severity

The `severity` label carries Zabbix's own severity name verbatim — you see the
same word your Zabbix UI shows. AlertINT's shared severity ladder ranks the
full Zabbix vocabulary:

| Zabbix severity | Rank | Sits with |
|---|---|---|
| `information` | 1 | `debug` / `info` / `low` |
| `warning` | 2 | `notice` / `medium` |
| `average` | 2 | same tier as `warning` |
| `high` | 3 | `error` |
| `disaster` | 5 | `emergency` / `fatal` / `page` — Zabbix's top severity |
| `not classified` | 0 (unranked) | unknown ranks below everything; never manufactures an escalation |

**Renamed severities:** Zabbix severity names are per-install configurable —
only the numeric `{EVENT.NSEVERITY}` (0–5) is stable. If your install renamed
its severity display names, an unrecognized name falls back to the numeric
tier's canonical Zabbix name for ranking (so escalation still works), and your
renamed word is preserved as a `severity_display` annotation on the alert. A
rename to a word the ladder already knows (e.g. "critical") stays verbatim and
ranks normally — only genuinely unrecognized names trigger the fallback.

## Grouping

The default `correlator.group_labels` includes `host`, so Zabbix alerts
correlate per-host with zero configuration — no `cluster`/`namespace`/`service`
labels required. To correlate a condition across hosts (e.g. one incident for
a shared dependency failing on several hosts at once), tag the trigger with a
`service` tag; tags pass through as labels and participate in grouping like
any other configured label.
