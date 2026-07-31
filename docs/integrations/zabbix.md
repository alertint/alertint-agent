---
title: "Zabbix"
description: "Push Zabbix problem/resolution events into AlertINT as a first-class alert source, and pull operator/CMDB/problem context back at triage time."
section: "Integrations"
order: 7
slug: "zabbix"
---

# Zabbix

**AlertINT** integrates with Zabbix in two independently-enableable roles:
Zabbix **pushes** problem/resolution events to AlertINT over a webhook (the
`zabbix.ingress` receiver, below), and AlertINT optionally **pulls** read-only
context back from the Zabbix API at triage time — the operator's runbook,
trigger dependencies, flap history, host CMDB/topology, other open problems,
and acknowledgement history (`zabbix.api`, further down). A Zabbix shop gets
correlated, triaged incidents the same way an Alertmanager shop does, with the
option to hand the LLM the same operator knowledge a human on-call would reach
for.

**Version target:** Zabbix 7.0.x LTS; the contract below is verified against
the 7.0 macro and JSON-RPC API documentation.

## Push: the alert source (`zabbix.ingress`)

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

Prefer importing? [`examples/zabbix-media-type.yaml`](https://github.com/alertint/alertint-agent/blob/main/examples/zabbix-media-type.yaml)
is this media type as a Zabbix 7.0 import file — **Alerts → Media types →
Import**, then set the `url` and `token` parameters for your install.

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

## Pull: the Zabbix context (`zabbix.api`)

When `zabbix.api` is enabled, AlertINT reads back three bounded, read-only
classes of context from the Zabbix JSON-RPC API at triage time and attaches
them to the LLM prompt, the persisted finding, and two MCP tools. The client
issues only `*.get` methods (plus the unauthenticated `apiinfo.version` health
probe) — it never mutates Zabbix state.

### Configuration

```yaml
zabbix:
  api:
    # enabled: false                       # uncomment to force OFF even when base_url is set
    base_url: https://zbx.example.com      # Zabbix frontend root; /api_jsonrpc.php is appended
    api_token_env: ZABBIX_API_TOKEN        # env var holding a read-only API token
    timeout_seconds: 10                    # default
    default_range_minutes: 60              # default; zabbix_metric_history look-back when start is omitted
    history_retention_days: 7              # default; windows older than this fall back to hourly trends
    flap_window_hours: 24                  # default; look-back for the trigger flap count
    host_label: host                       # default; alert label carrying the Zabbix technical host name
```

Enablement is presence-based: setting `base_url` turns the Source on
automatically; an explicit `enabled: false` forces it off. See the
[configuration reference](../getting-started/configuration.md#zabbix) for the
full field table.

### Read-only API identity

Create a dedicated service user for AlertINT rather than reusing a human
account:

1. **User roles → Create role.** Set **API access** to a dedicated role whose
   API methods are an **Allow list** containing only:
   `host.get, trigger.get, problem.get, event.get, item.get, history.get, trend.get`.
   This is the read-only contract, enforced on the Zabbix side, not just
   documented — the client only ever calls these methods, and the token
   cannot do anything else even if it leaked.
2. **Users → User groups → Create user group.** Grant **Read** permission on
   the host groups you want AlertINT to see context for (not Deny-by-default
   on everything — an unlisted host group returns empty results, not an
   error, which reads as "no context" rather than "misconfigured").
3. **Users → Create user.** Assign the role from step 1 and the group from
   step 2.
4. **Users → API tokens → Create API token,** scoped to that user, with no
   expiry (or a long one you rotate deliberately). Export it as the env var
   named by `api_token_env`:

```bash
export ZABBIX_API_TOKEN="<the generated token>"
```

Auth is the `Authorization: Bearer` header — never the legacy `auth` request
parameter, which Zabbix removed in 7.2.

### The Apache gotcha (ZBX-22952)

If your Zabbix frontend runs under **Apache**, `CGIPassAuth On` is required in
the frontend's Apache config or the `Authorization` header is silently
stripped before PHP ever sees it (nginx is unaffected). The symptom is
distinctive: the `zabbix` health check stays green — `apiinfo.version` needs
no auth and answers fine — while every real context fetch comes back empty or
unauthorized. If context is silently missing but health looks fine, check this
first.

### What the Zabbix context adds

| Class | Needs | Adds |
|---|---|---|
| **Operator knowledge** | `zabbix_trigger_id` label | The trigger's runbook (`comments`), a jump-off `url`, the raw trigger expression, upstream dependency triggers (possible root cause), and how many times it has fired in the flap window. |
| **CMDB/topology** | the configured `host_label` only — works even for non-Zabbix-origin incidents | Host groups, templates (role/stack), a curated inventory subset (contact, location, OS, hardware), live maintenance state, per-interface reachability, and other currently-open problems on the same host. |
| **Problem detail** | `zabbix_event_id` annotation | Ongoing/duration, suppression (maintenance vs. manual, with an until-time), operational data, and acknowledgement history (who already knows, with their message). |

Runbooks, host descriptions, operational data, and acknowledgement messages
are operator-authored free text — they render inside AlertINT's untrusted-text
frame (context for the model, never instructions) and are never treated as
evidence the host is healthy when the section is empty or a class failed.

### MCP tools

When `zabbix.api` is enabled, two additional tools become available to your
MCP client:

| Tool | Description |
|---|---|
| `zabbix_metric_history` | An item's metric history for a host (raw `history.get`, or hourly `trend.get` for windows older than `history_retention_days` — the response's `source` field says which). Parameters: `host`, `item_key` (required), `start`/`end` (optional RFC3339), `limit` (optional). |
| `zabbix_host_problems` | Currently-open Zabbix problems on a host, with severity, tags, duration, and ack/suppression state. Parameters: `host` (required), `severity_min` (optional, `"0"`–`"5"`). |

Both take a **host + item key**, never Zabbix internal IDs — the tools hide
the item-discovery dance and the `history.get` value-type quirk (it silently
returns nothing for a float item unless the item's type is resolved first).

```text
Show CPU history for web01 over the last 2 hours.
List open problems on db-primary with severity at least high.
```

## Verification

With `zabbix.api` configured, the [verification round](../concepts/verification-round.md)
runs its Zabbix floor checks automatically, no additional configuration
required: the incident host's reachability (per-interface, maintenance-aware)
and whether its smallest host groups have other open problems. On installs
that don't also run Prometheus, this is what replaces the permanent
`⚠ unverified — checks unavailable` caveat with a genuine, checked finding.
