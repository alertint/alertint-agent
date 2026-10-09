---
title: "ntfy"
description: "Send selected Situation changes to your phone using ntfy.sh or your own ntfy server."
section: "Notifications"
order: 2
slug: "ntfy"
---

# ntfy

**Availability:** planned for AlertINT 0.15. The current v0.14.3 release does
not include this integration. Until 0.15 is released, test from a source
checkout containing the ntfy changes; do not add these fields to v0.14.3.

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

Notification bodies can contain alert labels, summaries and investigation
evidence. ntfy.sh receives that content when you choose its hosted endpoint;
your own server can keep delivery inside your network. Use separate publishing
and read-only subscriber credentials where your ntfy server supports them.

## Docker Compose

From the repository, create a gitignored local config and point Compose at it:

```bash
cp .env.example .env
cp docker/agent.config.yaml docker/agent.config.local.yaml
```

Fill in the normal required variables in `.env`, then add:

```bash
ALERTINT_CONFIG_FILE=./agent.config.local.yaml
NTFY_TOKEN=tk_your_publisher_access_token
```

In `docker/agent.config.local.yaml`, uncomment `notify.ntfy`, set your topic and
server, and keep `token_env: NTFY_TOKEN`. The Compose stack passes that optional
variable into the agent. For anonymous publishing, set `token_env: ""`.

Before 0.15, build the ntfy-enabled source checkout rather than pulling the
released image:

```bash
docker compose -f docker/docker-compose.yaml -f docker/docker-compose.build.yaml \
  --env-file .env up --build -d
```

After release, use the normal Compose stack with a 0.15 image. A changed
config or environment requires recreating the agent container.

## Kubernetes

Use a chart and image from the release that includes ntfy. For a source-built
test image, override the image repository/tag explicitly. The current chart's
default v0.14.3 image does not accept ntfy configuration.

Add ntfy under the chart's `config` and refer to a Secret you manage:

```yaml
config:
  notify:
    ntfy:
      enabled: true
      base_url: https://ntfy.example.com
      topic: infrastructure-alerts
      token_env: NTFY_TOKEN
      # Omit events for the five defaults.

extraEnv:
  - name: NTFY_TOKEN
    valueFrom:
      secretKeyRef:
        name: alertint-ntfy
        key: publisher-token
```

The Secret above supplies only the ntfy token. Keep the chart's existing
Secret configuration for the other required agent variables. Alternatively,
add `NTFY_TOKEN` to your existing `secret.existingSecret`; its keys are already
exposed through `envFrom` and need no separate `extraEnv` entry. See the
[Helm guide](../getting-started/kubernetes.md) for the supported Secret modes.

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

Messages use Markdown with compact service/outcome titles, readable alert names,
bold section labels, evidence bullets and a copyable Situation reference. Required
actions and uncertainty appear before bounded analysis details. Historical analysis
is labeled separately; recovery confirmation does not imply a confirmed cause.
Activity and checkpoint times are explicitly scoped to the update, so an ordered
older notification does not claim the investigation is still running now.
The app's notification list and expanded message show the rich layout. Android
app version 1.17.8 or newer renders Markdown; system notification previews may
show a simpler layout. See [ntfy's formatting guide](https://docs.ntfy.sh/publish/#markdown-formatting).

Only the renderer supplies Markdown syntax. Alert, journal and analysis text is
escaped, and long content is shortened by section with an explicit MCP history
notice. Existing queued messages keep their frozen payload when an agent upgrade
changes the layout; new messages use the updated presentation.

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
ntfy delivery resumed · ✅ Recovered · payment
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

### Android setup

1. In the ntfy app, add a subscription using your **topic** and **server URL**.
   Use `https://ntfy.sh` or your public/self-hosted HTTPS URL. The phone must
   be able to reach it; `localhost` and Docker service names will not work
   from a phone. Include the port if your HTTPS endpoint uses a custom port.
2. For an authenticated server, add the server's subscriber username and
   password under the app's user settings. These are ntfy credentials,
   separate from the publisher access token named by `token_env`.
3. Allow notifications and check the app's instant/background delivery status.
   Test once with the app open and once with the screen locked.

Subscribe to the same topic used by AlertINT. Choose read-only subscriber
access if the phone does not need to publish. Android 1.17.8+ renders Markdown
inside the app; the operating system's notification preview may be simpler.

## Verify delivery and troubleshoot

First send a clearly marked setup message directly to your ntfy endpoint:

Set `NTFY_TOKEN` in your current shell to your publisher access token before
running this command. The `.env` file used by Compose does not export variables
into your shell.

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $NTFY_TOKEN" \
  -H 'Title: DRILL - AlertINT ntfy setup test' \
  -H 'Markdown: yes' \
  --data-binary '**DRILL**: Setup test only. No live incident.' \
  https://ntfy.example.com/infrastructure-alerts
```

Replace the server/topic; omit the Authorization header for anonymous
publishing. This confirms ntfy and phone connectivity. Then run
[`alertint drill`](../getting-started/quickstart.md#2-fire-a-drill) through the
configured agent to verify event selection and agent delivery. Drills use the
configured LLM and can incur provider charges; use a mock provider for delivery
mechanics tests. Confirm both the initial and recovered updates, including
with the app in the background.

| Symptom | Check |
|---|---|
| Agent rejects the config | Use a build with ntfy support, run `alertint validate`, and check the event names. |
| Agent fails startup with an empty token variable | Supply the named variable to the process/container, or remove `token_env` for anonymous publishing. |
| HTTP 401 or 403 | Check the publisher token and write access to this exact topic. Check subscriber read access separately. Correct configuration-blocked work resumes after an agent restart. |
| HTTP 429 | ntfy rate-limited the publisher; the queue retries with backoff and honors `Retry-After`. |
| No update reaches the phone | Check the exact server/topic, selected events and the agent's ntfy delivery logs. Try the direct setup message above. |
| Only arrives when the app is open | Check phone reachability, instant delivery and battery restrictions; on self-hosted iOS, check upstream push configuration. |
| Delayed recap or duplicate | Catch-up summarizes the latest committed state after a pause/outage; an uncertain HTTP response can produce a duplicate on retry. |
| Old messages still have the previous layout | Previously queued payloads and phone history remain unchanged; new updates use the current renderer. |

There is no startup test push. Successful ntfy acceptance confirms server
delivery, while receipt on a locked phone confirms that device's background
delivery. The complete Situation record stays available through MCP.
