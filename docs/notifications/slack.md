---
title: "Slack"
description: "Send AlertINT findings to Slack channels."
section: "Notifications"
order: 1
slug: "slack"
---

# Slack

**AlertINT** posts structured Block Kit messages to Slack after every
completed incident analysis. When alerts recover, the original message is
updated in-place and a thread reply is posted — one message per incident,
no channel noise.

Synthetic incidents fired by `alertint drill` are unmistakable in a shared
channel: every surface of their card — headline, thread details, and the
plain-text fallback — carries a 🧪 **DRILL** banner, so a drill never
reads as a real incident to a teammate scrolling past.

## Setup — Slack app with bot token

Bot tokens let **AlertINT** track the message it posted. When an incident
fires, **AlertINT** posts a rich Block Kit message and records its position in
the channel. When all alerts recover, it updates that message in-place
(🔴 → ✅, a duration field appears) and posts a short resolution note in
the thread.

1. **Create a Slack app.** Go to <https://api.slack.com/apps> and click
   **Create New App → From scratch**. Name it **AlertINT** and select your
   workspace.

2. **Add the `chat:write` scope.** In the left sidebar, click
   **OAuth & Permissions**, scroll to **Bot Token Scopes**, and add
   `chat:write`. That is the only permission **AlertINT** needs.

3. **Install to your workspace.** Scroll to the top of
   **OAuth & Permissions** and click **Install to Workspace → Allow**.
   Slack displays a **Bot User OAuth Token** starting with `xoxb-`. Copy
   it.

4. **Invite the bot to your channel.** In Slack, open the channel where
   alerts should appear (create `#alerts` if needed) and type
   `/invite @AlertINT`. The bot must be a channel member to post there.

5. **Add the token to your `.env` file** — the same file that holds your
   other secrets. Never put the token value directly in `config.yaml`:

   ```bash
   # .env  (gitignored — never commit this file)
   SLACK_BOT_TOKEN=xoxb-...
   ```

6. **Add Slack to your `config.yaml`** under `notify`. Use the env var
   name — not the token value itself:

   ```yaml
   notify:
     slack:
       enabled: true
       bot_token_env: SLACK_BOT_TOKEN  # name of the env var — not the token value
       channel: "#alerts"              # channel name or ID where alerts should post
   ```

What happens at runtime:

- **Firing** — posts a brief main-channel message (name + root cause) and
  immediately posts the full analysis — severity, confidence, correlation
  findings, MCP hint — as a thread reply.
- **Resolved** — updates the original main-channel message in-place
  (header changes 🔴 → ✅, duration appears) and posts full resolution
  details — duration, alert count, resolved time — as a thread reply.

## Message structure

Every notification uses Slack Block Kit. The same blocks appear for firing
and resolved — only the header and fields change on resolution.

| Block | Description |
|---|---|
| Main — header | 🔴 INCIDENT DETECTED when firing, updated to ✅ INCIDENT RESOLVED in-place when resolved. |
| Main — root cause | One-sentence root cause hypothesis, preserved when the message is updated on resolution. |
| Main — footer | Incident ID, alert count, group key, and start time. Replaced by resolved time and duration on resolution. |
| Main — agent handoff | `investigate incident <id> using alertint` — the MCP call to action, with the full incident ID. Dropped when the incident resolves. |
| Thread — analysis | Posted immediately after the main message: severity, confidence, alert count, and group key in a fields grid. |
| Thread — evidence | One line: per-source counts (Prometheus/Loki/Changes/Sentry) that fed the triage, e.g. `Prometheus 21 metrics · Loki 0 lines`. A connector that could not be reached shows `unreachable` instead of a count; a known-issue short-circuit shows `skipped (known issue)`; a zero-connector install shows `no sources configured`. Always present. |
| Thread — findings | Bullet list of correlation findings. Only shown when the LLM identified more than one contributing factor. |
| Thread — agent handoff | The same handoff block, so the call to action reads identically on every firing surface. |
| Thread — resolved | Posted when all alerts recover: duration, alert count, and resolved timestamp in a fields grid. |

## Example — firing

Two messages are posted: a brief main-channel message and an immediate
thread reply with the full analysis.

Main channel:

```text
🔴 INCIDENT DETECTED — API Tier Degraded: CPU Saturation + Error Spike

Root cause: CPU saturation on api-2 is causing request queuing, elevating
error rates and response latency across the cluster.

Incident a1b2c3d4 · 3 alerts · group cluster=prod · started 14:37 UTC

🤖 Investigate in your AI agent
investigate incident a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d using alertint
```

Thread reply (posted immediately):

```text
Analysis details

Severity: HIGH        Confidence: 91%
Alerts: 3             Group: cluster=prod

Evidence: Prometheus 14 metrics · Loki 6 lines · Changes 1 · Sentry 2 issues

Correlation findings
• HighCPU (api-2) fired 15 s before HighErrorRate — causal ordering confirmed.
• HighLatency shares the same instance label, indicating single-host origin.

🤖 Investigate in your AI agent
investigate incident a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d using alertint
```

## Example — resolved

The original main-channel message is updated in-place and a resolution
note is posted in the thread.

Main channel (updated in-place):

```text
✅ INCIDENT RESOLVED — API Tier Degraded: CPU Saturation + Error Spike

Root cause: CPU saturation on api-2 is causing request queuing, elevating
error rates and response latency across the cluster.

Incident a1b2c3d4 · resolved after 15m · 14:52 UTC
```

Thread reply:

```text
✅ All clear — all alerts have recovered.

Duration: 15m    Alerts: 3 recovered    Resolved: 14:52 UTC

Incident a1b2c3d4 · duration 15m
```

The MCP hint in the message footer is a pre-filled tool call. Paste it
directly into Claude Code, Cursor, or Windsurf to open the full evidence
pack for that incident — see [MCP clients](../integrations/mcp-clients.md).

## Recurrence resurfacing

When an already-analyzed incident re-fires inside the collapse window, it
doesn't get a new card — it attaches as another occurrence on the same
incident, and the card that's already in the channel is what carries the
update. Recurrence never adds channel messages: everything below happens on
the existing card or inside its thread. What lands depends on what changed:

- **A plain re-fire** — same symptom, same severity, steady cadence — just
  bumps the occurrence count on the existing card in place
  (`🔁 recurred ×N · last HH:MM`). No new message anywhere.
- **A real-world change** — severity escalated, a new symptom (alertname)
  joined, or the cadence sped up markedly — posts a thread reply naming
  exactly why (`why: severity` / `why: new_alertname` / `why: cadence`), and
  the incident is re-analyzed with the fresh finding edited into the same
  card — never a new one.
- **A steady flapper** that never trips one of those changes still gets a
  thread reply at milestone counts — ×5, ×10, ×25, ×50, ×100, then every
  ×100 — so a long-running recurring incident keeps a visible trail in its
  thread even without a qualifying change.

Every recurrence reply states the reason, e.g.:

```text
Incident a1b2c3d4 · recurred ×9 · last 14:52 UTC · why: cadence
```

Two backstop triggers — a hard occurrence cap and a periodic re-analysis
ceiling — force a fresh re-analysis without representing a genuine escalation,
so they edit the card but never post a reply; they stay silent by design.

Control this with `notify.slack.recurrence_mode`:

```yaml
notify:
  slack:
    recurrence_mode: change-gated   # change-gated (default) | off
```

- `change-gated` (default) — post a thread reply on a real-world change or a
  milestone, as described above.
- `off` — recurrence never posts replies; the card's occurrence count still
  updates in place, silently.

Drill incidents (`alertint drill`) keep their 🧪 DRILL banner on every
recurrence surface — card edit, thread reply, and fallback text — same as
every other rendered surface.
