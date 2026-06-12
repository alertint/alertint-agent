---
title: "Slack"
description: "Send AlertINT findings to Slack channels."
section: "Notifications"
order: 1
slug: "slack"
---

# Slack

AlertINT posts structured Block Kit messages to Slack after every
completed incident analysis. When alerts recover, the original message is
updated in-place and a thread reply is posted — one message per incident,
no channel noise.

## Setup — Slack app with bot token

Bot tokens let AlertINT track the message it posted. When an incident
fires, AlertINT posts a rich Block Kit message and records its position in
the channel. When all alerts recover, it updates that message in-place
(🔴 → ✅, a duration field appears) and posts a short resolution note in
the thread.

1. **Create a Slack app.** Go to <https://api.slack.com/apps> and click
   **Create New App → From scratch**. Name it *AlertINT* and select your
   workspace.

2. **Add the `chat:write` scope.** In the left sidebar, click
   **OAuth & Permissions**, scroll to **Bot Token Scopes**, and add
   `chat:write`. That is the only permission AlertINT needs.

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
| Thread — analysis | Posted immediately after the main message: severity, confidence, alert count, and group key in a fields grid. |
| Thread — findings | Bullet list of correlation findings. Only shown when the LLM identified more than one contributing factor. |
| Thread — MCP hint | Pre-filled `alertint_get_incident()` tool call — paste directly into your AI agent to open the full evidence pack. |
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
```

Thread reply (posted immediately):

```text
Analysis details

Severity: HIGH        Confidence: 91%
Alerts: 3             Group: cluster=prod

Correlation findings
• HighCPU (api-2) fired 15 s before HighErrorRate — causal ordering confirmed.
• HighLatency shares the same instance label, indicating single-host origin.

🔍 alertint_get_incident("a1b2c3d4") · alertint_list_incidents
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
