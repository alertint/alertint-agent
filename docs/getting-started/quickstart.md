---
title: "Quickstart"
description: "Install the agent, fire a built-in incident drill, and connect your first MCP client."
section: "Getting started"
order: 1
slug: "quickstart"
---

# Quickstart

This guide takes you from zero to a triaged incident: you'll get **AlertINT**
running as a single self-hosted binary (or as a bundled Docker Compose
stack), fire a built-in incident drill to watch the pipeline produce an
AI finding end to end, connect your AI agent over the Model Context
Protocol (MCP), and then point Alertmanager at it for real alerts.

## Prerequisites

- Go 1.26+ (binary install) **or** Docker with Compose v2
- An Anthropic API key — create one at <https://console.anthropic.com>
- An MCP client such as Claude Code, Cursor, or Windsurf
- To go live after the drill (step 6): a reachable Alertmanager instance —
  the drill itself needs nothing beyond the agent
- Recommended: a reachable Prometheus instance — if you run Alertmanager,
  you almost certainly have one, and it is the first evidence source worth
  connecting for live metric context

## Option A — Docker Compose

The fastest first run. The bundled stack starts **AlertINT** together with
Prometheus and Alertmanager, already wired together:

```bash
git clone https://github.com/alertint/alertint-agent
cd alertint-agent
cp .env.example .env
# Edit .env: set ALERTINT_WEBHOOK_TOKEN, ALERTINT_CHANGES_WEBHOOK_TOKEN and
# ALERTINT_MCP_TOKEN (any long secrets), plus ANTHROPIC_API_KEY
docker compose -f docker/docker-compose.yaml --env-file .env up --build
```

With the stack running, skip straight to
[firing a drill](#4-fire-a-drill).

## Option B — Binary install

### 1. Install the binary

**AlertINT** is distributed as a static Go binary with zero external
dependencies:

```bash
go install github.com/alertint/alertint-agent/cmd/alertint@latest
# or download a pre-built binary from the GitHub Releases page
```

Verify the install:

```bash
alertint version
```

### 2. Create the configuration

Copy `config.example.yaml` from the repo root and adjust it — or, if you
installed the binary without cloning the repo, fetch it directly:

```bash
curl -LO https://raw.githubusercontent.com/alertint/alertint-agent/main/config.example.yaml
cp config.example.yaml config.yaml
```

At minimum, set:

- `alertmanager.webhook_token_env` — name of the env var holding your
  webhook bearer token. There is nothing to obtain anywhere: you make
  this secret up yourself — any long random string works, and the export
  below generates one with `openssl rand -hex 32`. Alertmanager will
  present the same token with every webhook it sends (step 6), and the
  agent rejects requests without it.
- `llm.api_key_env` — name of the env var holding your Anthropic API key

Secrets are never written into the config file — fields ending in `_env`
name the environment variable that holds the value. See
[Configuration](configuration.md) for every option.

The example config ships with the change webhook and the MCP server
enabled (both are part of the drill below and of everyday use), so their
tokens are required at startup too. Export the secrets before starting:

```bash
export ALERTINT_WEBHOOK_TOKEN="$(openssl rand -hex 32)"
export ALERTINT_CHANGES_WEBHOOK_TOKEN="$(openssl rand -hex 32)"
export ALERTINT_MCP_TOKEN="$(openssl rand -hex 32)"
export ANTHROPIC_API_KEY="sk-ant-..."
```

Check the config before starting it anywhere (CI-friendly — filesystem
paths meant for another machine are not probed):

```bash
alertint validate config.yaml
```

### 3. Start the agent

```bash
alertint serve --config config.yaml
```

You should see:

```text
level=INFO msg="alertint starting" version=... addr=0.0.0.0:9911
```

The agent is now listening for webhooks and building incident history.

### 4. Fire a drill

With the agent running, one command takes you to "finding ready" — no
Alertmanager and no MCP client needed yet; the drill fires straight at the
agent's own webhook:

```bash
alertint drill --config config.yaml
```

Running the Docker Compose stack instead? The binary lives inside the
agent container:

```bash
docker compose -f docker/docker-compose.yaml exec agent /alertint drill --config /etc/alertint/config.yaml
```

The drill reads the same config file serve reads (no extra flags, no token
pasting), plants a fake deploy on the change webhook, fires a burst of
obviously fictional drill alerts at the production ingress, waits out the
correlation window (`correlator.window_seconds` — lower it for faster
drills), then polls until triage completes and prints the resulting
finding — a causal analysis that names the planted deploy. Add `--resolve`
to close the drill at the end of the run: the same burst is re-sent as
resolved, and the Slack card (if enabled) flips to resolved in place. The synthetic incident is marked end to
end: every drill alert carries the reserved `alertint_drill="true"` label,
the Slack card (if enabled) shows a 🧪 DRILL banner, and the MCP incident
list flags the row with `drill: true`. The whole `alertint_` label prefix
is reserved for AlertINT — don't use it in your own alert labels or
`correlator.group_labels`.

Drill incidents are regular incidents: they enter through the production
webhook, live permanently in the store, and appear in the audit log —
that first entry is your proof the pipeline ran. The drill ends by
printing an MCP handoff command — connect a client next and finish the
loop.

### 5. Connect an MCP client

**AlertINT** runs a persistent MCP HTTP server on port 9912 (enable it with
`mcp.enabled: true` and set the `ALERTINT_MCP_TOKEN` env var). Open your
preferred MCP-capable tool — Claude Code, Cursor, or Windsurf — and point
it at the endpoint; copy-paste configs are in
[MCP clients](../integrations/mcp-clients.md). Verify connectivity with
the command the drill printed:

> investigate incident `<id>` using alertint

or ask a specific operational question:

> List recent AlertINT incidents and summarize the most critical one.

### 6. Point Alertmanager at the agent

The drill proved the pipeline; now feed it real alerts. Add an
`alertint-agent` receiver to your `alertmanager.yml` and route
alerts to it. A complete minimal config ships in the repo as
`examples/alertmanager.yml`; the essential pieces are:

```yaml
route:
  receiver: alertint-agent
  group_by: [alertname, cluster, namespace, service]
  group_wait: 10s
  group_interval: 30s

receivers:
  - name: alertint-agent
    webhook_configs:
      - url: "http://<agent-host>:9911/webhook/alertmanager"
        send_resolved: true
        http_config:
          authorization:
            credentials_file: /etc/alertmanager/alertint_token
```

Reload Alertmanager so it picks up the new receiver. From now on the agent
receives a copy of every alert, deduplicates and correlates alerts into
incidents, and produces an AI finding for each incident. See
[Prometheus](../integrations/prometheus.md) for integration details and
for enabling live metric context.

## Next steps

- Connect Prometheus — the recommended first evidence source; it lifts
  findings past the metadata-only confidence cap on real incidents: see
  [Prometheus](../integrations/prometheus.md)
- Enable Slack notifications: see [Slack](../notifications/slack.md)
- Tune incident grouping (`correlator.window_seconds`,
  `correlator.group_labels`): see [Configuration](configuration.md)
- Understand what the agent will and won't do:
  [Scope and limits](../concepts/scope-and-limits.md)
- See how it's built: [Architecture](../concepts/architecture.md)
