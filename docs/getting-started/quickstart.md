---
title: "Quickstart"
description: "Install the agent, feed it your alerts, and connect your first MCP client."
section: "Getting started"
order: 1
slug: "quickstart"
---

# Quickstart

This guide takes you from zero to a working setup: you'll get AlertINT
running as a single self-hosted binary (or as a bundled Docker Compose
stack), point Alertmanager at it, and connect your AI agent over the
Model Context Protocol (MCP). At the end, your agent can analyze live
incidents with production context.

## Prerequisites

- Go 1.26+ (binary install) **or** Docker with Compose v2
- An Anthropic API key — create one at <https://console.anthropic.com>
- A reachable Alertmanager instance (or use the bundled Docker Compose stack)
- An MCP client such as Claude Code, Cursor, or Windsurf
- Optional: a reachable Prometheus instance for live metric context

## Option A — Docker Compose

The fastest first run. The bundled stack starts AlertINT together with
Prometheus and Alertmanager, already wired together:

```bash
git clone https://github.com/alertint/alertint-agent
cd alertint-agent
cp .env.example .env
# Edit .env: set ALERTINT_WEBHOOK_TOKEN (any long secret) and ANTHROPIC_API_KEY
docker compose -f docker/docker-compose.yaml --env-file .env up --build
```

With the stack running, skip straight to
[connecting an MCP client](#5-connect-an-mcp-client).

## Option B — Binary install

### 1. Install the binary

AlertINT is distributed as a static Go binary with zero external
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

Copy `config.example.yaml` from the repo root and adjust it:

```bash
cp config.example.yaml config.yaml
```

At minimum, set:

- `alertmanager.webhook_token_env` — name of the env var holding your
  webhook bearer token. There is nothing to obtain anywhere: you make
  this secret up yourself — any long random string works, and the export
  below generates one with `openssl rand -hex 32`. Alertmanager will
  present the same token with every webhook it sends (step 4), and the
  agent rejects requests without it.
- `llm.api_key_env` — name of the env var holding your Anthropic API key

Secrets are never written into the config file — fields ending in `_env`
name the environment variable that holds the value. See
[Configuration](configuration.md) for every option.

Export the secrets before starting:

```bash
export ALERTINT_WEBHOOK_TOKEN="$(openssl rand -hex 32)"
export ANTHROPIC_API_KEY="sk-ant-..."
```

### 3. Start the agent

```bash
alertint serve --config config.yaml
```

You should see:

```text
level=INFO msg="alertint starting" version=... addr=0.0.0.0:9911
```

The agent is now listening for Alertmanager webhooks and building incident
history.

### 4. Point Alertmanager at the agent

Add an `alertint-agent` receiver to your `alertmanager.yml` and route
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

### 5. Connect an MCP client

AlertINT runs a persistent MCP HTTP server on port 9912 (enable it with
`mcp.enabled: true` and set the `ALERTINT_MCP_TOKEN` env var). Open your
preferred MCP-capable tool — Claude Code, Cursor, or Windsurf — and point
it at the endpoint; copy-paste configs are in
[MCP clients](../integrations/mcp-clients.md). Verify connectivity by
asking a specific operational question:

> List recent AlertINT incidents and summarize the most critical one.

## Next steps

- Enable Slack notifications: see [Slack](../notifications/slack.md)
- Enable Prometheus metric enrichment and PromQL tools: see
  [Prometheus](../integrations/prometheus.md)
- Tune incident grouping (`correlator.window_seconds`,
  `correlator.group_labels`): see [Configuration](configuration.md)
- Understand what the agent will and won't do:
  [Scope and limits](../concepts/scope-and-limits.md)
- See how it's built: [Architecture](../concepts/architecture.md)
