---
title: "Quickstart"
description: "Run the agent, fire a built-in incident drill, and read the finding from your AI agent — in under 15 minutes."
section: "Getting started"
order: 1
slug: "quickstart"
---

# Quickstart

Zero to a triaged incident in under 15 minutes: run **AlertINT**, fire the
built-in incident drill to watch the pipeline produce an AI finding end to
end, then connect your AI agent over MCP. Pointing Alertmanager at it for
real alerts is the last step — the drill needs nothing but the agent.

## Prerequisites

- Docker with Compose v2 **or** Go 1.26+ (for the binary install)
- An LLM: an [Anthropic API key](https://console.anthropic.com), **or** a
  self-hosted OpenAI-compatible endpoint (SGLang, vLLM, Ollama, LM Studio) —
  see [OpenAI-compatible endpoint](../integrations/openai-compatible.md)
- An MCP client such as Claude Code, Cursor, or Windsurf

## 1. Run the agent

### Option A — Docker Compose

The fastest first run: **AlertINT** plus Prometheus and Alertmanager,
already wired together, pulling the released agent image:

```bash
git clone https://github.com/alertint/alertint-agent
cd alertint-agent
cp .env.example .env
# Edit .env: set the three ALERTINT_* tokens (any long random strings —
# openssl rand -hex 32 works) and your LLM API key
docker compose -f docker/docker-compose.yaml --env-file .env up
```

Skip to [fire a drill](#2-fire-a-drill).

### Option B — Binary

```bash
go install github.com/alertint/alertint-agent/cmd/alertint@latest
# or download a pre-built binary from the GitHub Releases page
```

Create `config.yaml`. This minimal config is a safe place to start — every
option you omit has a sensible default:

```yaml
alertmanager:
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN

llm:
  provider: anthropic              # or openai-compatible for self-hosted endpoints
  api_key_env: ANTHROPIC_API_KEY

changes:
  ingress:                         # change webhook — lets the drill plant its fake deploy
    enabled: true
    webhook_token_env: ALERTINT_CHANGES_WEBHOOK_TOKEN
```

Secrets never go in the config file — fields ending in `_env` name the
environment variable that holds the value. Export them and start:

```bash
export ALERTINT_WEBHOOK_TOKEN="$(openssl rand -hex 32)"
export ALERTINT_CHANGES_WEBHOOK_TOKEN="$(openssl rand -hex 32)"
export ALERTINT_MCP_TOKEN="$(openssl rand -hex 32)"
export ANTHROPIC_API_KEY="sk-ant-..."   # skip for an unauthenticated local endpoint

alertint serve --config config.yaml
```

The `ALERTINT_*` tokens are secrets you invent — any long random string
works. Setting `ALERTINT_MCP_TOKEN` is also what turns the MCP server on.

For every option — the fully annotated `config.example.yaml`, self-hosted
LLM settings, `alertint validate` for pre-flight checks — see
[Configuration](configuration.md).

> **Save `ALERTINT_MCP_TOKEN`** in a password manager or your team's secret
> store. The webhook tokens are exchanged machine-to-machine and never seen
> again, but the MCP token is what you and every teammate paste into an MCP
> client (step 3), long after this shell is gone.

## 2. Fire a drill

With the agent running, one command takes you to "finding ready":

```bash
alertint drill --config config.yaml
```

Running Docker Compose instead? The binary lives inside the agent container:

```bash
docker compose -f docker/docker-compose.yaml exec agent /alertint drill --config /etc/alertint/config.yaml
```

The drill plants a fake deploy, fires a burst of clearly fictional alerts at
the production ingress, waits out the correlation window, then prints the
resulting finding — a causal analysis that names the planted deploy. Every
drill alert is marked end to end (`alertint_drill="true"` label, 🧪 DRILL
banner on the Slack card, `drill: true` in the MCP incident list), and the
run ends by printing an MCP handoff command for the next step.

## 3. Connect an MCP client

**AlertINT** serves MCP over HTTP on port 9912; clients authenticate with
`ALERTINT_MCP_TOKEN`. Copy-paste configs for Claude Code, Cursor, and
Windsurf are in [MCP clients](../integrations/mcp-clients.md). Then verify
with the command the drill printed:

> investigate incident `<id>` using alertint

or ask a specific operational question:

> List recent AlertINT incidents and summarize the most critical one.

## 4. Point Alertmanager at the agent

The drill proved the pipeline; now feed it real alerts. Add a receiver to
your `alertmanager.yml` (a complete minimal config ships in the repo as
`examples/alertmanager.yml`):

```yaml
route:
  receiver: alertint-agent
  group_by: [alertname, cluster, namespace, service]

receivers:
  - name: alertint-agent
    webhook_configs:
      - url: "http://<agent-host>:9911/webhook/alertmanager"
        send_resolved: true
        http_config:
          authorization:
            credentials_file: /etc/alertmanager/alertint_token
```

Reload Alertmanager. From now on the agent receives a copy of every alert,
correlates alerts into incidents, and produces an AI finding for each.

## Next steps

- Connect Prometheus — the first evidence source worth adding; it lifts
  findings past the metadata-only confidence cap:
  [Prometheus](../integrations/prometheus.md)
- Run triage on your own hardware:
  [OpenAI-compatible endpoint](../integrations/openai-compatible.md)
- Enable Slack notifications: [Slack](../notifications/slack.md)
- Tune grouping and every other knob: [Configuration](configuration.md)
- Understand what the agent will and won't do:
  [Scope and limits](../concepts/scope-and-limits.md)
