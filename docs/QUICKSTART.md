# AlertINT Agent — Quickstart

Get from zero to a real LLM finding in under 10 minutes.

## Prerequisites

| Requirement | Notes |
|---|---|
| Go 1.26+ **or** Docker with Compose v2 | Binary install needs Go; Docker path needs neither |
| Anthropic API key | [console.anthropic.com](https://console.anthropic.com) → API Keys |
| Alertmanager reachable | Existing instance or the bundled Docker Compose stack |
| MCP client | Connect Claude Code, Cursor, or Windsurf to AlertINT's HTTP MCP endpoint (`:9912/mcp`) |
| Prometheus reachable (optional) | Used by read-only MCP tools for deeper metric context |

---

## Option A — Docker Compose (recommended for first run)

```bash
git clone https://github.com/alertint/alertint-agent
cd alertint-agent
cp .env.example .env
# Edit .env: set ALERTINT_WEBHOOK_TOKEN (any long secret) and ANTHROPIC_API_KEY
docker compose -f docker/docker-compose.yaml --env-file .env up --build
```

Skip to [Step 5 — Send a test alert](#step-5--send-a-test-alert).

---

## Option B — Binary install

### Step 1 — Install

```bash
go install github.com/alertint/alertint-agent/cmd/alertint@latest
# or download a pre-built binary from the GitHub Releases page
```

Verify:

```bash
alertint version
```

### Step 2 — Create config

```bash
cp config.example.yaml config.yaml
```

Open `config.yaml` and set at minimum:

- `alertmanager.webhook_token_env` — name of the env var that holds your bearer token
- `llm.api_key_env` — name of the env var that holds your Anthropic API key

### Step 3 — Set secrets in env

```bash
export ALERTINT_WEBHOOK_TOKEN="$(openssl rand -hex 32)"
export ANTHROPIC_API_KEY="sk-ant-..."
```

### Step 4 — Start the agent

```bash
alertint serve --config config.yaml
```

You should see:

```
level=INFO msg="alertint starting" version=... addr=0.0.0.0:9911
```

---

## Step 5 — Hook up Alertmanager

Add this receiver block to your `alertmanager.yml` (or create a new one):

```yaml
receivers:
  - name: alertint-agent
    webhook_configs:
      - url: "http://<agent-host>:9911/webhook/alertmanager"
        send_resolved: true
        http_config:
          authorization:
            credentials: "<your ALERTINT_WEBHOOK_TOKEN value>"
```

And set the route:

```yaml
route:
  receiver: alertint-agent
  group_by: [alertname, cluster, namespace, service]
  group_wait: 10s
  group_interval: 30s
```

Reload Alertmanager so it picks up the new receiver (`kill -HUP <pid>`, or restart the service).

---

## Step 6 — Send a test alert

You don't need Alertmanager (or any extra tooling) to see a finding — POST an
Alertmanager-style payload straight to the agent's webhook with your bearer token:

```bash
curl -sS -X POST http://localhost:9911/webhook/alertmanager \
  -H "Authorization: Bearer $ALERTINT_WEBHOOK_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "version": "4",
    "status": "firing",
    "alerts": [
      {
        "status": "firing",
        "labels": {"alertname":"DiskFull","cluster":"local","namespace":"default","service":"api","severity":"critical"},
        "annotations": {"summary":"Disk at 95% on web1"},
        "startsAt": "'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'"
      }
    ]
  }'
```

The agent returns `204 No Content` on success. Wait up to `window_seconds` (default 90 s); the agent then logs and emits one JSON finding line to stdout:

```json
{
  "ts": "2026-01-01T12:01:30Z",
  "kind": "finding",
  "finding": {
    "incident_id": "...",
    "analysis_name": "DiskFull on api",
    "overall_issue": "Disk utilisation reached 95% ...",
    "confidence": 0.87,
    ...
  }
}
```

---

## Step 7 — Connect an MCP client

AlertINT runs a persistent MCP HTTP server on port **9912**. Any MCP-capable AI coding agent can connect to it and query incidents in natural language.

**Endpoint:** `http://localhost:9912/mcp`  
**Auth:** Bearer token — the value of `ALERTINT_MCP_TOKEN` (or whichever env var `mcp.token_env` names)

**Claude Code** — create `.mcp.json` at your project root (or merge into `~/.claude.json` for global access):

```json
{
  "mcpServers": {
    "alertint": {
      "type": "http",
      "url": "http://localhost:9912/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_ALERTINT_MCP_TOKEN"
      }
    }
  }
}
```

After saving, reload with `/mcp` in a Claude Code prompt. Try:

```
What incidents has AlertINT seen? Show me the evidence pack for the latest one.
```

For Cursor and Windsurf configs, see [`examples/mcp-clients/README.md`](../examples/mcp-clients/README.md).

---

## Next steps

- Enable Slack: set `notify.slack.enabled: true`, `slack.bot_token_env: SLACK_BOT_TOKEN`, and `slack.channel: "#alerts"`
- Connect an MCP client: see [`examples/mcp-clients/`](../examples/mcp-clients/) for Claude Code, Cursor, and Windsurf configs
- Enable Prometheus enrichment: set `prometheus.enabled: true` and `prometheus.base_url` for live metric context in triage
- Try the Prometheus MCP tools without a real metrics source: the Docker demo stack bundles a Pushgateway, and `docker/push-synthetic-metrics.sh` seeds sample metrics you can query (optional, local-demo only)
- Tune the correlator window: `correlator.window_seconds`
- Review the full configuration reference: [CONFIGURATION.md](CONFIGURATION.md)
- Understand what the agent will and won't do: [LIMITS.md](LIMITS.md)
- See how it's built: [ARCHITECTURE.md](ARCHITECTURE.md)
