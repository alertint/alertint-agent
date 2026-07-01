---
title: "MCP clients"
description: "Query AlertINT findings from Claude and other MCP clients."
section: "Integrations"
order: 5
slug: "mcp-clients"
---

# MCP clients

**AlertINT** runs a persistent MCP Streamable HTTP server on port 9912,
started inside `alertint serve` when `mcp.enabled: true`. Any MCP-capable
AI agent can connect to it and query incidents, evidence packs, and live
metrics in natural language.

**Endpoint:** `http://<host>:9912/mcp`

**Auth:** Bearer token — the value of `ALERTINT_MCP_TOKEN` (or whichever
env var `mcp.token_env` names in your config).

Copy-paste versions of the configs below also ship in the repo under
`examples/mcp-clients/`.

## Claude Code

Create `.mcp.json` at your project root (or merge into `~/.claude.json`
for global access), then reload with `/mcp`:

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

## Cursor

Merge into `~/.cursor/mcp.json` (create if absent), then restart Cursor
and check **Settings → MCP** to confirm the server is listed:

```json
{
  "mcpServers": {
    "alertint": {
      "url": "http://localhost:9912/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_ALERTINT_MCP_TOKEN"
      }
    }
  }
}
```

## Windsurf

Merge into `~/.codeium/windsurf/mcp_config.json` (create if absent), then
restart Windsurf and check **Settings → MCP Servers**:

```json
{
  "mcpServers": {
    "alertint": {
      "serverUrl": "http://localhost:9912/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_ALERTINT_MCP_TOKEN"
      }
    }
  }
}
```

## Available tools

| Tool | Description |
|---|---|
| `alertint_list_incidents` | List incidents with optional status and limit filters. |
| `alertint_get_incident` | Get full analysis details for one incident by ID. |
| `alertint_search_alerts` | Search raw alerts by label key and value. |
| `alertint_get_evidence_pack` | Get the evidence pack and Prometheus metrics for an incident. |
| `alertint_verify_audit` | Verify the hash-chained audit log and report any tampering. |
| `prometheus_query` | Instant PromQL query against the connected Prometheus (requires Prometheus enabled). |
| `prometheus_query_range` | Range PromQL query with auto-stepped resolution (requires Prometheus enabled). |
| `sentry_issues_list` | List live, distilled Sentry issues for a project (+ optional environment) by status (`unresolved`/`resolved`/`ignored`); requires the Sentry Error source enabled. |
| `sentry_issues_trace` | Return full distilled stacktraces (`file:line`, function, `in_app`) for up to 10 Sentry issue ids; requires the Sentry Error source enabled. |

All tools read local **AlertINT** state; the Prometheus tools additionally
issue queries to the configured Prometheus instance — see
[Prometheus](prometheus.md).
