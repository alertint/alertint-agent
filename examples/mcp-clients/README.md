# MCP Client Configuration Examples

AlertINT runs a persistent MCP Streamable HTTP server on port **9912** (configurable via `mcp.addr`).

Endpoint: `http://<host>:9912/mcp`  
Auth: Bearer token — the value of the env var named in `mcp.token_env` (default `ALERTINT_MCP_TOKEN`)

---

## Claude Code

**Project-level** — create or merge `.mcp.json` at your project root:

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

**Global** — merge the same `mcpServers` block into `~/.claude.json`.

After saving, reload with `/mcp` in a Claude Code prompt. Verify with:

```
What alertint tools are available?
```

See [`claude-code.json`](claude-code.json) for the copy-paste file.

---

## Cursor

Merge into `~/.cursor/mcp.json` (create if absent):

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

Restart Cursor and check **Settings → MCP** to confirm the server is listed.

See [`cursor.json`](cursor.json) for the copy-paste file.

---

## Windsurf

Merge into `~/.codeium/windsurf/mcp_config.json` (create if absent):

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

Restart Windsurf and open **Windsurf Settings → MCP Servers** to verify.

See [`windsurf.json`](windsurf.json) for the copy-paste file.

---

## Available tools

| Tool | Description |
|---|---|
| `alertint_list_incidents` | List incidents with optional status/limit filters |
| `alertint_get_incident` | Get full details for one incident by ID |
| `alertint_search_alerts` | Search raw alerts by label key/value |
| `alertint_get_evidence_pack` | Get the evidence pack + metrics for an incident |
| `alertint_verify_audit` | Verify the hash-chained audit log and report any tampering |
| `prometheus_query` | Run an instant PromQL query against the connected Prometheus |
| `prometheus_query_range` | Run a range PromQL query with auto-stepped resolution |

---

## Token rotation

The MCP token is read from the environment at startup. To rotate:

1. Update the env var value (e.g., in your `.env` file or secrets manager)
2. Restart the agent — `alertint serve` picks up the new value
3. Update the `Authorization` header in your MCP client config
