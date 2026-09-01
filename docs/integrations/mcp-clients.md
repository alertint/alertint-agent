---
title: "MCP clients"
description: "Query AlertINT findings from Claude Code, Codex, and other MCP clients."
section: "Integrations"
order: 5
slug: "mcp-clients"
---

# MCP clients

**AlertINT** runs a persistent MCP Streamable HTTP server on port 9912,
started inside `alertint serve` whenever the `ALERTINT_MCP_TOKEN` env var
is set (presence-based; `mcp.enabled: false` forces it off). Any MCP-capable
AI agent can connect to it and query incidents, evidence packs, and live
metrics in natural language.

**Endpoint:** `http://<host>:9912/mcp`

**Auth:** Bearer token — the value of `ALERTINT_MCP_TOKEN` (or whichever
env var `mcp.token_env` names in your config). The token is an opaque
secret — the agent compares it byte-for-byte, so any long random string
of printable ASCII works; `openssl rand -hex 32` in the docs is just
one way to generate one. This is a shared team
credential: every client below presents the same value, so store it
where teammates can retrieve it (a password manager or secret store) —
not only in the deployment that set it. In a Kubernetes setup, read it
back from the Secret if it wasn't saved at creation time
(`kubectl get secret <name> -o jsonpath='{.data.ALERTINT_MCP_TOKEN}' | base64 -d`).
If the value is lost entirely, set a new one and restart the agent,
then update every connected client.

Copy-paste versions of the configs below also ship in the repo under
`examples/mcp-clients/`.

## Claude Code

Export the token, then add **AlertINT** from the shell. `--scope user` makes it
available in every project; use `--scope local` to keep it private to the
current project instead:

```bash
export ALERTINT_MCP_TOKEN="<your-token>"
claude mcp add --transport http --scope user alertint http://localhost:9912/mcp --header "Authorization: Bearer ${ALERTINT_MCP_TOKEN}"
```

Alternatively, create `.mcp.json` at your project root (or merge into
`~/.claude.json` for global access), then reload with `/mcp`:

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

## Codex

Export the token in the environment from which you start Codex, then add the
Streamable HTTP server. Codex stores the environment-variable name, not the
token itself, in its shared MCP configuration:

```bash
export ALERTINT_MCP_TOKEN="<your-token>"
codex mcp add alertint --url http://localhost:9912/mcp --bearer-token-env-var ALERTINT_MCP_TOKEN
```

Run `codex mcp get alertint` to inspect the saved entry or `codex mcp list` to
list all configured servers. The Codex CLI, IDE extension, and desktop app use
the same MCP configuration.

Alternatively, merge this into `~/.codex/config.toml` for global access, or
`.codex/config.toml` in a trusted project for project-only access:

```toml
[mcp_servers.alertint]
url = "http://localhost:9912/mcp"
bearer_token_env_var = "ALERTINT_MCP_TOKEN"
```

The token itself still belongs in the `ALERTINT_MCP_TOKEN` environment
variable; do not put its value in `config.toml`.

For a hosted **AlertINT** instance, replace `http://localhost:9912/mcp` in the
command or configuration with its HTTPS MCP endpoint.

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
| `alertint_get_incident` | Get full analysis details for one incident by ID, including `operator_history` — the group's governing verdict and age-stamped notes, visible from any incident on the group key. |
| `alertint_search_alerts` | Search raw alerts by label key and value. |
| `alertint_get_evidence_pack` | Get the evidence pack and Prometheus metrics for an incident. |
| `alertint_verify_audit` | Verify the hash-chained audit log and report any tampering. |
| `alertint_list_situations` | List durable Situations — the exact-group lineage that durably owns one or more Incidents — most recently updated first. Foundation state only: no controller Assessment or operator contract exists yet. |
| `alertint_get_situation` | Get one Situation by id or public handle, with its member Incidents. `assessment` and `operator_contract` are always `null` — there is no Situation controller yet to produce either. |
| `prometheus_query` | Instant PromQL query against the connected Prometheus (requires Prometheus enabled). |
| `prometheus_query_range` | Range PromQL query with auto-stepped resolution (requires Prometheus enabled). |
| `loki_query_range` | Range-query the configured log backend using its native query language (requires a log source enabled). |
| `alertint_recent_changes` | List recent deploys/releases/PRs matching a label selector (requires change enrichment enabled). |
| `sentry_issues_list` | List live, distilled Sentry issues for a project (+ optional environment) by status (`unresolved`/`resolved`/`ignored`); requires the Sentry Error source enabled. |
| `sentry_issues_trace` | Return full distilled stacktraces (`file:line`, function, `in_app`) for up to 10 Sentry issue ids; requires the Sentry Error source enabled. |
| `alertint_incident_annotate` | Attach a permanent, age-stamped operator note to an incident — context for the next investigator; never affects triage or memory recall. |
| `alertint_incident_capture_verdict` | Capture an operator-confirmed correction or confirmation as a replayable, graded record. A correction steers the next triage of its failure group (tested against live evidence, ruling-gated — never blended in) and demotes the corrected prior from strong recall; a confirmation retires steering. |

Read-only toward your systems, always; feedback writes (the last two tools
above) land only in AlertINT's own incident state, additive and
audit-chained. Every other tool reads local **AlertINT** state; the
Prometheus tools additionally issue queries to the configured Prometheus
instance — see [Prometheus](prometheus.md).
