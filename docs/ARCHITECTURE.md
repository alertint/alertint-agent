# Architecture

## High-level data flow

```
Alertmanager
    │  POST /webhook/alertmanager (Bearer token)
    ▼
┌─────────────────────────────────────────────────┐
│  ingress.Receiver                               │
│  • Validates token                              │
│  • Parses Alertmanager v4 payload               │
│  • Deduplicates by fingerprint (SQLite upsert)  │
│  • Calls AlertSink (= correlator.Accept)        │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  correlator.Correlator                          │
│  • Groups alerts by group_key                   │
│    (sorted label values from config)            │
│  • One SQLite incident row per group+window     │
│  • Background ticker flushes expired windows   │
│  • On flush → calls IncidentSink               │
│  • Startup recovery re-arms collecting windows │
└───────────────────┬─────────────────────────────┘
                    │  store.Incident (status=ready)
                    ▼
┌─────────────────────────────────────────────────┐
│  skills/acutetriage.Skill                       │
│  • Loads member alerts from store               │
│  • Builds evidence pack (shared labels,         │
│    timeline, annotations)                       │
│  • Calls LLM (Anthropic Messages API)           │
│  • Validates required JSON keys                 │
│  • Persists output_json, summary, root_cause,   │
│    confidence → incident status=analyzed        │
│  • Sets per-alert role_in_incident              │
│  • Calls Notifier                               │
└───────────────────┬─────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────┐
│  notify.Multi                                   │
│  ├── stdout: one JSON line per finding          │
│  └── slack (optional): Blocks message           │
└─────────────────────────────────────────────────┘

AI agent / MCP client (Claude Code, Cursor, Windsurf, etc.)
    │  HTTP MCP (Streamable): http://host:9912/mcp (Bearer token)
    ▼
┌─────────────────────────────────────────────────┐
│  MCP HTTP server (started inside `serve`)       │
│  • Reads local SQLite alert/incident state      │
│  • Exposes incidents, alerts, evidence packs    │
│  • Verifies audit chain on request              │
│  • Optionally queries Prometheus read-only      │
└─────────────────────────────────────────────────┘

Throughout: audit.Auditor appends hash-chained rows to audit_log.
```

## Key packages

| Package | Role |
|---|---|
| `cmd/alertint` | Binary entrypoint; subcommands `serve`, `health`, `verify-audit`, `version` |
| `internal/config` | YAML config loading, defaults, validation; secrets via env vars |
| `internal/store` | SQLite store (WAL, embedded migrations); alerts, incidents, audit_log |
| `internal/audit` | SHA-256 hash-chained audit log; `Append` + `Verify` |
| `internal/ingress` | HTTP webhook receiver; Alertmanager v4 payload parsing |
| `internal/correlator` | Fixed-window correlator; startup recovery; `IncidentSink` interface |
| `internal/llm/anthropic` | Anthropic Messages API client; retry/backoff; prompt-hash audit |
| `internal/notify` | `Notifier` interface, `Multi` fan-out, stdout + Slack implementations |
| `skills/acutetriage` | End-to-end triage pipeline: evidence pack → LLM → persist → notify |
| `internal/mcp` | HTTP MCP server (`:9912/mcp`, started inside `serve`) exposing read-only incident, alert, evidence, audit, and Prometheus tools |
| `internal/prometheus` | Read-only Prometheus HTTP client used by MCP tools |

## State machine — incident lifecycle

```
collecting  →  ready  →  (skill running)  →  analyzed
                                          →  failed
```

- `collecting`: window is open, alerts arriving
- `ready`: window expired (or `min_alerts` met + window expired), dispatched to skill
- `analyzed`: LLM output persisted
- `failed`: LLM call or persistence error (currently logged; retry on the roadmap)

## Audit log

Every action appends a row:

```
hash = SHA256( ts FS actor FS kind FS canonical_json(payload) FS prev_hash )
```

`FS` = ASCII unit separator `0x1f`. Each row's hash covers the previous row, so any tampering is detectable by `alertint verify-audit`.

## Design constraints

- **No silent config drift** — unknown YAML keys are rejected at load time.
- **No inline secrets** — all secret values come from env vars named by config fields.
- **No 5xx to Alertmanager** — ingress always returns 2xx or 4xx; errors are logged, not propagated upstream.
- **Single binary, SQLite state** — no external dependencies to install.
- **MCP-first investigation** — local context is exposed through an HTTP MCP server on `:9912`; there is no web UI.
