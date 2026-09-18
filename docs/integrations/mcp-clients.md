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
| `alertint_list_situations` | List durable Situations — the exact-group lineage that durably owns one or more Incidents — most recently updated first. A bounded summary: lifecycle/attention/scheduling fields and due reasons only, no Assessment or controller detail (use `alertint_get_situation` for that) and no Slack presence. |
| `alertint_get_situation` | Get one Situation by id or public handle: its immutable member Incidents (each with its current Triage decision/phase/attempts/due time/covered digests), the current authoritative Assessment and derivation, current operator contract, material/Assessment-basis hashes, the eligible Sufficient-reason candidate set (`eligible_reasons`: identity, code, catalog/predicate versions, evidence references, deterministic-floor flag), up to 20 bounded sanitized recent Assessment attempts, and controller retry/park state. `assessment`/`operator_contract`/the hash fields render as explicit `null`, and `recent_attempts` and `eligible_reasons` as empty arrays, for a Situation the controller has not reconciled at least once yet — never an error, and never a fabricated placeholder. Also carries `episode` — the current Episode summary read coherently with the exact Transition it was folded from (explicit `null` before any Transition exists) — and `slack_delivery`, the Situation's whole Slack presence: whether a root is durably published, where it lives, and every durable delivery obligation's class, status, priority, retry/supersession reason, and delivered coordinates. `artifacts_recorded_after_closure` lists operator annotations and Captured verdicts that reached the Situation after it had already closed — recorded against it, never journaled (a closed episode is immutable), and never lost. |
| `alertint_list_situation_transitions` | Page one Situation's immutable Transition journal, oldest first. Each Transition is one authoritative material change: lifecycle/attention, operator contract, transition reason, journal kind and bounded journal entry, evidence references, actor, and drill marker. History is never reconstructed from current state — a Situation with no Transition yet returns an empty array. Page with the returned `next_cursor`, a stable `(sequence, id)` position rather than an offset. |
| `alertint_get_delivery_state` | Get the installation-level Situation Slack delivery state: the continuous-failure window, the durable Slack configuration generation and how many effects are blocked on it, the current Delivery-gap generation with its status/age and replay backlog, retries and outcomes by effect class, how many outcomes Slack never confirmed either way, and the stdout Transition-stream backlog. Bounded counts and closed codes only — never a token, a Slack response, or a provider error body. |
| `alertint_list_observation_runs` | Page one Situation's bounded evidence-preparation runs, oldest first: each capability read's immutable result status, coverage, and normalized facts — or an explicit `detail_state: "expired"` once its 10-day unused-detail retention window has passed, never a fabricated or reconstructed value. Page with `next_cursor`. Never returns a raw connector request, provider response, or claim owner/token. |
| `alertint_get_semantic_profile` | Get one or more advisory semantic profiles: current head, a bounded page of immutable version history (newest first — model inferences and operator corrections alike), and the current live inference job state, if any. Pass exactly one of `signature` (from a Situation's evidence references) or a Situation (`id`/`handle`) — a Situation may resolve to more than one distinct signature when its deliveries span sources with different proven identity. Advisory content never asserts source state or bypasses proven identity. |
| `alertint_correct_semantic_profile` | Record an operator-confirmed correction to one advisory semantic profile — always append-only: creates a new immutable version, advances the head, and atomically enqueues its change for fan-out to every matching nonterminal Situation. Requires `signature`, `expected_version` (the current head version; `0` only to create a missing head), a structured `profile`, `confirm: true`, and a non-empty `asserted_by`. A stale `expected_version` is refused, never silently retried — re-read with `alertint_get_semantic_profile` first. A correction never asserts source state, bypasses proven identity, or widens the observation horizon downward. |
| `prometheus_query` | Instant PromQL query against the connected Prometheus (requires Prometheus enabled). |
| `prometheus_query_range` | Range PromQL query with auto-stepped resolution (requires Prometheus enabled). |
| `loki_query_range` | Range-query the configured log backend using its native query language (requires a log source enabled). |
| `alertint_recent_changes` | List recent deploys/releases/PRs matching a label selector (requires change enrichment enabled). |
| `sentry_issues_list` | List live, distilled Sentry issues for a project (+ optional environment) by status (`unresolved`/`resolved`/`ignored`); requires the Sentry Error source enabled. |
| `sentry_issues_trace` | Return full distilled stacktraces (`file:line`, function, `in_app`) for up to 10 Sentry issue ids; requires the Sentry Error source enabled. |
| `alertint_incident_annotate` | Attach a permanent, age-stamped operator note to an incident — context for the next investigator; never affects triage or memory recall. On the `state-controller` branch it is also journalled, attributed to the operator, into the owning Situation's Slack thread in the same transaction — as recorded context, never as a change to the assessment, the attention level, or publication authority, and never as proof that anyone touched the operated system. |
| `alertint_incident_capture_verdict` | Capture an operator-confirmed correction or confirmation as a replayable, graded record. A correction steers the next triage of its failure group (tested against live evidence, ruling-gated — never blended in) and demotes the corrected prior from strong recall; a confirmation retires steering. On the `state-controller` branch it is separately attributed in the owning Situation's journal and keeps exactly the authority it already had — no more. |

Both feedback writes land whether or not a Situation currently owns the
incident. With **no current owner** — none was ever assigned, or the owner
had already closed — the write still persists and stays visible through the
incident's own history here and in the audit log, never journalled into a
closed episode and never lost. A closed Situation's
`artifacts_recorded_after_closure` is narrower than that: it holds only the
race where the owner closed *between* the write being accepted and being
applied. A write against a Situation that was already closed when it landed
is visible through the incident's own history and the audit log only. No old
Incident Slack card is resurrected or rewritten in any of these cases.

Read-only toward your systems, always; feedback writes (the last two tools
above) land only in AlertINT's own incident state, additive and
audit-chained. Every other tool reads local **AlertINT** state; the
Prometheus tools additionally issue queries to the configured Prometheus
instance — see [Prometheus](prometheus.md).
