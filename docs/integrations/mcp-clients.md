---
title: "MCP clients"
description: "Query AlertINT findings from Claude Code, Codex, and other MCP clients."
section: "Integrations"
order: 5
slug: "mcp-clients"
---

# MCP clients

The [Situation workflow](https://alertint.com/situation-workflow)
shows the lifecycle and investigation handoff visually.

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

### Install the Situation investigation skill

The repository includes a client-side Codex skill that turns a Situation or
Slack card reference into a short, record-backed operator brief. From a
checked-out release, install it for the current user:

```bash
mkdir -p ~/.codex/skills
cp -R client-skills/alertint-situation-investigation ~/.codex/skills/
```

Restart Codex so it discovers the skill, then ask it to investigate an
AlertINT Situation ID, public handle, or Slack card. The skill contains no
token or server address; it uses the `alertint` MCP connection configured
above. Remove `~/.codex/skills/alertint-situation-investigation` to uninstall
it. Install the skill from the same AlertINT release as the server when
upgrading so its workflow and tool names stay aligned.

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
| `alertint_usage_stats` | Summarize alert intake, LLM tokens, new Slack Situation cards, withheld channel pokes, completed analyses, and triage exhaustion over a time window. |
| `alertint_list_situations` | List durable Situations — the exact-group lineage that durably owns one or more Incidents — most recently updated first. A bounded summary: lifecycle/attention/scheduling fields and due reasons only, no Assessment or controller detail (use `alertint_get_situation` for that) and no Slack presence. |
| `alertint_get_situation` | Get one Situation by id or public handle, including controller state, current `input_version`, `judgment_version`, and `active_judgment`. Expired, withdrawn, invalidated, urgent, or terminal judgments return `active_judgment: null` with their typed `judgment_applicability`; immutable history remains available separately. Also carries the current Episode summary, Slack delivery state, and post-closure artifacts. |
| `alertint_list_situation_transitions` | Page one Situation's immutable Transition journal, oldest first. Each Transition is one authoritative material change: lifecycle/attention, operator contract, transition reason, journal kind and bounded journal entry, evidence references, actor, and drill marker. History is never reconstructed from current state — a Situation with no Transition yet returns an empty array. Page with the returned `next_cursor`, a stable `(sequence, id)` position rather than an offset. |
| `alertint_record_situation_expected` | Mark the current non-critical condition in one open Situation expected until a future RFC3339 deadline. Requires explicit confirmation, asserted operator, request identity, and the current Situation and judgment versions. Coverage is derived by the server from current facts. |
| `alertint_replace_situation_expected` | Replace the current expectedness revision with fresh coverage and a future deadline. Uses the same confirmation, idempotency, and optimistic-version fields as record. |
| `alertint_revoke_situation_expected` | Withdraw current expectedness. Monitoring and lifecycle continue; normal assessment resumes. |
| `alertint_restore_situation_expected` | Explicitly restore a withdrawn judgment against fresh current facts and a new future deadline. It never silently revives an older revision. |
| `alertint_list_situation_judgments` | Page one Situation's immutable judgment revision history, oldest first. Continue with the returned `next_cursor.revision` as `cursor_revision`. Historical rows are not current authority; use `alertint_get_situation` for that. |
| `alertint_expected_behavior_prepare` | Prepare fresh exact Zabbix or Alertmanager current-state proof for proposed required, allowed, and forbidden bindings. Preparation creates no authority. |
| `alertint_get_expected_behavior_validation` | Read one prepared binding-validation request and its current pending, ready, stale, or unavailable result. |
| `alertint_expected_behavior_confirm` | Promote one explicitly confirmed Situation judgment into a reusable expected schedule. Requires exact source scope/version, a bounded schedule and duration, review date, current Situation version, and optional prepared binding proof. |
| `alertint_expected_behavior_replace` | Replace an existing reusable expected schedule under an optimistic envelope-version check. |
| `alertint_expected_behavior_revoke` | Withdraw a reusable expected schedule. Monitoring and source-owned recovery continue. |
| `alertint_expected_behavior_restore` | Restore a withdrawn schedule as a new, freshly proven revision; it does not silently revive old authority. |
| `alertint_get_expected_behavior` | Read one schedule's current active, withdrawn, or invalidated head. |
| `alertint_list_expected_behaviors` | List current schedule heads, optionally filtered by exact group, source installation, rule, and active state. |
| `alertint_list_expected_behavior_history` | Page one schedule's immutable operator revision history oldest first. |
| `alertint_get_delivery_state` | Get the installation-level Situation Slack delivery state: the continuous-failure window, the durable Slack configuration generation and how many effects are blocked on it, the current Delivery-gap generation with its status/age and replay backlog, retries and outcomes by effect class, how many outcomes Slack never confirmed either way, and the stdout Transition-stream backlog. Bounded counts and closed codes only — never a token, a Slack response, or a provider error body. |
| `alertint_list_observation_runs` | Page one Situation's bounded evidence-preparation runs, oldest first: each capability read's immutable result status, coverage, and normalized facts — or an explicit `detail_state: "expired"` once its 10-day unused-detail retention window has passed, never a fabricated or reconstructed value. Page with `next_cursor`. Never returns a raw connector request, provider response, or claim owner/token. |
| `alertint_get_semantic_profile` | Get one or more advisory semantic profiles: current head, a bounded page of immutable version history (newest first — model inferences and operator corrections alike), and the current live inference job state, if any. Pass exactly one of `signature` (from a Situation's evidence references) or a Situation (`id`/`handle`) — a Situation may resolve to more than one distinct signature when its deliveries span sources with different proven identity. Advisory content never asserts source state or bypasses proven identity. |
| `alertint_correct_semantic_profile` | Record an operator-confirmed correction to one advisory semantic profile — always append-only: creates a new immutable version, advances the head, and atomically enqueues its change for fan-out to every matching nonterminal Situation. Requires `signature`, `expected_version` (the current head version; `0` only to create a missing head), a structured `profile`, `confirm: true`, and a non-empty `asserted_by`. A stale `expected_version` is refused, never silently retried — re-read with `alertint_get_semantic_profile` first. A correction never asserts source state, bypasses proven identity, or widens the observation horizon downward. |
| `prometheus_query` | Instant PromQL query against Prometheus. This tool is always registered; a call reports an explicit error when Prometheus is not configured. |
| `prometheus_query_range` | Range PromQL query with auto-stepped resolution. This tool is always registered; discovery alone does not prove configuration or reachability. |
| `loki_query_range` | Range-query the configured log backend using its native query language (requires a log source enabled). |
| `alertint_recent_changes` | List recent deploys/releases/PRs matching a label selector (requires change enrichment enabled). |
| `sentry_issues_list` | List live, distilled Sentry issues for a project (+ optional environment) by status (`unresolved`/`resolved`/`ignored`); requires the Sentry Error source enabled. |
| `sentry_issues_trace` | Return full distilled stacktraces (`file:line`, function, `in_app`) for up to 10 Sentry issue ids; requires the Sentry Error source enabled. |
| `zabbix_metric_history` | Read bounded metric history or trends for an explicit Zabbix host and item key; registered only when the Zabbix API source is configured. |
| `zabbix_host_problems` | List currently open Zabbix problems for an explicit host and optional severity floor; registered only when the Zabbix API source is configured. |
| `alertint_incident_annotate` | Attach a permanent, age-stamped operator note to an incident — context for the next investigator; never affects triage or memory recall. In v0.14 it is also journalled, attributed to the operator, into the owning Situation's Slack thread in the same transaction — as recorded context, never as a change to the assessment, the attention level, or publication authority, and never as proof that anyone touched the operated system. |
| `alertint_incident_capture_verdict` | Capture an operator-confirmed correction or confirmation as a replayable, graded record. A correction steers the next triage of its failure group (tested against live evidence, ruling-gated — never blended in) and demotes the corrected prior from strong recall; a confirmation retires steering. In v0.14 it is separately attributed in the owning Situation's journal and keeps exactly the authority it already had — no more. |

## Explain a Situation from records

Start with current state, then read history. This keeps an agent from using
today's configuration to invent what was true earlier.

```json
alertint_get_situation {"handle":"SIT-2026-0142"}
alertint_list_situation_transitions {"situation_id":"sit-0142"}
alertint_list_observation_runs {"situation_id":"sit-0142"}
alertint_get_delivery_state {}
alertint_list_expected_behavior_history {"envelope_id":"env-nightly-payments"}
```

For the question **“Why did this stop being expected, and why has it not
recovered?”**, a grounded answer should look like this:

> The Situation is currently **Active / Monitoring**. Expected schedule
> `env-nightly-payments` version 3 stopped applying at `2026-09-22T22:41:08Z`.
> Transition `tr-0187` records reason `source_identity_or_version_changed`,
> and observation run `obs-0441` records the newly proven source rule version.
> It has not recovered because alert delivery `del-9921` still records one
> member firing at `2026-09-22T22:42:03Z`; recovery grace therefore has not
> started. Slack delivery is healthy according to the current installation
> delivery state.

The identifiers and times above are illustrative; use the returned records in
the actual answer. Separate these parts explicitly:

- **Current state:** lifecycle, attention, current source state, current
  judgment/schedule applicability, and the recorded next checkpoint.
- **Historical decision:** the immutable transition or schedule-history row
  that states what changed, when, who acted, and the typed reason.
- **Evidence:** the observation or delivery record supporting the conclusion,
  including whether it succeeded, was empty, unavailable, unsupported, stale,
  or expired.
- **Missing history:** say “AlertINT has no recorded transition/schedule
  history for that claim.” Do not reconstruct a past rule version or reason
  from current configuration.

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

The MCP server's initialize response repeats the compact investigation rules,
and `tools/list` marks every tool with read-only, destructive, idempotent and
open-world hints. These annotations help clients present the surface; they are
not an authorization boundary.

Local writes include notes and verdicts, episode expected-until decisions,
reusable expected schedules, their preparation records, and semantic-profile
corrections. Incident notes and verdicts land only in AlertINT's own incident
state; the other writes land in the corresponding AlertINT Situation,
schedule, or semantic-profile state. All remain audit-chained or
revisioned, but still require explicit operator authorization. Each confirmed
write keeps its existing confirmation and optimistic-version checks. Live
Prometheus, log, Sentry and Zabbix reads query their configured external
systems with the scope and time supplied by the caller. Change reads and all
other inspection tools read persisted AlertINT state.

## Connection check and concise investigation output

At first setup, on explicit request, or after a connection failure, verify MCP
initialization, discover tools, and run one bounded state read such as
`alertint_list_situations` with a small limit. Report configured/available,
queried successfully, failed and not checked separately. Logs, changes,
Sentry and Zabbix tools are conditionally registered, so their presence means
the MCP capability is enabled but does not prove reachability. Prometheus
tools are unconditional, so their presence does not prove even configuration.
Do not probe every connector merely to populate a health table.

Default investigation answers to **Finding / Evidence / Now / Next**, followed
by up to three useful numbered read options supported by discovered tools.
**Next** is AlertINT's recorded action and deadline, separate from proposed
operator work. When no Finding is supported, say **Finding: Insufficient
evidence —** and name the specific missing or failed evidence.
