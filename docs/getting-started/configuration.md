---
title: "Configuration"
description: "Complete YAML configuration reference for the AlertINT agent."
section: "Getting started"
order: 2
slug: "configuration"
---

# Configuration

**AlertINT** runs from a single YAML file plus environment-based secrets.
Start from `config.example.yaml` at the repo root.

Secrets are **never** stored inline. Fields named `*_env` hold the
**name** of an environment variable; the value is read at startup.

## Validate before you deploy

`alertint validate <config.yaml>` dry-runs the strict loader — unknown
keys are rejected, every cross-field rule below is checked — and exits
`0`/`1` with actionable errors. Filesystem checks that depend on the
machine you validate on (the SQLite parent-directory write probe, the
local rule-pack directory) are skipped, so a config destined for a pod
(`storage.sqlite_path: /data/alertint.db`) validates cleanly on a laptop
or CI runner. Typical workflow: draft the config from this reference,
`alertint validate` it locally or in CI, then paste it into your
ConfigMap — no CrashLoopBackOff from a typo'd key.

Environment variables are **not** read during validation; secret presence
is checked at serve startup. A working `.env` starting point:

```bash
# Required
ALERTINT_WEBHOOK_TOKEN=<openssl rand -hex 32>          # Alertmanager webhook bearer
ALERTINT_CHANGES_WEBHOOK_TOKEN=<openssl rand -hex 32>  # change webhook bearer
ALERTINT_MCP_TOKEN=<openssl rand -hex 32>              # MCP client bearer
ANTHROPIC_API_KEY=sk-ant-...                           # console.anthropic.com — the one real TODO

# Optional integrations (uncomment what you connect)
# PROMETHEUS_BEARER_TOKEN=...     # https://alertint.com/docs/integrations/prometheus
# SLACK_BOT_TOKEN=xoxb-...        # https://alertint.com/docs/notifications/slack
# LOKI_BEARER_TOKEN=...           # https://alertint.com/docs/integrations/loki
# SENTRY_AUTH_TOKEN=...           # https://alertint.com/docs/integrations/sentry
```

`openssl rand -hex 32` is an example, not a requirement — tokens are
opaque secrets compared byte-for-byte, so any long random string of
printable ASCII works, whatever tool generates it.

Of these, `ALERTINT_MCP_TOKEN` is the one to **save in your team's
secret store or password manager** when you generate it: the webhook
tokens are only ever presented machine-to-machine (Alertmanager, your
CI), but the MCP token is pasted into each teammate's MCP client config
— and needed again every time someone connects a new client, long after
the shell or pod that generated it is gone.

## `receivers`

Settings shared by **every** inbound webhook receiver. The listen address is a
server concern, not a per-receiver one, so all receivers (alertmanager, change,
…) mount on this single address.

| Field | Type | Default | Description |
|---|---|---|---|
| `address` | string | `":9911"` | TCP address the inbound webhook HTTP server binds to (also serves `GET /health`). Required when any receiver is enabled. |

> Renamed from `alertmanager.webhook_addr` (and the `--webhook-addr` flag → `--receivers-addr`). Strict config rejects the old key, so a stale `alertmanager.webhook_addr` fails loud at startup.

## `alertmanager`

The inbound Alertmanager webhook receiver, mounted on `receivers.address`.
Enabled by default — it is the only integration that is. Every integration
section carries an `enabled` flag; when a section is enabled, its required
fields must be set or the agent refuses to start. At least one of
`alertmanager`, `changes.ingress`, or `mcp` must be enabled.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | `true` | Run the Alertmanager webhook receiver |
| `webhook_token_env` | string | — | **Required when enabled.** Env var name holding the webhook bearer token |

The agent returns `401` for any request missing or mismatching the token.

## `changes`

The change-events namespace — receive deploy/config/flag events over a webhook
and feed the ones overlapping an incident's labels into triage. Dual-role:
`ingress` is the write surface (receive), `enrichment` is the read surface
(triage prompt + the `alertint_recent_changes` MCP tool). See the
[change-event integration guide](../integrations/changes.md).

| Field | Type | Default | Description |
|---|---|---|---|
| `ingress.enabled` | bool | `false` | Mount `POST /webhook/change` on `receivers.address` |
| `ingress.webhook_token_env` | string | — | **Required when `ingress.enabled`.** Env var name holding the change webhook bearer token |
| `enrichment.enabled` | bool | auto | Attach recent changes to triage and register the MCP tool. Omitted = **on automatically** when a change source exists (`ingress.enabled` or the Sentry releases poller); set `false` to force off. |
| `enrichment.window_minutes` | int | `120` | Look-back before the first alert when correlating changes (must be `> 0`) |
| `enrichment.max_events` | int | `10` | Cap on ranked changes attached to a prompt (must be `> 0`) |
| `retention_days` | int | `30` | Prune changes older than this; required `> 0` when changes are enabled |

## `storage`

| Field | Type | Default | Description |
|---|---|---|---|
| `sqlite_path` | string | `./alertint-agent.db` | Path to the SQLite database file. The directory must be writable. |

## `llm`

| Field | Type | Default | Description |
|---|---|---|---|
| `provider` | string | `anthropic` | Only `anthropic` is supported today |
| `api_key_env` | string | — | **Required.** Env var name holding the Anthropic API key |
| `model` | string | `claude-sonnet-5` | Anthropic model ID used for incident analysis |
| `max_tokens` | int | `4096` | Output-token ceiling for the triage reply. Raise it if a very large correlated incident truncates (the finding JSON carries one entry per member alert) |

This is the model that triages your incidents and writes the finding
summaries, so every dispatched incident consumes Anthropic API tokens.
The Sonnet default gives the strongest analysis in its price class; set
`model: claude-haiku-4-5` to cut per-incident cost when volume matters
more than finding depth. Keep an eye on your spend in the Anthropic
console — the agent does not yet meter or cap usage (budget tracking is
planned).

`max_tokens` bounds the finding reply. The finding JSON lists every member
alert, so a very large correlated incident can exceed the default and truncate
mid-reply; when that happens the log names it explicitly
(`response truncated at max_tokens=…; raise llm.max_tokens`) so the fix is a
one-line bump. It is a ceiling, not a target — small incidents still emit only
what they need, so raising it costs nothing for normal traffic.

## `correlator`

| Field | Type | Default | Description |
|---|---|---|---|
| `window_seconds` | int | `90` | Alerts sharing the same group key within this window form one incident |
| `min_alerts` | int | `1` | Minimum alerts before the incident is dispatched to the skill. The default `1` triages a lone alert too — use `notify.slack.min_severity` to control channel noise instead of dropping triage. |
| `group_labels` | list | `[cluster, namespace, service]` | Label names used to compute the group key. Two alerts are correlated when all of these labels match. Deliberately excludes `alertname` so related alerts of different types (latency + crash-loop on one service) correlate into one incident; add it only if you want one incident per alert type. The `alertint_` label-key prefix is reserved for AlertINT itself (e.g. the `alertint_drill` drill marker) and is rejected here — reserved labels never participate in grouping. |

`window_seconds` is a tradeoff. A lower value reacts faster, but an
incident may be analyzed with only the first alert or two of a burst
grouped in; a higher value waits to gather more related alerts — more
context for the analysis — at the cost of a slower first finding.

## `memory`

Incident memory stops an unchanged, already-analyzed condition from being
re-triaged as brand new every time it re-fires. When an alert whose group key
matches an already-analyzed incident fires again inside the collapse horizon,
it attaches as a lightweight occurrence — the incident's Slack card edits to
`recurred ×N` — instead of minting a new incident and spending another LLM
call. This is deterministic, free, and always on; there is no enable switch,
only the knobs below.

| Field | Type | Default | Description |
|---|---|---|---|
| `attach_window_minutes` | int | `30` | Clock A. A re-fire within this many minutes of the last occurrence attaches instead of re-triaging. A longer window collapses more aggressively. |
| `judgment_ceiling_hours` | int | `4` | Clock B. A steady flapper that never pauses would slide Clock A forever; once this long has passed since the last analysis, the next re-fire forces a fresh re-judgment (with the accumulated history) even while still collapsing. |
| `occurrence_cap` | int | `100` | Backstop trigger: force a re-judgment after this many occurrences have attached since the last analysis, regardless of the clocks. |
| `lookback_days` | int | `90` | How long occurrence rows are retained and how far back recurrence counts and cadence are computed. Older occurrences are pruned on the correlator's normal flush cycle. |
| `classifier.mode` | string | `off` | Shadow classifier (see below). `off` makes no extra LLM call; `shadow` runs a small fuzzy-match call and records every verdict in the audit log while the recall render stays unchanged; `on` lets a graduated match tag the recall. **Quote the value** — bare `off`/`on` are YAML booleans. |
| `classifier.timeout_seconds` | int | `10` | Seconds-scale timeout for the classifier's own Haiku call. Only used when `mode` is `shadow` or `on`. |

When the exact recurrence key misses but a prior finding is only one group-label
value away (for example the same `cluster`/`namespace` but a different
`service`), the deterministic recall renders it as a weak "one label off" signal.
The optional **shadow classifier** adds a small second Haiku call that judges
whether that weak candidate is really the same underlying condition. It ships
**dark**: at `mode: shadow` the verdict lands only in the audit log
(`memory.classifier_verdict`) and the prompt the model sees is byte-identical to
the deterministic recall. You graduate it to `on` — where a match tags the recall
as "LLM-matched, probably related" — only after your own audit log shows the
call is accurate enough. See [Incident memory](../concepts/incident-memory.md#shadow-classifier)
for the per-call cost and the graduation gate query.

The recurrence key is the verbatim group key with no normalization. If you add
a volatile per-instance label (such as `pod`, `instance`, or `job_name`) to
`correlator.group_labels`, the key rarely repeats, so collapse and recall
seldom match — `alertint validate` and startup emit a warning when they see
one.

## `notify`

| Field | Type | Default | Description |
|---|---|---|---|
| `stdout` | bool | `true` | Deliver the finding to **stdout** as one JSON line. The full JSON is verbose detail: it is written **only at `--log-level=debug`** (consistently, in every format). At `info` the sink is still active — a send is confirmed on the `notified` line — but no JSON is written; the result shows as the one-line `finding` summary instead. Recommended to leave on. |
| `slack.enabled` | bool | `false` | Post a Block Kit message to a Slack channel via the bot-token API (message updated in-place on resolve) |
| `slack.bot_token_env` | string | — | Required when `slack.enabled: true`. Env var name holding the Slack bot token (`xoxb-…`, requires the `chat:write` scope) |
| `slack.channel` | string | — | Required when `slack.enabled: true`. Channel name (e.g. `#alerts`) or ID (e.g. `C1234567890`) |
| `slack.min_severity` | string | `low` | Findings below this severity (`low` \| `medium` \| `high`) are not posted to Slack; stdout always emits. An incident suppressed at firing is also suppressed at resolution. The default posts everything. |
| `slack.recurrence_mode` | string | `change-gated` | How a recurring incident resurfaces in its thread: `change-gated` posts a thread reply only on a real-world change (severity rise, new symptom, faster cadence) or a milestone (×5/×10/×25/×50/×100, then every ×100) — replies stay in the thread, nothing extra is sent to the channel; `off` keeps recurrence to a silent card count-bump. See [Slack](../notifications/slack.md) for details. |

At startup the agent logs one `notifiers ready` line listing the active sinks
(and the Slack channel) so you can see where findings will go. Every analysis
then logs, at INFO regardless of format:

- one human-readable `finding` summary (severity, confidence, alert count,
  incident id, analysis name) — the live-watch view of the result; and
- one `notified` line confirming delivery per sink (`notified · stdout=ok
  slack=ok …`), so a send — or a sink-specific failure — is never silent.

The full JSON finding (`notify.stdout`, above) is the verbose machine
representation, reserved for `--log-level=debug`.

See [Slack](../notifications/slack.md) for the full setup walkthrough.

## `mcp`

When enabled, `alertint serve` starts a second HTTP listener — a
Streamable HTTP MCP server — that AI coding agents (Claude Code, Cursor,
Windsurf) connect to for incident, alert, evidence, audit, and Prometheus
tools. Enablement is presence-based: setting the bearer-token env var
(`ALERTINT_MCP_TOKEN` by default) turns the server on; an explicit
`enabled: false` forces it off.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | auto | Omitted = on when the env var named by `token_env` holds a token (presence-based); set `false` to force off |
| `addr` | string | `"0.0.0.0:9912"` | TCP address the MCP server binds to. Endpoint is `http://host:9912/mcp` |
| `token_env` | string | `ALERTINT_MCP_TOKEN` | Env var name holding the MCP bearer token |

Clients authenticate with `Authorization: Bearer <token>`. Keep the
token value retrievable (secret store or password manager) — every
current and future MCP client needs it, so treat it as a shared team
credential rather than a set-and-forget deployment secret. Lost it?
Set a new value and restart the agent; existing clients must be
updated to match. See
[MCP clients](../integrations/mcp-clients.md) for copy-paste client
configs.

## `prometheus`

Optional read connector. When enabled it adds live metric values to LLM
triage prompts and exposes PromQL tools over MCP. Enablement is
presence-based: setting `base_url` turns the connector on; an explicit
`enabled: false` forces it off. See
[Prometheus](../integrations/prometheus.md) for details.

| Field | Type | Default | Description |
|---|---|---|---|
| `enabled` | bool | auto | Omitted = on when `base_url` is set (presence-based); set `false` to force off |
| `base_url` | string | — | Prometheus HTTP API base URL, e.g. `http://localhost:9090` |
| `bearer_token_env` | string | — | Optional env var name holding a bearer token for Prometheus |
| `timeout_seconds` | int | `10` | Total budget for one incident's metric enrichment fetch. Shared across every scope queried, each of which gets an equal slice so a slow query cannot starve the rest |
| `default_range_minutes` | int | `60` | Default lookback window for range queries |
| `max_series` | int | `1000` | Server-side cap on the number of series each enrichment query may return, bounding the payload a broad selector pulls during an alert storm |

`max_series` keeps metric enrichment from self-inflicting timeouts during a
storm: a bare `{instance="…"}` selector can otherwise pull every series for a
node. During a large multi-alert incident the enrichment also caps how many
per-instance queries it fires and splits `timeout_seconds` into a per-query
budget, so a backend that is merely slow is reported as `degraded` (metrics
slow) rather than falsely as `unreachable`, and does not lower the finding's
confidence.

Set `bearer_token_env` only when your Prometheus requires authentication
— for example, when it sits behind an auth proxy or ingress that expects
an `Authorization: Bearer <token>` header. Name the env var that holds
that token and export it before starting the agent. A plain,
unauthenticated Prometheus needs only `base_url`.

## `rules`

The embedded baseline rule pack always loads. `local_pack_dir` optionally
adds one local pack directory whose rules and templates override baseline
entries with the same id or name. The directory must follow the standard
pack layout (`pack.yaml`, `rules/*.yaml`, `templates/*.md`); see
`examples/rules/` in the repo for a working starter pack.

| Field | Type | Default | Description |
|---|---|---|---|
| `local_pack_dir` | string | — | Optional path to a local rule pack directory. Must exist and contain `pack.yaml`. |

## `log_level`

One of `debug`, `info`, `warn`, `error`. Default: `info`.

## `log_format`

How log records are rendered. One of `auto`, `console`, `json`. Default:
`auto`.

| Value | Behavior |
|---|---|
| `auto` | Resolves to `console` when the log stream (stderr) is a terminal, `json` otherwise — so an interactive run is readable while a container or pipe stays machine-parseable. |
| `console` | One human-readable, colored line per record (`HH:MM:SS LEVEL message · key=value …`). Color is emitted only on a TTY with `NO_COLOR` unset; redirected to a file it is plain text. |
| `json` | One compact JSON object per record, for log shipping and aggregation. The stdout JSON finding line is unaffected by this setting. |

> The legacy `text` format (slog's raw `key=value`) was **removed**. It is not
> aliased — setting `log_format: text` fails loudly at startup rather than
> silently re-rendering as `console` and breaking a `key=value` parser.

Resolution keys off **stderr** (the log stream), not stdout, so a redirect
like `alertint serve > out.txt` still shows the colored action trail on your
terminal. To capture findings as machine-readable JSON for piping, run with
`--log-level=debug` — see [`notify.stdout`](#notify). At `info` (any format) the
finding appears as a one-line summary in the trail plus a `notified` line.

When the colored console stream is captured and replayed to a terminal — e.g.
`docker logs` / `docker compose logs`, where the container's stderr is not a
TTY — set `CLICOLOR_FORCE=1` in the environment to force color on anyway.
`NO_COLOR` still overrides it.

### Level × format

The two axes are orthogonal — level controls *how much* is logged, format
controls *how it is rendered*:

| | `console` | `json` |
|---|---|---|
| `info` (default) | clean one-line action trail — the live-watch view | compact JSON for shipping |
| `debug` | action trail plus extra detail lines | full verbose JSON for troubleshooting |

### Precedence and overrides

The `--log-level` and `--log-format` CLI flags override the config values,
which override the built-in defaults (`info` / `auto`):

```text
CLI flag  >  config (log_level / log_format)  >  built-in default
```

An unset flag (the default) falls through to config, so the flags are for
one-off overrides — e.g. `alertint serve --config alertint.yaml --log-format json`.

## Full example

```yaml
receivers:
  address: "0.0.0.0:9911"

alertmanager:
  enabled: true
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN

storage:
  sqlite_path: /var/lib/alertint/alertint.db

llm:
  provider: anthropic
  api_key_env: ANTHROPIC_API_KEY
  model: claude-sonnet-5

correlator:
  window_seconds: 90
  min_alerts: 1
  group_labels:
    - cluster
    - namespace
    - service

notify:
  stdout: true
  slack:
    enabled: true
    bot_token_env: SLACK_BOT_TOKEN
    channel: "#alerts"

mcp:
  # on automatically when ALERTINT_MCP_TOKEN is set
  addr: "0.0.0.0:9912"
  token_env: ALERTINT_MCP_TOKEN

rules:
  local_pack_dir: /etc/alertint/rules

prometheus:
  enabled: true
  base_url: http://localhost:9090
  bearer_token_env: PROMETHEUS_BEARER_TOKEN
  timeout_seconds: 10
  default_range_minutes: 60
  max_series: 1000

log_level: info
log_format: auto
```

## Integration health

At startup the agent probes every **enabled** integration (Prometheus via
a trivial instant query, Slack via `auth.test`) and logs one line per
integration:

```text
15:04:05 INFO  integration health: OK · integration=prometheus detail=http://prometheus:9090
15:04:05 WARN  integration health: FAILED · integration=slack detail=#alerts err=invalid_auth
```

(shown in the default `console` format; with `log_format: json` the same
records render as one JSON object per line.)

`GET /health` includes the same statuses (cached for 60 s). The top-level
`status` field reflects only agent liveness — a failing integration is
informational and never makes an orchestrator restart the agent:

```json
{"status":"ok","integrations":[{"name":"prometheus","detail":"http://prometheus:9090","ok":true,"checked_at":"..."}]}
```
