# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.8.3] - 2026-07-16

### Added

- Triage prompt caching: when verification is enabled, the draft call marks
  the shared prefix (system prompt + evidence pack) as an Anthropic
  prompt-cache breakpoint and the re-judge call reads it seconds later at
  ~0.10× input price — roughly a 40% input-cost cut on a typical verified
  incident with the default model. `llm.response` audit rows now carry
  `cache_creation_input_tokens` / `cache_read_input_tokens`, and a warning is
  logged when the re-judge call read no cached prefix (model floor not met, or
  prefix drift). With verification disabled, requests are byte-identical to
  before and nothing is cached.

### Fixed

- Triage verification no longer lowers a finding's confidence over empty
  contrast-query results unless the query reused metric names and label keys
  confirmed present in the evidence; the verification-plan prompt now steers
  the model toward single-metric queries and away from cross-metric label
  joins that return empty regardless of ground truth.
- Evidence-pack metric snapshots: comparator series (those sharing only the
  incident's node/instance) are now ranked largest-value-first within each
  metric family and capped at 3 per family, so the LLM sees a true top-N of
  neighboring producers instead of an alphabetical slice; the incident's own
  member series are never capped.

## [0.8.2] - 2026-07-16

### Fixed

- Storm-sized incidents no longer fail triage with `llm: response truncated at max_tokens`:
  prompts now itemize at most the 20 most significant alerts (omitted members are recorded
  with the `correlated` role deterministically) and cap finding prose, so the response's
  output-token size stays flat at any incident size. `llm.max_tokens` is unchanged.

## [0.8.1] - 2026-07-15

### Fixed

- Model-proposed verification queries were silently dropped when the model
  emitted the `verification` key as a bare query list instead of the
  `{"queries": [...]}` envelope — the plan parser rejected the whole block and
  every such round fell back to floor-only checks (observed on
  `claude-haiku-4-5` immediately after 0.8.0 went live). The prompt now spells
  out the exact envelope shape and the parser accepts both shapes, so targeted
  disprove-queries — including the mandatory ones behind the scope-inflation
  guard — actually run.

## [0.8.0] - 2026-07-14

### Added

- Verification round: triage now falsifies its own draft verdict before persisting —
  a deterministic floor (peer-scope up ratio + cross-incident scan) plus up to 4
  model-chosen read-only checks run on every judged incident, and a second LLM pass
  revises the verdict against the results. Degraded rounds mark the finding
  "unverified" and can never raise confidence. Config: `triage.verification`
  (default on; `enabled: false` restores single-call triage).

## [0.7.5] - 2026-07-13

### Changed

- **Slack recurrence updates no longer post to the channel.** The recurrence
  resurfacing messages introduced in 0.7.4 (real-world-change "why" and
  milestone nudges) used Slack's "also send to channel" on their thread
  replies, so every resurface also landed as a new channel message — too
  noisy in practice. These messages now post as plain thread replies only;
  the in-place card count edit is unchanged. `notify.slack.recurrence_mode`
  keeps its meaning (`change-gated` gates the thread replies, `off` silences
  them).

## [0.7.4] - 2026-07-13

### Added

- Change-gated recurrence visibility in Slack: a recurring incident resurfaces in
  the channel only when a re-fire is a real-world change (severity rise, a new
  symptom, or accelerating cadence) or crosses a milestone (×5/×10/×25/×50/×100,
  then every ×100), each stating why it resurfaced. Plain re-fires stay silent —
  the card's occurrence count edits in place. An escalation now edits the
  incident's existing card instead of posting a new one, so the whole recurrence
  reads as one thread. New `notify.slack.recurrence_mode: change-gated | off`.

## [0.7.3] - 2026-07-10

### Fixed

- **Metric enrichment no longer self-inflicts "Prometheus unreachable" during
  alert storms.** A broad `{instance="…"}` selector pulled every series for a
  node, and all of an incident's scopes shared one query deadline, so under storm
  load the later queries timed out — falsely reporting a healthy backend as
  unreachable and capping the finding's confidence. Each enrichment query is now
  bounded server-side (`prometheus.max_series`, default 1000), the per-instance
  queries are capped, and the fetch deadline is split per query so one slow query
  can no longer starve the rest. A backend that is merely slow is reported as
  `degraded` (metrics slow) rather than `unreachable`, and no longer lowers the
  finding's confidence.

## [0.7.2] - 2026-07-10

### Fixed

- **Large incidents no longer fail triage with a truncated reply.** The triage
  output ceiling was hardwired to 1024 tokens; a large correlated incident (whose
  finding JSON carries one entry per member alert) could exhaust it mid-reply,
  failing the whole analysis with a misleading `not valid JSON` error and leaving
  the prior finding standing on every re-judgment. The ceiling is now a
  configurable `llm.max_tokens` (default 4096), and a reply cut off at the ceiling
  is reported as an actionable `response truncated at max_tokens=…; raise
  llm.max_tokens` instead of a JSON parse error.

## [0.7.1] - 2026-07-10

### Added

- **Kubernetes metric enrichment**: Prometheus metric enrichment now scopes series
  by the generic label selector (namespace/pod/container/…), so Kubernetes-style
  alerts get live metrics instead of an annotations-only confidence cap (#24).
- **Evidence line on every finding**: notifications now carry a per-source evidence
  summary (e.g. `Prometheus 21 metrics · Loki 0 lines · Changes 2 · Sentry
  unreachable`), distinguishing an unreachable connector from a genuine zero, with
  explicit `skipped (known issue)` and `no sources configured` states.

## [0.7.0] - 2026-07-10

### Added

- **Recurrence collapse** — a re-firing alert whose group key matches an
  already-analyzed incident now attaches to it as an *occurrence* instead of
  minting a new incident and spending another LLM call. The incident's Slack
  card edits in place to `recurred ×N · last HH:MM` (throttled to one edit per
  minute) and one JSON occurrence line is written to stdout; the analysis is
  only re-run when an escalation trigger fires — a severity rise, a new alert
  type joining, a cadence spike, or a hard time/occurrence ceiling — and the
  fresh finding replaces the old one in place. Deterministic, free, and on by
  default; tune it under the new `memory:` config block
  (`attach_window_minutes`, `judgment_ceiling_hours`, `occurrence_cap`,
  `lookback_days`). MCP incident payloads now carry an `occurrences` count, and
  running `alertint drill` twice inside the window demonstrates the collapse.
- **Memory recall** — when a new incident matches a past analysis for the same
  key, the prior findings are injected into the new analysis as a `memory`
  enrichment section, so the model triages with "we have seen this before" in
  hand: the recurrence count and cadence as computed facts, and each prior root
  cause framed as an unconfirmed hypothesis. Recalled findings never count as
  live evidence, so an evidence-free re-fire stays under the metadata-only
  confidence cap regardless of the prior's confidence. The model returns a
  `confirms`/`refutes`/`silent` verdict on the recalled cause; a cause refuted
  twice is demoted so a newer finding displaces it. When a recalled finding
  points at an application error, one bounded status check renders the transition
  (`resolved → now firing = likely regression`, `ignored = known-tolerated`). MCP
  incident payloads gain a `memory` block showing exactly what the analysis saw.
  Deterministic and on by default; recall reuses the `memory.lookback_days`
  horizon. See [Incident memory](docs/concepts/incident-memory.md).
- **Shadow classifier (opt-in)** — recall matches on the verbatim group key; when
  the key just misses but a prior finding is one label off, an optional small
  Haiku call can judge whether it is really the same underlying condition. It
  ships dark: `memory.classifier.mode: shadow` records every verdict in the audit
  log while the analysis prompt stays byte-identical, so you can measure its
  precision against memory recall's own confirm/refute ground truth before
  flipping it to `on` (where a match tags the recall "LLM-matched, probably
  related"). Off by default; ~$0.0003 per call on Haiku, and it never attaches,
  suppresses, or skips a triage. See
  [Shadow classifier](docs/concepts/incident-memory.md#shadow-classifier).

### Changed

- **Docker Compose pulls the released image** — the bundled stack now runs
  `ghcr.io/alertint/alertint-agent:latest` (multi-arch) instead of
  compiling the agent from source, cutting minutes off the quickstart's
  first `docker compose up`. Building from the working tree moved to an
  opt-in override file (`docker/docker-compose.build.yaml`), which the
  developer Taskfile targets (`task run`, `task docker:*`) include
  automatically.

## [0.6.2] - 2026-07-06

### Changed

- **MCP server is now on by default when its token is set** — `mcp.enabled`
  is presence-based like the Prometheus and Loki connectors: setting the
  bearer-token env var (`ALERTINT_MCP_TOKEN` by default, now also the
  `mcp.token_env` default) starts the MCP server inside `alertint serve`;
  an explicit `enabled: false` forces it off, and an explicit `enabled: true`
  still fails loud when the token is missing. Existing configs with an
  explicit `enabled` value keep their behavior.

### Added

- **One-command release** — `task release -- x.y.z` now cuts the whole
  release from any branch: it switches to a fast-forwarded `main`, rolls
  the changelog, previews the release body, and on confirmation commits
  the roll to `main`, tags, and pushes — replacing the manual
  branch/PR/merge/tag choreography (see `RELEASING.md`).
- **Config/docs drift gate** — `go test` now verifies that
  `config.example.yaml` loads through the strict config parser, that the
  defaults documented in the configuration reference match the code's
  actual defaults, and that every key shipped in the example config is
  documented.

## [0.6.1] - 2026-07-06

### Changed

- **Docker Compose stack is drill-ready** — `docker/agent.config.yaml` now
  ships `changes.ingress` enabled and the compose file passes
  `ALERTINT_CHANGES_WEBHOOK_TOKEN` into the agent container, so
  `alertint drill` run inside the stack plants its deploy and produces the
  causal, uncapped finding. `docker compose up` therefore requires the token
  in `.env` (already documented in `.env.example`).
- **Quickstart reordered around the drill** — install → configure → serve →
  drill → MCP client → Alertmanager: the drill needs neither Alertmanager nor
  an MCP client, so it now comes right after first start, with a
  compose-variant command and a `config.example.yaml` fetch for
  binary-only installs. The README's step-by-step quickstart was replaced by
  a pointer to the canonical walkthrough at alertint.com/docs.
- **One agent handoff per Slack surface** — the analysis thread no longer
  appends a raw MCP tool-name hint under the handoff block; the
  `investigate incident <id> using alertint` call to action is the single
  handoff, and its "paste" phrasing is dropped on Slack and in the drill
  console.

## [0.6.0] - 2026-07-06

### Changed

- **Default triage model is now `claude-sonnet-5`** (was `claude-haiku-4-5-20251001`).
  The first finding is built by the strongest reasoning tier in its price class;
  `model: claude-haiku-4-5` remains a one-line opt-in for cost-sensitive deployments.
  Every LLM request now also disables extended thinking explicitly, so models that
  default thinking on cannot consume the output budget of the JSON reply.
- **Presence-based enrichment enablement** — Prometheus, log (Loki), and change
  enrichment now turn on automatically when they are configured: setting
  `prometheus.base_url` or `logs.loki.base_url`, or activating any change source
  (`changes.ingress` or the Sentry releases poller), enables the corresponding
  read-only connector. An explicit `enabled: false` still forces a connector off.
  `logs.provider` now defaults to `loki`.
- **Single-alert triage by default** — `correlator.min_alerts` defaults to `1`
  (was `2`), so a lone first alert still produces a finding.
- **Example config ships change ingress and MCP enabled** —
  `config.example.yaml` now has `changes.ingress.enabled: true` (the flagship
  drill is causal out of the box, and a one-line deploy-time `curl` gives real
  triage its "what changed" evidence) and `mcp.enabled: true` (the drill's
  payoff fetch and the product's MCP handoff work without editing config).
  Copying the example verbatim therefore requires `ALERTINT_CHANGES_WEBHOOK_TOKEN`
  and `ALERTINT_MCP_TOKEN` at startup (both documented in `.env.example`).
  Docs positioning updated to match: Prometheus is promoted to the recommended
  first evidence source; Pushgateway synthetic metrics are demoted to optional
  compose-stack realism.
- **`correlator.group_labels` is validated more strictly** — entries using the
  now-reserved `alertint_` label-key prefix, duplicated keys, and
  whitespace-padded keys are rejected at config load. Configs that previously
  carried such entries (silently misbehaving) now fail loud at startup;
  `alertint validate` catches them ahead of a deploy.
- **Drill change events never enrich real incidents** — change events carrying
  the reserved `alertint_drill` marker are excluded from triage change
  enrichment unless the incident itself is a drill, so a planted drill deploy
  can neither lift a real incident's confidence cap nor invite a false causal
  attribution.
- **Docs validator** — `docs/scripts` now rejects duplicate page `order` values
  within a section, so the rendered sidebar order stays deterministic.

### Added

- **`alertint drill`** — one command fires a synthetic Drill at a running
  instance and ends at "finding ready". The flagship
  scenario plants a fake deploy on the change webhook and follows with an
  overlapping alert burst, producing a causal, uncapped finding that names the
  deploy; a `--scenario storm` variant fires a storm-sized burst that lands as
  one incident. Everything is
  derived from the same config file `serve` reads (receiver/MCP addresses,
  tokens, `group_labels` adaptation); the console prints progress, waits out
  the correlation window, then polls MCP until the finding is ready (bounded
  by a triage grace) and renders it plus the
  `investigate incident <id> using alertint` handoff (`--result <id>`
  re-checks a slow triage). `--resolve` re-sends the burst as resolved after
  the run, closing the Drill through the production resolution path (Slack
  cards update in place). Drill alerts carry the reserved
  `alertint_drill="true"` label — rendered as a 🧪 DRILL banner on Slack cards
  and a `drill` flag on the MCP incident list — and the whole `alertint_`
  label-key prefix is now reserved (rejected in `correlator.group_labels`).
  Remote targets require confirmation (`--yes`), plain-HTTP remotes an
  explicit `--allow-insecure-http`, and `--via-alertmanager` optionally
  validates your AM→AlertINT routing.
- **`alertint validate <config>`** — an `nginx -t`-style config dry-run: strict
  parse (unknown keys rejected) plus full validation, skipping
  machine-coupled filesystem checks so pod-destined configs validate cleanly
  on a laptop or CI runner; exits 0/1 with actionable errors.
- **`notify.slack.min_severity`** (`low` | `medium` | `high`, default `low`) — a
  Slack noise gate: findings below the threshold are not posted (stdout always
  emits, and a suppressed incident's resolution is suppressed too). Suppressions
  are recorded in the audit trail as `notify.skipped`.
- **Agent-handoff prompt on the Slack incident card** — the firing card and the
  analysis thread both carry a copy-pasteable
  `investigate incident <id> using alertint` prompt with the full incident ID,
  rendered as a full-size section (not caption text), so the MCP handoff is a
  prominent one-paste action on every firing surface.
- **Deterministic confidence cap for metadata-only findings** — when triage had no
  live evidence (no metrics, logs, changes, or Sentry issues), the persisted and
  notified confidence is capped at 0.6 regardless of what the model returned,
  backing the existing prompt-side calibration directive.

### Fixed

- **Sentry integration docs** — the page now documents both connector roles as
  consistently as the other integration docs. The frontmatter summary covers the
  Error source alongside the Change source, the `sentry.releases` and `sentry.issues`
  config blocks each gained a field-reference table, and all three MCP tools
  (`alertint_recent_changes`, `sentry_issues_list`, `sentry_issues_trace`) now live
  under one `MCP tools` section with an example-queries block.
- **Docs sidebar ordering** — `loki` and `mcp-clients` both declared `order: 2`,
  leaving their relative sidebar position undefined; `mcp-clients` is now `order: 5`.

## [0.5.1] - 2026-07-01

### Fixed

- **Log enrichment for multi-service incidents** — triage now fetches logs for correlated
  incidents whose alerts span several services or instances. The log selector previously used
  only labels shared *identically* by every member alert, so a multi-service cascade (exactly
  the kind AlertINT correlates) yielded an empty selector and no logs at all. It now unions each
  member's values for labels present on all of them, e.g. `{service=~"api|db-proxy"}`, and the
  Loki provider renders multi-value labels as anchored regex alternations.
- **Confidence calibrated to evidence** — when a finding is produced with no live evidence (no
  log lines, metrics, deploy/config changes, or Sentry errors), the triage prompt now flags the
  analysis as annotations-only and instructs the model to treat causal direction as a hypothesis
  and lower its confidence, so an unverified root cause no longer reads as authoritative.
- **Incident recovery visible over MCP** — `alertint_get_incident` and `alertint_list_incidents`
  now include a `recovery` object (firing/resolved member counts, `fully_resolved`, and
  `resolved_at`) so an investigating agent can tell an active incident from a recovering or
  recovered one without a second query for member statuses.
- **Empty query results are self-explaining** — `prometheus_query` and the `<backend>_query_range`
  log tool now attach a `hint` when a query matched nothing, so an empty result is distinguishable
  from a misconfigured selector or wrong metric name.

## [0.5.0] - 2026-07-01

### Added

- **Sentry connector** — optional read-only, egress-only Sentry integration over one shared
  connection and token, playing four roles you enable independently:
  - **Change source** — a background poller records new releases/deploys as change events on
    the shared change plane (beside pushed CI deploys), answering *"what shipped right before
    this?"* Surfaces in the triage *Recent changes* block and via `alertint_recent_changes`.
  - **Error source** — a bounded read-only query-at-triage (`1+K` Sentry calls per incident)
    that distills the top issues into a `sentry` prompt section: exception type + deepest in-app
    `file:line`, blast radius (level / affected users / in-window rate), and a NEW-vs-chronic
    flag. Persisted with the finding and replayed by `alertint_get_evidence_pack`.
  - **Cross-source reconciliation tag** — a zero-LLM verdict (`matched` / `infra-only`)
    prepended to the `sentry` section as one neutral headline the model weighs; persisted, and
    inert when Sentry is disabled or the query degrades.
  - **`sentry_issues_list` / `sentry_issues_trace` MCP tools** — live, read-only distilled
    issue lookups (by project/status; full stacktraces for up to 10 issue ids), registered when
    the Error source is enabled.
  Distillation is the privacy boundary: only an allowlist of structured fields crosses Sentry's
  API into the prompt, at-rest SQLite, and MCP surfaces — never local variables, request bodies,
  or breadcrumbs. `include_message: false` strips the exception message from all three at once.

## [0.4.0] - 2026-06-20

### Added

- **Change-event enrichment** — a universal webhook ingester accepts pushed **change events**
  (deploys, config changes) on the same receiver port as Alertmanager alerts. At triage the LLM
  prompt gains a *Recent changes* block answering *"what changed right before this incident?"*,
  and the read-only `alertint_recent_changes` MCP tool exposes them to an investigating agent.
  This is the change plane the Sentry **Change source** (v0.5.0) later feeds. (#6)
- **Selectable agent config** — `ALERTINT_CONFIG_FILE` chooses which config file the container
  loads at startup; the dev stack gains a `log_format` toggle.

### Changed

- **Breaking — receiver config unified:** `alertmanager.webhook_addr` becomes `receivers.address`,
  and the `--webhook-addr` flag becomes `--receivers-addr`, reflecting the single ingester that
  now receives both alerts and change events.

## [0.3.0] - 2026-06-18

### Added

- **Human-readable `console` log format** — a colored, one-line-per-event format
  (`HH:MM:SS LEVEL  message · key=value …`) for live watching, plus an `auto` default that
  resolves to `console` on a terminal and `json` otherwise (keyed off stderr). Selectable
  via `log_format: auto | console | json` (config) or `--log-format`, with precedence
  CLI flag > config > default. `CLICOLOR_FORCE` forces color when the stream is not a TTY
  (e.g. `docker logs`); `NO_COLOR` always disables it.
- **Operator action trail** — every meaningful action emits one INFO line that stands alone
  with incident context: `webhook received`, `loki fetched`, `llm responded`, `finding`,
  `notified` / `notify partial` / `notify failed`, `triage done`, plus a `notifiers ready`
  line at startup listing the active sinks (and the Slack channel).
- **Per-sink notification outcomes** — `Notifier.Name()` and a `Multi`-owned outcome line
  name each sink `ok`/`FAIL`; any failure additionally logs one detail line per failing sink
  carrying the full wrapped error (Slack includes the channel). Closes the silent-Slack-send
  gap.
- **Dev convenience** — `task docker:logs` / `task docker:up:logs` follow the agent container
  with color intact; `CLICOLOR_FORCE=1` is set in the Compose dev stack.

### Changed

- **Default log format** flips from JSON to `auto` (console on a terminal, json otherwise);
  non-TTY deployments (compose, pipes, journald) are unchanged.
- **Log level/format are now config-driven** — the previously-dead `log_level` config value
  is applied, and config loads before the logger is built so the first `alertint starting`
  line honors it.
- **Cleaner INFO view** — chatty internals (per-alert upsert, correlator bookkeeping,
  selector derivation) moved to DEBUG; the default view reads as the action trail.
- **Finding output** — the full machine-readable JSON finding to stdout is reserved for
  `--log-level=debug`; at INFO the finding shows as a one-line `finding` summary while the
  stdout sink still confirms delivery on the `notified` line.
- **Anthropic client** — `Complete` now returns token usage and latency so the caller emits
  `llm responded` without re-deriving them.

### Removed

- **`text` log format** (breaking) — removed and not aliased; an unknown `log_format`
  (including `text`) fails loud at startup. The slog `TextHandler` and the separate 3-line
  "card" finding notifier are gone — the finding is now the one-line `finding` summary.

## [0.2.0] - 2026-06-17

### Added

- **Loki log-enrichment connector** — optional read-only Loki/Grafana-Cloud-Logs client.
  At triage time it enriches the LLM prompt with the most relevant recent log lines
  (error-biased filtered query, with one unfiltered fallback), translating the incident's
  shared alert labels into LogQL via a configurable `label_map`. The exact lines the model
  saw are persisted with the finding and replayed by `alertint_get_evidence_pack`.
- **`loki_query_range` MCP tool** — read-only native-LogQL range query, registered when the
  Loki connector is enabled, so an investigating agent can drill into logs over MCP.
- **Dev-stack logs** — bundled Loki service in the Docker Compose dev stack plus
  `docker/push-synthetic-logs.py` (`task logs:push:local` / `task logs:push:cloud`) to seed
  fake multi-level log lines for local Loki or Grafana Cloud.

## [0.1.0] - 2026-06-10

### Added

- **Alertmanager webhook receiver** — `POST /webhook/alertmanager` accepts Alertmanager v4
  payloads with bearer-token auth; deduplicates alerts by fingerprint into SQLite.
- **Fixed-window correlator** — groups alerts by configurable labels within a time window;
  dispatches incidents when the window expires.
- **Acute-triage skill** — builds an evidence pack (shared labels, timeline, severity
  distribution, top annotations) and calls the Anthropic Claude API to produce a
  structured finding (summary, root cause, confidence, per-alert roles).
- **Notifiers** — stdout (JSON), human-readable console, and optional Slack delivery via the
  bot-token API (`chat.postMessage`) with in-thread resolution updates.
  Resolution events are also forwarded through all configured notifiers.
- **MCP HTTP server** — `alertint serve` exposes `:9912/mcp` when `mcp.enabled: true`.
  Five read-only tools: `alertint_list_incidents`, `alertint_get_incident`,
  `alertint_search_alerts`, `alertint_get_evidence_pack`, `alertint_verify_audit`.
  Compatible with Claude Code, Cursor, and Windsurf.
- **Prometheus read connector** — optional read-only PromQL client; powers two MCP tools
  (`prometheus_query`, `prometheus_query_range`) for live metric context during investigation.
  Also enriches the LLM prompt with relevant metric values at triage time.
- **Hash-chained audit log** — every action (alert received, LLM call, notification sent)
  appends a SHA-256-chained row. `alertint verify-audit` detects any tampering.
- **Health endpoint** — `GET /health` on the webhook port returns `{"status":"ok"}` when
  SQLite is reachable; used as the Docker healthcheck.
- **`alertint health` subcommand** — probes `GET /health` and exits 0/1; safe to use as a
  Docker `CMD` healthcheck on scratch-based images with no shell.
- **MCP client examples** — copy-paste configs for Claude Code, Cursor, and Windsurf under
  `examples/mcp-clients/`.
- **Docker Compose dev stack** — Alertmanager + AlertINT agent + Prometheus + Pushgateway;
  synthetic metric script for local testing.
- **Single static binary** — pure-Go SQLite (no CGO), no external runtime dependencies.
  Multi-platform builds: `linux/amd64`, `linux/arm64`, `darwin/arm64`.

[Unreleased]: https://github.com/alertint/alertint-agent/compare/v0.8.3...HEAD
[0.8.3]: https://github.com/alertint/alertint-agent/compare/v0.8.2...v0.8.3
[0.8.2]: https://github.com/alertint/alertint-agent/compare/v0.8.1...v0.8.2
[0.8.1]: https://github.com/alertint/alertint-agent/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/alertint/alertint-agent/compare/v0.7.5...v0.8.0
[0.7.5]: https://github.com/alertint/alertint-agent/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/alertint/alertint-agent/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/alertint/alertint-agent/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/alertint/alertint-agent/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/alertint/alertint-agent/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/alertint/alertint-agent/compare/v0.6.2...v0.7.0
[0.6.2]: https://github.com/alertint/alertint-agent/compare/v0.6.1...v0.6.2
[0.6.1]: https://github.com/alertint/alertint-agent/compare/v0.6.0...v0.6.1
[0.6.0]: https://github.com/alertint/alertint-agent/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/alertint/alertint-agent/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/alertint/alertint-agent/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/alertint/alertint-agent/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/alertint/alertint-agent/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/alertint/alertint-agent/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/alertint/alertint-agent/releases/tag/v0.1.0
