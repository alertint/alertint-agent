---
title: "Slack"
description: "How AlertINT presents incidents and Situations in a Slack channel."
section: "Notifications"
order: 1
slug: "slack"
---

# Slack

**AlertINT** posts to one Slack channel over the bot-token Web API. What it
posts depends on which build you run:

| Build | What Slack shows | Written by |
|---|---|---|
| Released binary (from `main`) | One **Incident card** per analyzed incident, edited in place on resolve, with a thread for detail | the Incident notification path |
| `state-controller` integration branch | One **Situation root** per Situation, edited in place, with an immutable ordered journal thread | the Situation delivery worker — the *only* Slack writer on that branch |

On the integration branch the Incident-keyed card, its resolve edit, and its
recurrence replies are **gone**: runtime assembly no longer wires any
Incident-shaped Slack call at all. The two exceptions are installation-level
`AlertINT system` messages, described at the end of this page.

Both models use the same app, token, channel, and setup below. There is no
mode switch: one build runs one Slack writer.

Synthetic incidents fired by `alertint drill` are unmistakable in a shared
channel: every surface — headline, thread details, and the plain-text
fallback — carries a 🧪 **DRILL** banner, so a drill never reads as a real
incident to a teammate scrolling past.

## Setup — Slack app with bot token

1. **Create a Slack app.** Go to <https://api.slack.com/apps> and click
   **Create New App → From scratch**. Name it **AlertINT** and select your
   workspace.

2. **Add the `chat:write` scope.** In the left sidebar, click
   **OAuth & Permissions**, scroll to **Bot Token Scopes**, and add
   `chat:write`. That is the only permission **AlertINT** needs. It never
   requests a history-read scope and never reads the channel back.

3. **Install to your workspace.** Scroll to the top of
   **OAuth & Permissions** and click **Install to Workspace → Allow**.
   Slack displays a **Bot User OAuth Token** starting with `xoxb-`. Copy
   it.

4. **Invite the bot to your channel.** In Slack, open the channel where
   alerts should appear (create `#alerts` if needed) and type
   `/invite @AlertINT`. The bot must be a channel member to post there.

5. **Add the token to your `.env` file** — the same file that holds your
   other secrets. Never put the token value directly in `config.yaml`:

   ```bash
   # .env  (gitignored — never commit this file)
   SLACK_BOT_TOKEN=xoxb-...
   ```

6. **Add Slack to your `config.yaml`** under `notify`. Use the env var
   name — not the token value itself:

   ```yaml
   notify:
     slack:
       enabled: true
       bot_token_env: SLACK_BOT_TOKEN  # name of the env var — not the token value
       channel: "#alerts"              # channel name or ID where alerts should post
   ```

## Situation-owned Slack

**Integration-branch behaviour, not yet the `main`-branch default.** This is
what a binary built from the `state-controller` branch posts. See
[Architecture: Situation foundation and
controller](../concepts/architecture.md#3a-situation-foundation-and-controller)
for where it sits in the pipeline.

### One root, one thread

A published Situation owns exactly **one** main-channel message — its
**root** — and an append-only thread of **journal entries** beneath it.

- The **root** always states the *current* full picture: what is happening,
  why the current attention level is warranted, what AlertINT checked or is
  checking, who acts next, what happens next and by when, and the Situation's
  immutable handle plus its MCP retrieval path. It is **edited in place**
  every time that picture materially changes. Once terminal, it states what
  happened, the final outcome, what AlertINT investigated or concluded, the
  duration and peak attention, and any recorded operator involvement.
- Each **journal entry** is the immutable record of exactly one material
  change, rendered from that change alone — never from the newest state.
  Entries are non-broadcast replies: they stay in the thread.

Journal entries are created for first publication, material investigation
changes and conclusions, operator-contract changes, recovery pending,
recovery refire, recovery, closure with uncertainty, and operator
write-backs. Routine reconciliation, retry accounting, elapsed seconds
ticking by, and a re-fire attaching to the Situation that is already open
create **nothing** — no entry, no edit, no interruption.

### Orientation

The root's first line is a compact orientation with exactly one phase
emphasised:

```text
active, before material investigation
  **Observed** → Investigating → Monitoring → Outcome

active, once investigation starts or while work/action remains
  Observed → **Investigating** → Monitoring → Outcome

watching for sustained recovery
  Observed → Investigating → **Monitoring** → Outcome

recovered
  Observed → Investigating → Monitoring → **Recovered**

closed with uncertainty, with no monitoring phase in the episode
  Observed → Investigating → **Closed uncertain**

closed with uncertainty, after monitoring
  Observed → Investigating → Monitoring → **Closed uncertain**
```

A Situation that closed uncertain without ever waiting out a stability grace
**omits** the Monitoring step rather than inventing it. A recovery that does
not hold returns the emphasis from Monitoring to Investigating.

Orientation is a pure rendering of durable state — it is never stored as a
second lifecycle, never changed by delivery state, and moving between phases
never by itself creates a journal entry.

The line immediately below renders the operator contract in plain prose, for
example `AlertINT is running Acute Triage · update by 10:00:15`. Every
instant uses Slack's viewer-local date markup with a UTC fallback, so the
time reads correctly in every reader's own timezone. A promised update that
has already passed renders as overdue, never as a current promise.

### What earns a main-channel interruption

A new main-channel interruption (a "poke") is permitted only for a first
warranted publication, newly crossed deterministic criticality, newly valid
urgent attention, a hand-off from "AlertINT is working on it" to "an operator
must act", or a materially changed required action once the repage cooldown
has elapsed. **Root edits and journal replies are never interruptions**, and
a missing acknowledgement never repeats one. A hand-off edits the root first,
then posts one broadcast reply.

`notify.slack.min_severity` is the operator's floor on that interruption. In
the Situation path it compares against the derived **interruption priority**
(`critical` / `high` / `medium` / `low`) — not against alert severity and not
against anything the model said. `critical` always passes. The floor applies
only to a *new* main-channel poke: it never suppresses Situation state, the
history in MCP, a root edit, or a journal reply. A poke below the floor is
durably recorded as withheld, and later independently warranted
higher-priority state can still publish.

### Delivery: durable intent, indefinite retry, at-least-once

Every effect Slack must show is committed as a **durable notification intent**
in the same fenced database transaction as the change that warranted it. The
delivery worker is the only thing that talks to Slack, and it never holds a
database transaction open across a Slack call.

- **Local delivery intent is idempotent.** Every post and reply carries a
  deterministic client message ID derived from the intent's own identity. A
  timeout, an uncertain success, a crash, or a restart reuses the identical
  ID and payload. A restart never creates a second intent, a second root, or
  a second interruption.
- **External delivery is at-least-once.** If Slack accepts a message but the
  response is lost, AlertINT cannot tell that apart from a message that never
  arrived, so it retries with the same identity. That can rarely produce a
  **duplicate message in the channel**. AlertINT requests no Slack
  history-read scope and performs no read-back reconciliation, so this
  boundary is real and deliberate: a duplicate is preferred to a silently
  missing notification. The durable coordinates and the ordered retry state
  are never corrupted by it.
- **Valid effects retry indefinitely.** Retryable failures (transport
  errors, 5xx, rate limits) back off exponentially from 5 seconds to 5
  minutes with jitter, honour a longer Slack `Retry-After`, and **never
  exhaust**. There is no attempt ceiling and no dead-letter.
- **Definite configuration rejections block, they do not discard.** A
  missing or invalid token, a lost channel, a revoked scope, or a permission
  rejection moves the effect to `blocked_configuration`, where it waits
  durably. Restarting with corrected configuration returns it to pending and
  it delivers. Nothing is dropped to silence Slack.
- **An effect Slack rejects as impossible is parked in `failed`, visibly.**
  `failed` is reserved for a durable intent this build cannot send at all —
  a payload Slack rejects outright, or any Slack rejection code this build
  does not recognise as retryable or as a configuration problem. The
  commonest way to reach it
  is to **delete a Situation's root message in Slack by hand**: every later
  edit of that root then comes back `message_not_found`, and the root effect
  parks in `failed`. It is never retried on its own, and effects that wait
  on that root stay pending behind it rather than failing in a chain.
  `failed` effects are visible in the durable ledger and over MCP alongside
  every other delivery outcome, so a Situation that stops updating in Slack
  is diagnosable rather than silent.

  **Honest limitation:** redriving a `failed` effect is a Store operation
  (`RedriveFailedNotificationIntent`) with **no operator-facing command in
  front of it yet** — recovering one today means direct database access or a
  small program against the Store, not a CLI flag. Deleting a Situation's
  root message is therefore best avoided: a redrive alone will not bring it
  back, because the coordinates AlertINT holds still point at the message
  you removed. An operator control surface for redrive, and a specific
  recovery for a deleted root, are both deliberately out of this slice.
- **Ordering is preserved.** A Situation's root must be durably delivered
  before any reply is claimable; journal replies deliver in change order; a
  hand-off's root edit delivers before its broadcast reply; and a stale root
  projection is superseded before the call is made rather than posted and
  then corrected.

### Slack outages and recovery replay

A first failing Slack call is an **ordinary delay** — one WARN in the console
action trail, then paced retry WARNs, and nothing in the channel.

If Slack keeps failing continuously for **five minutes**, AlertINT opens one
durable **Delivery gap** generation. The gap makes the outage visible; it does
not change the delivery obligation. Subsequent failures join the same
generation.

When Slack answers again, the generation recovers and AlertINT posts, in this
order:

1. exactly **one bounded `AlertINT system` recovery notice** for that
   generation, stating the interval the gap covered, how many Situations were
   affected, how many effects were delayed, and that the backlog is now
   replaying; then
2. for every affected Situation, its **latest informative root** — posted if
   no root exists yet, edited if one does; then
3. **every** material journal entry, in change order.

Replay is complete, not summarised: no episode and no journal entry is
dropped because the gap was long. Old calls to action are shown as delayed,
non-current thread history — a hand-off whose requested action is no longer
current is delivered as an ordinary non-broadcast entry marked delayed rather
than broadcast to the channel as though it were live. Rate limits and
ordering are still honoured, so a large backlog takes time to finish.

A second outage during that replay opens its own generation with its own
single recovery notice; generations are never reused.

If a Situation reached its terminal state while its first publication was
still queued, AlertINT posts **one** root — the latest informative terminal
one — and then the ordered journal. It never replays the original card as
though it were current, and never posts a generic "all clear".

### Quiet Situations leave no Slack trace

A Situation that never warrants publication posts nothing at all: no root, no
thread, no interruption. Its state, history, and delivery decisions remain
complete and readable over MCP and in the audit log. The same is true of a
Situation whose only poke was withheld by your `min_severity` floor. Silence
in Slack is never a gap in the record.

### Operator notes and captured verdicts

An annotation or a captured verdict recorded over MCP (see
[MCP clients](../integrations/mcp-clients.md)) is journalled into its
Situation's own thread, attributed to the operator, in the same transaction
that records it.

- An **annotation** is recorded context. It does not change the assessment,
  the attention level, the reason, or publication authority, and it is never
  rendered as proof that anyone touched the operated system.
- A **captured verdict** is recorded with its own attribution and keeps
  exactly the authority it already had — it can steer later triage through
  the normal input path, and nothing more.
- If the incident has **no current owning Situation** — none was ever
  assigned, or the owner had already closed — the write still lands and stays
  visible through the incident's own MCP and audit history. It is recorded
  against a closed Situation as an artifact that arrived after closure
  (`artifacts_recorded_after_closure` in `alertint_get_situation`), never
  journalled into a closed episode and never lost. No old Incident card is
  resurrected or rewritten.

### What Slack agreement is checked against

Slack, SQLite, MCP, the audit log, logs, and stdout all identify the same
things by the same identities. `alertint_get_situation` exposes the whole
Slack presence of one Situation — whether a root is published, where it
lives, and every delivery obligation's class, status, priority, retry or
supersession reason, and delivered coordinates — and
`alertint_get_delivery_state` exposes the installation-level view: the
continuous-failure window, the configuration generation and how many effects
are blocked on it, the current Delivery gap and its backlog, and how many
outcomes Slack never confirmed either way.

### stdout is independent of Slack

Every material change also emits one machine-readable line on stdout:

```json
{"kind":"situation.transition","version":1,"transition_id":"…","situation_id":"…","sequence":4,"reason":"recovery_observed","journal_kind":"recovery_pending","lifecycle":"recovery_pending","attention":"observe","next_actor":"alertint","drill":false}
```

This line means the change is durably committed. It does **not** mean
anything reached Slack — a quiet Situation, a floor-withheld poke, and a
Situation whose delivery is queued behind an outage all still emit state.
**Deduplicate by `transition_id`:** a consumer that restarts, or reads a
stream that was replayed, may see the same transition line more than once,
and the transition ID is the stable identity to key on.

## Incident cards

**Released-binary behaviour (builds from `main`).** On the integration branch
this whole surface is removed; everything below is what a released binary
does today.

When an incident fires, **AlertINT** posts a brief main-channel message (name
+ root cause) and immediately posts the full analysis — severity, confidence,
correlation findings, MCP hint — as a thread reply. When all alerts recover,
it updates that message in place (🔴 → ✅, a duration field appears) and
posts a short resolution note in the thread.

### Message structure

Every notification uses Slack Block Kit. The same blocks appear for firing
and resolved — only the header and fields change on resolution.

| Block | Description |
|---|---|
| Main — header | 🔴 INCIDENT DETECTED when firing, updated to ✅ INCIDENT RESOLVED in-place when resolved. |
| Main — root cause | One-sentence root cause hypothesis, preserved when the message is updated on resolution. |
| Main — footer | Incident ID, alert count, severity, confidence, group key, and start time. Replaced by resolved time and duration on resolution. |
| Main — agent handoff | `investigate incident <id> using alertint` — the MCP call to action, with the full incident ID. Dropped when the incident resolves. |
| Main — steering ruling | On failure groups governed by an operator correction: one line stating whether live evidence supported it, contradicted it, or could not test it. Channel-visible on purpose — it is the triage outcome. |
| Thread — analysis | Posted immediately after the main message: severity, confidence, alert count, and group key in a fields grid. |
| Thread — operator history | The failure group's operator context: first-occurrence / seen-before state or the governing verdict's note, followed by up to three operator notes with ages. |
| Thread — evidence | One line: per-source counts (Prometheus/Loki/Changes/Sentry) that fed the triage, e.g. `Prometheus 21 metrics · Loki 0 lines`. A connector that could not be reached shows `unreachable` instead of a count; a known-issue short-circuit shows `skipped (known issue)`; a zero-connector install shows `no sources configured`. Always present. |
| Thread — findings | Bullet list of correlation findings. Only shown when the LLM identified more than one contributing factor. |
| Thread — agent handoff | The same handoff block, so the call to action reads identically on every firing surface. |
| Thread — resolved | Posted when all alerts recover: duration, alert count, and resolved timestamp in a fields grid. |

### Example — firing

Main channel:

```text
🔴 INCIDENT DETECTED — API Tier Degraded: CPU Saturation + Error Spike

Root cause: CPU saturation on api-2 is causing request queuing, elevating
error rates and response latency across the cluster.

Incident a1b2c3d4 · 3 alerts · high · 91% · group cluster=prod · started 14:37 UTC

🤖 Investigate in your AI agent: investigate incident a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d using alertint
```

Thread reply (posted immediately):

```text
Analysis details

Severity: HIGH        Confidence: 91%
Alerts: 3             Group: cluster=prod

Evidence: Prometheus 14 metrics · Loki 6 lines · Changes 1 · Sentry 2 issues

Correlation findings
• HighCPU (api-2) fired 15 s before HighErrorRate — causal ordering confirmed.
• HighLatency shares the same instance label, indicating single-host origin.

👀 seen ×2 in the last 90d (since 2026-07-01) — no operator verdict yet

Operator notes
📝 observation (2h ago): api-2 is the canary host; rollout paused.

🤖 Investigate in your AI agent: investigate incident a1b2c3d4-5e6f-7a8b-9c0d-1e2f3a4b5c6d using alertint
```

### Example — resolved

Main channel (updated in-place):

```text
✅ INCIDENT RESOLVED — API Tier Degraded: CPU Saturation + Error Spike

Root cause: CPU saturation on api-2 is causing request queuing, elevating
error rates and response latency across the cluster.

Incident a1b2c3d4 · resolved after 15m · 14:52 UTC
```

The MCP hint in the message footer is a pre-filled tool call. Paste it
directly into Claude Code, Cursor, or Windsurf to open the full evidence
pack for that incident — see [MCP clients](../integrations/mcp-clients.md).

### Recurrence resurfacing

When an already-analyzed incident re-fires inside the collapse window, it
doesn't get a new card — it attaches as another occurrence on the same
incident, and the card that's already in the channel is what carries the
update. Recurrence never adds channel messages:

- **A plain re-fire** just bumps the occurrence count on the existing card in
  place (`🔁 recurred ×N · last HH:MM`).
- **A real-world change** — severity escalated, a new symptom joined, or the
  cadence sped up markedly — posts a thread reply naming exactly why
  (`why: severity` / `why: new_alertname` / `why: cadence`).
- **A steady flapper** still gets a thread reply at milestone counts — ×5,
  ×10, ×25, ×50, ×100, then every ×100.

Control this with `notify.slack.recurrence_mode`:

```yaml
notify:
  slack:
    recurrence_mode: change-gated   # change-gated (default) | off
```

- `change-gated` (default) — post a thread reply on a real-world change or a
  milestone, as described above.
- `off` — recurrence never posts replies; the card's occurrence count still
  updates in place, silently.

On the integration branch this setting has **no effect**, and neither does a
re-fire that attaches to a Situation that is already open: it posts no reply
and edits no root. A Situation's recurrence count is the number of *closed*
Situations that preceded it in the same group, and only one Situation per
group can be open at a time — so that count is fixed for the Situation's whole
lifetime. `recurred ×N` therefore appears exactly once per Situation, on the
root of the **next** Situation the group opens, at its first publication. The
key is still accepted so an existing `config.yaml` keeps loading.

## System messages

Two installation-level `AlertINT system` messages are not tied to any
incident or Situation. They are the only sanctioned non-Situation Slack
writes on the integration branch.

### LLM dependency health

The configured LLM is an installation dependency, not a property of any
Incident. When it has been continuously unhealthy for
`health.broadcast_after_seconds` (default 5 minutes), AlertINT posts one
plain-text `AlertINT system` root message — on whenever Slack is enabled, no
second switch:

> ⚠️ AlertINT system · LLM unavailable for 5m. New Incident triage is
> retrying; correlation may be delayed.

> ⚠️ AlertINT system · LLM degraded for 5m. Verification re-judgment is
> failing; draft Findings continue with reduced confidence.

If the state changes again inside the same outage (`degraded ↔ unavailable`),
the same message is edited in place — never a second post. Once the LLM
recovers, one more edit closes it out:

> ✅ AlertINT system · LLM recovered after 12m. Pending triage retries
> continue automatically.

One root per sustained episode, edited in place, never per-Incident and never
threaded. If the LLM recovers before the root was ever successfully
delivered, the stale outage/recovery pair is suppressed — it survives only in
state, audit, and logs. A post Slack definitely rejected is retried on the
next minute; a post whose outcome is unknown (the request may have been
accepted before the connection failed, or the process restarted mid-post) is
never retried, because a second root is worse than a missing one — the
outage still shows in `/health`, audit, and logs. A root that turns out to
have landed after its episode already recovered is edited to that episode's
recovery — however many episodes have come and gone since, and even across a
restart before the edit lands — never left standing as a stale outage, and
never reused by the next episode, which earns its own root on its own clock.
Each Slack request is bounded by its own timeout: a request Slack accepts but
never answers counts as an unknown outcome (a post) or is retried on the
next minute (an edit), and never delays the idle probe that would report the
LLM back. During an outage, new Incident triage retries with backoff and
correlation may be delayed; this copy never claims Alert intake itself is
unaffected. See [Integration health](../getting-started/configuration.md#integration-health)
for the `/health` shape behind these messages.

### Slack delivery gap recovery

**Integration branch only.** One bounded notice per Delivery-gap generation,
posted ahead of the backlog replay described above. It is not a Situation and
not an LLM message, and it is never edited or repeated.
