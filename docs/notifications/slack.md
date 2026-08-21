---
title: "Slack"
description: "One evolving Slack thread per Situation, with viewer-local update promises and visible recovery confirmation."
section: "Notifications"
order: 1
slug: "slack"
---

# Slack

**AlertINT**'s Situation controller is the only Slack writer in this build.
Every operational episode gets **one root message and one thread** — never
one card per Incident, never a card per re-fire. The root is edited in place
as the episode evolves; routine detail goes to the thread, almost always
without re-notifying the channel.

Synthetic Situations fired by `alertint drill` are unmistakable in a shared
channel: every surface of their root and thread — text, fallback, and
recurrence replies — carries a 🧪 **DRILL** prefix, so a drill never reads as
a real Situation to a teammate scrolling past.

## Setup — Slack app with bot token

1. **Create a Slack app.** Go to <https://api.slack.com/apps> and click
   **Create New App → From scratch**. Name it **AlertINT** and select your
   workspace.

2. **Add the `chat:write` scope.** In the left sidebar, click
   **OAuth & Permissions**, scroll to **Bot Token Scopes**, and add
   `chat:write`. That is the only permission **AlertINT** needs.

3. **Install to your workspace.** Scroll to the top of
   **OAuth & Permissions** and click **Install to Workspace → Allow**.
   Slack displays a **Bot User OAuth Token** starting with `xoxb-`. Copy
   it.

4. **Invite the bot to your channel.** In Slack, open the channel where
   Situations should appear (create `#alerts` if needed) and type
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

## One root, seven states

A Situation receives its immutable public handle and one Slack root only
when it is first published — a genuinely silent Situation (one whose facts
never crossed a publication reason) never gets a root at all. Text is
authoritative; color/icon is supplementary:

| State | Color/icon | Meaning |
|---|---|---|
| `investigating` | 🟠 orange | AlertINT investigating — no operator action |
| `judgment_requested` | 🟡 yellow | Operator judgment requested — still monitoring |
| `action_required` | 🔴 red | Operator action required — monitoring continues |
| `expected_active` | ⚪ neutral | Expected for this episode — no operator action (a matching, quieting Expected-behaviour envelope covers the current episode) |
| `recovery_pending` | 🟢 light green | Recovery observed — confirming stability |
| `recovered` | ✅ green check | Recovered — no further action |
| `closed_unknown` | ⚫ neutral | Closed with uncertainty — review reason in MCP |

`recovery_pending` uses a deliberately distinct light-green treatment so it
never reads as the same state as `recovered` on a Slack surface that can't
render the exact shade. An explicit operator action requirement beats an
explicit judgment request beats a matching expected-episode envelope beats
the default "AlertINT investigating" state.

`expected_active` itself renders correctly whenever the controller has a
matching envelope evaluation to act on. In this build that evaluation is not
yet produced automatically during ordinary reconciliation — see "Known gap"
under [Judgment and envelope confirmation](#judgment-and-envelope-confirmation)
below.

## What the root says

Every published root states why attention is warranted, what has been
checked, what runs next, who acts, and when the next update lands — plus the
Situation's MCP handle:

```text
🟠 AlertINT investigating — no operator action
Why: sustained CPU saturation on db-prod-1, no confirmed causal change yet
Checked: Prometheus, recent deploys
Next: verification round on the acute finding
Actor: AlertINT
Next update in 5 minutes, by <!date^1787210400^{date_short_pretty} at {time}|2026-08-20 10:00 UTC>.
Handle: `db-prod-sustained-cpu`
```

That `<!date^…>` token is Slack's own date markup — **AlertINT** emits it for
every instant on the Situation surface (start time, evidence time, next
update, envelope boundaries, recovery observed/grace, terminal time, prior-
episode comparisons). Slack renders the same underlying epoch in **each
viewer's own device-local timezone and time format** — the same message
shows roughly 13:00 to a Riga viewer and 11:00 to a UK viewer in summer,
while the canonical stored instant stays `10:00Z` everywhere else (storage,
audit, MCP, scheduling). A plain UTC fallback rides in the same payload for
any surface that cannot render the markup.

The promised update line always pairs a relative and a viewer-local absolute
time: `Next update in 5 minutes, by <viewer-local time>`, plus `, or on
recovery` when recovery is one of the events that can trigger an earlier
update. Relative minutes are computed from the canonical rendered time and
the next-update deadline, rounding a partial minute upward; a root edit
recomputes both, and reconciliation at the promised deadline replaces an
expired countdown before it can go stale in the channel.

## Thread vs. channel — the re-page rule

Routine evidence, retries, limitations, judgments, and Assessment history
post as **non-broadcast thread replies** or root edits — visible to anyone
who opens the thread, invisible to anyone just scanning the channel. A new
main-channel poke (a broadcast reply, or the very first root) is permitted
only for:

- a newly crossed deterministic critical floor,
- a valid urgent Attention,
- a no-action → judgment/action handoff, or
- a materially changed required action, after a cooldown
  (`situations.slack.repage_cooldown_seconds`, default 900s).

A handoff always edits the root first, then adds exactly one broadcast
reply. Lack of acknowledgement never causes repeated paging — **AlertINT**
does not re-page because nobody responded.

### Recurrence

A recurring symptom resurfaces in its Situation's existing thread, controlled
by `notify.slack.recurrence_mode`:

```yaml
notify:
  slack:
    recurrence_mode: change-gated   # change-gated (default) | off
```

- `change-gated` (default) — a real-world change (severity rise, new
  symptom, faster cadence) or a milestone (×5/×10/×25/×50/×100, then every
  ×100) posts one non-broadcast thread reply naming why
  (`:repeat: recurred ×9`); anything short of that just edits the root count
  in place.
- `off` — recurrence never posts a reply; the root's count still updates in
  place, silently.

## Recovery pending — visible before "recovered"

When a Situation's current member Alerts resolve, **every published root
immediately edits** to the light-green `recovery_pending` state and a
non-broadcast thread reply records it — the prior Attention is preserved for
audit and refire handling, but the pending Slack contract, not the Attention
color, controls what's on screen. Firing-only probes pause; source/recovery
watching continues.

- **A refire before grace expires** edits the root back to its active state
  and records "recovery did not hold" as a non-broadcast reply — no new
  channel message, unless the refire independently crosses one of the
  re-page rules above.
- **Clean grace expiry** turns the same root green (`recovered`) and adds a
  closure thread reply.

`recovery_pending`, `expected_active`, and every ordinary de-escalation edit
are root edits — none of them count as a main-channel poke. The recovery
confirmation window is configurable per source in
`situations.recovery_grace`; in this build every Situation currently uses
the flat `webhook_seconds` default (120s) regardless of source, since no
caller yet classifies deliveries as webhook versus polling — see
[Architecture](../concepts/architecture.md#situation-controller-known-gaps).

## Judgment and envelope confirmation

`alertint_situation_judgment_record` and `alertint_expected_behavior_confirm`
both **require explicit confirmation and an asserted operator identity**
(`operator_confirmed: true` plus `confirmed_by`). A recorded judgment steers
the *existing* root directly — it becomes part of the Situation's next
deterministic snapshot, so the root's action contract and state can move
(e.g. out of `judgment_requested`) as a root edit plus a non-broadcast
thread reply, without minting a new Situation. Every judgment and envelope
write is audit-chained with both `authenticated_as=installation_mcp_token`
(the one MCP trust domain today — there is no per-user RBAC/SSO in this
tracer bullet) and the asserted operator.

**Known gap:** confirming or revoking an Expected-behaviour envelope does
**not** yet, on its own, steer an existing root to or from `expected_active`
in this build. Confirmation and revocation persist the envelope version
correctly and schedule the affected Situations for reconsideration, but the
Reconcile loop does not call the envelope-matching logic during that
reconsideration — so a newly confirmed envelope will not silence a matching
Situation's poke, and a revoked one will not resume interrupting, until this
wiring lands. The envelope surface itself — confirmation, versioning,
matching logic, schedule/DST resolution, violation detection — is fully
correct and covered by tests that call it directly; only its automatic
invocation from an ordinary reconciliation attempt is missing. See
[Architecture: Situation controller — known
gaps](../concepts/architecture.md#situation-controller-known-gaps).

An Expected-behaviour envelope's sparse confirmation reminder
(`situations.envelope_review.reminder_interval_days`, default 30) is its own
standalone, high-priority main-channel message — it never creates or reuses
a Situation thread:

```text
:clipboard: Expected-behaviour review due — nightly_risk_calculation on db-prod-1
Review by: <!date^…|2026-11-20 UTC>
Matches since last confirmation: 4
MCP: `alertint_expected_behavior_confirm`
```

## The outward Slack floor: `min_severity`

`notify.slack.min_severity` (`low` \| `medium` \| `high`, default `low`) is a
temporary, outward-only escape hatch. In Situation mode it no longer compares
against Alert severity — it compares against a deterministic **Interruption
priority** derived from the validated reason, Attention, and action
contract:

| Interruption priority | When it applies |
|---|---|
| `critical` | an unquieted deterministic critical floor — **always passes this outward floor**, regardless of `min_severity` |
| `high` | urgent Attention, operator judgment/action required, actionable terminal uncertainty, or a sustained shared-health outage |
| `medium` | non-critical investigation while AlertINT remains the next actor |
| `low` | an informational standalone interruption, if one is introduced |

L2 cannot propose or set this priority — code derives it deterministically.
Today the outward config value's string-to-priority mapping is intentionally
permissive: `warning` maps to `medium`, and any unrecognized or unset value
falls back to the most permissive `low` floor rather than silently
withholding a poke.

The floor only withholds a **new main-channel poke** — never an in-place
root edit, non-broadcast thread history, ingestion, Assessment, or MCP
visibility. A poke withheld this way persists as
`withheld_by_operator_slack_floor` in the notification history (visible on
`alertint_situation_get`); it is never silently rewritten as "observe" or
treated as healthy.

## Shared dependency health

When a shared installation-level dependency (the LLM, a connector) stays
degraded past `situations.dependency_health.broadcast_after_seconds` (default
300s), **AlertINT** posts **at most one health root** for the whole outage,
and one recovery update when it clears:

```text
:warning: LLM degraded — AlertINT's shared dependency is unavailable; affected Situations remain visible in MCP
```

Affected Situations expose the degradation in MCP and audit and only update
their own existing threads if their operator contract actually changes — a
shared outage never fans out into one noisy message per affected Situation.
The health root and its recovery update are both main-channel pokes, and
both are counted separately in the funnel (see
[Architecture](../concepts/architecture.md#the-funnel)).

## Idempotency

Every post carries a deterministic `client_msg_id` (a UUIDv5 over a fixed
AlertINT Slack namespace and the notification's own `idempotency_key`), so a
retry after a timeout or a restart reuses the exact identity Slack already
saw instead of double-posting. Root edits always target the persisted
channel and message timestamp from the first publish. A Slack-side failure
never rewrites an actionable Assessment as `observe` — it remains a durable
pending/failed intent that retries with the same identity, honoring Slack's
own rate-limit retry timing where available.

## Legacy per-Incident notification (removed)

Earlier builds posted one Slack card per Incident directly after triage, with
firing/resolved states and per-recurrence card edits. That code path is no
longer wired in `alertint serve` — the Situation controller described above
is the sole Slack writer. The old per-Incident renderers remain in the
codebase only to back fixture tests for the earlier card format; they are
never reachable at runtime.
