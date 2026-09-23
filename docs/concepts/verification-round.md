---
title: "Verification round"
description: "How AlertINT falsifies its own draft verdict — a deterministic floor plus targeted checks — before a finding persists."
section: "Concepts"
order: 5
slug: "verification-round"
---

# Verification round

A single LLM call can be confidently wrong. Every piece of evidence a triage
call sees is scoped to the incident's own alerts — so a verdict like
"regional infrastructure event" has nothing in its prompt that could ever
contradict it, even when the rest of the fleet is healthy. Left alone, that
kind of draft doesn't just ship once: it gets re-confirmed on every
recurrence, because the same one-sided evidence produces the same confident
answer every time.

The **verification round** is the fix: after the model drafts a verdict,
AlertINT gathers **contrast evidence** — facts chosen to disprove the draft,
not support it — and asks the model to re-judge the draft against what it
finds. This is a fixed, two-step process, not an open-ended investigation: it
runs the same bounded shape on every judged triage — a capped batch of
read-only queries between the two calls. Open-ended, hypothesis-chasing
investigation stays where it already lived — at the MCP layer, driven by a
human or a connected agent.

The normal path remains two LLM calls. If model-proposed PromQL is
syntactically invalid, AlertINT parses it locally and makes one repair call
for the invalid batch, capped at 512 output tokens, before executing any
repaired query. It validates once more and never makes a second repair
call.

## What runs

Every judged triage — a fresh analysis or a re-judgment — runs the same two
steps.

**Call 1** drafts a finding exactly as before, plus a short list of
disprove-queries the model itself proposes: read-only checks it thinks would
challenge its own conclusion.

Before call 2, a runner executes:

- **The deterministic floor** — two checks that run on *every* judged
  triage, regardless of what the model asked for or whether it asked for
  anything at all:
  - **Peer-scope up ratio** — what fraction of the incident's broader scope
    (`namespace`/`service`/`job`, derived from the alerts' own labels) is
    up right now, rendered as a plain pair like "up 34/37 in
    namespace=checkout" — never a raw series dump. No shared broad label
    means an unscoped global ratio instead.
  - **Incidents in window** — is anything else firing on a different group
    key right now? A count plus up to five other incidents' group keys,
    severities, and statuses — never another incident's finding text.

  The model can add precision on top of the floor; it can never shrink or
  skip it. An overconfident draft is exactly the draft most likely to
  decline checking itself, so the floor's presence can't depend on the
  model's own self-assessment.
- **Up to `max_queries` model-chosen checks** — read-only Prometheus queries
  or another `incidents_in_window` lookup, run under the same rails as
  everyday enrichment (`prometheus.max_series`, per-query timeout slices).
  A named, closed set of query kinds — never raw SQL, never a write.
- **When a governing correction is steering the triage, its operator-sourced
  checks** — the correction's widened queries plus one probe per named cause
  series, run alongside the floor and model queries (not instead of them),
  capped at 5 and exempt from `max_queries` like the floor. Absent when no
  correction verdict governs the group key.

**Call 2** is a full continuation of call 1 — the same prompt prefix, the
draft as the model's own prior turn, then every query's result appended
verbatim. The instruction is explicit: verification results outrank the
draft, the evidence pack, and any recalled memory. If the checks contradict
the draft, revise; don't defend it. The result is the finding that persists —
confidence caps and the memory verdict apply to this final judgment, not the
draft.

### Locally invalid PromQL

Every PromQL check this pipeline runs is parsed locally before it can
run — not only the model's own proposals: a governing correction's
operator-sourced steering checks and the widen queries run once at verdict
capture go through the identical local check (the floor's own up-ratio and
incidents-in-window checks have no arbitrary expression to parse, so this
step never applies to them). All of it uses the official
Prometheus PromQL grammar — the same package Prometheus itself uses to
parse queries, statically compiled into the AlertINT binary. There is no
runtime download and no dependency on the target Prometheus's own version
or reachability to validate syntax.

A query that fails local parsing isn't dropped outright: AlertINT batches
every locally invalid **model-proposed** query from the round's plan into one
repair call to the model, capped at 512 output tokens, asking it to fix only
the syntax. Operator-sourced steering and capture-widening queries that fail
the same local check are marked invalid outright and never sent to a repair
call — they weren't drafted by the model, so there is nothing for the model
to be asked to fix. Each returned replacement is parsed again and checked
against the original — a repair may rearrange grouping or aggregation
syntax, but it may not change a
metric name, a label matcher, a function call, or a literal, so a model can't
"fix" a query it can't parse by quietly substituting a different question.
Whatever is still invalid after that one call — a failed repair call, a
malformed reply, or a replacement that fails either check — is never sent to
Prometheus. There is no second repair attempt.

A query that never reaches the backend this way resolves the query outcome
`invalid`: distinct from a query that ran and matched nothing (`empty`) and
from a query the backend couldn't answer (`failed`/`degraded`). It's logged
with the expression that was tried, persisted and audited as `invalid`, and
treated as inconclusive evidence — it can't confirm or contradict the draft
in call 2, the same as a failed or timed-out check. The Finding card surfaces
it as its own Slack/stdout caveat, kept separate from the `⚠ unverified —
checks unavailable` caveat below: an invalid query is a query-construction
problem, not a missing or slow metrics backend.

The same `invalid` outcome also covers a query that *passes* local syntax
validation but Prometheus itself still rejects as malformed — a
query-specific `bad_data` response naming the `query` parameter. That
backend-authoritative fallback applies to any live query the round runs, not
only the batch that went through repair: the deterministic floor's
peer-scope ratio can hit it too. A `bad_data` response about something else
(an out-of-range `limit` or `time` parameter, say), or any other backend
error, is a genuine backend problem and stays classified as `failed`
(hard error) or `degraded` (timeout) as before — it is never conflated with
`invalid`.

A syntactically valid query that runs and simply matches nothing is a
separate, ordinary case: `empty`, not `invalid`. An empty or weak-but-valid
result is a semantic question — did the query ask about the right series? —
not a query-construction defect, and call 2 is told to weigh it as
inconclusive rather than as a contradiction, exactly as before this feature.

### Floor sources

The deterministic floor speaks the install's backend. Prometheus contributes
a parent-scope up-ratio; a configured Zabbix API contributes two checks built
from the incident's host — is the host reachable per Zabbix's own polling
(and is it in maintenance), and are its host-group neighbors quiet or
burning. Installs with either backend get a real falsification pass; on a
Zabbix-only install findings no longer carry the "unverified — checks
unavailable" caveat. Neighbor scope prefers the smallest host groups first
(functional groups over catch-alls) and always names the groups it
searched — and the ones it left out.

## Cost

Judged incidents go from one LLM call to two, plus up to eleven read-only
queries (the two-query floor, up to four model-chosen checks by default, and
— when a governing correction is steering the triage — up to five more
operator-sourced checks). This lands after [recurrence collapse](incident-memory.md) has
already cut incident *volume* — a steady flapper that used to spend a fresh
analysis on every re-fire spends none, so the extra call per judged incident
isn't multiplied by every recurrence, only by genuinely new or escalated
conditions.

Two calls is still the normal path. A third call is possible, never
guaranteed: only when call 1 proposes at least one locally-invalid PromQL
check does the round spend the one bounded repair call (capped at 512 output
tokens) described above, before call 2 runs. A round with only valid
model-proposed queries — the overwhelming majority — never sees it. The
repair call is small, independent of the draft/re-judge prompt pair, and
doesn't share their prompt-cache prefix.

The second (re-judge) call also costs less than it looks: it reuses the
first call's prompt verbatim as an Anthropic prompt-cache prefix, so the
shared span (system prompt plus evidence) is written to the cache on call 1
and read back at roughly a tenth of the input price seconds later on call 2.
`llm.response` audit rows carry the raw numbers —
`cache_creation_input_tokens` and `cache_read_input_tokens`; effective input
cost is `input + 1.25 × creation + 0.10 × read`. Caching engages only when
the prefix clears the model's minimum cacheable size (model-dependent; small
incidents on `claude-haiku-4-5` typically don't) — when the re-judge call
reads no cached tokens, the agent logs a warning naming the likely cause.
Worst case is today's cost, never more. With verification disabled, requests
are unchanged and nothing is cached.

## The `unverified` caveat

Most rounds resolve cleanly: the checks either back up the draft or
contradict it, and the model revises accordingly. Occasionally a round can't
finish — a floor query fails, or the shared triage deadline runs out before
the second call. That round is **degraded**, and it's the one round-related
state that ever reaches the finding card: a short trust caveat, `⚠
unverified — checks unavailable`, next to the finding on Slack and stdout.

The card never renders the draft-versus-final story — no "revised from",
no confidence-before-and-after. The verdict text carries its own grounding;
the only thing a caveat needs to say is "the checks that were supposed to
back this up didn't run." A degraded round can never raise confidence past
what the draft already had, and it produces no memory verdict — an
unverified finding can't confirm or refute a recalled prior, so the
recurrence flywheel is only ever fed by contrast-checked judgments. A failed,
degraded, or locally/backend-invalid *model-chosen* query alone doesn't
degrade the round; the floor is the promised minimum, and targeted queries
are bonus precision on top of it. An invalid model-chosen query gets its own
caveat (see [Locally invalid PromQL](#locally-invalid-promql) above),
separate from `⚠ unverified`.

## Configuration

The verification round is tuned under
[`triage.verification`](../getting-started/configuration.md#triage):

```yaml
triage:
  verification:
    enabled: true              # kill-switch; false = single-call triage (today's old flow)
    max_queries: 4             # cap on model-chosen checks; the floor always runs regardless
    query_timeout_seconds: 10  # query-phase budget, sliced per query
    max_rounds: 1              # reserved for a future multi-round extension; only 1 is accepted today
```

`enabled` defaults on and doesn't need to be written out — omit the whole
`verification` block to accept the defaults above, or set `enabled: false`
to restore the old single-call flow byte-for-byte.

## Seeing it in a drill

`alertint drill` runs the exact same triage flow a real alert would — there
is no drill-specific code path. Its synthetic alerts carry fabricated
labels (`namespace=drill-shop`, `service=drill-checkout`, and similar) that
don't match anything in a real Prometheus, so the peer-scope up ratio
typically comes back "(no data)" rather than a real ratio. That's not a
degraded round — an empty result still counts as an answer, just an
uninformative one — and it's a correct demonstration of the same round a
production incident goes through: the drill's finding still carries a
`verification` section you can inspect over MCP.

## Kill-switch

Setting `triage.verification.enabled: false` restores the pre-verification
flow: one LLM call, no floor queries, no `unverified` caveat, memory
verdicts requested and read from that single call as before. Nothing else
about the pipeline changes — correlation, enrichment, recurrence collapse,
and notification are all unaffected by this flag.
