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
runs the same bounded shape on every judged triage, never more than a second
call and a capped batch of read-only queries. Open-ended, hypothesis-chasing
investigation stays where it already lived — at the MCP layer, driven by a
human or a connected agent.

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

**Call 2** is a full continuation of call 1 — the same prompt prefix, the
draft as the model's own prior turn, then every query's result appended
verbatim. The instruction is explicit: verification results outrank the
draft, the evidence pack, and any recalled memory. If the checks contradict
the draft, revise; don't defend it. The result is the finding that persists —
confidence caps and the memory verdict apply to this final judgment, not the
draft.

## Cost

Judged incidents go from one LLM call to two, plus at most six read-only
queries (the two-query floor plus up to four model-chosen checks by
default). This lands after [recurrence collapse](incident-memory.md) has
already cut incident *volume* — a steady flapper that used to spend a fresh
analysis on every re-fire spends none, so the extra call per judged incident
isn't multiplied by every recurrence, only by genuinely new or escalated
conditions.

The second call also costs less than it looks: it reuses the first call's
prompt verbatim as an Anthropic prompt-cache prefix, so the shared span
(system prompt plus evidence) is written to the cache on call 1 and read back
at roughly a tenth of the input price seconds later on call 2. `llm.response`
audit rows carry the raw numbers — `cache_creation_input_tokens` and
`cache_read_input_tokens`; effective input cost is
`input + 1.25 × creation + 0.10 × read`. Caching engages only when the prefix
clears the model's minimum cacheable size (model-dependent; small incidents on
`claude-haiku-4-5` typically don't) — when the re-judge call reads no cached
tokens, the agent logs a warning naming the likely cause. Worst case is
today's cost, never more. With verification disabled, requests are unchanged
and nothing is cached.

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
recurrence flywheel is only ever fed by contrast-checked judgments. A failed
*model-chosen* query alone doesn't degrade the round; the floor is the
promised minimum, and targeted queries are bonus precision on top of it.

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
