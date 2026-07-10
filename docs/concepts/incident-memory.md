---
title: "Incident memory"
description: "How AlertINT remembers recurring conditions — collapsing repeats and recalling prior findings into new analyses."
section: "Concepts"
order: 4
slug: "incident-memory"
---

# Incident memory

An unchanged, already-analyzed condition should not be re-triaged as if it were
brand new. A backup job that fills a disk to 90% every night, or a quota that
exhausts in a burst of near-identical alerts, used to cost a fresh LLM analysis
and a fresh notification every single time. **Incident memory** stops that in two
complementary ways: it *collapses* repeats of a condition, and it *recalls* what
was concluded last time into the next analysis.

Both are deterministic, cost nothing extra, and are on by default. Tune them
under the [`memory`](../getting-started/configuration.md#memory) config block.

## Recurrence collapse

When a firing alert's group key matches an already-analyzed incident and lands
inside the **collapse horizon**, AlertINT attaches it as an **occurrence** of
that incident instead of minting a new one and spending another analysis. The
incident's Slack card edits in place — `recurred ×N · last HH:MM` — and a JSON
occurrence line is written to stdout. No second LLM call.

The horizon is two clocks: a sliding attach window (default 30 minutes from the
last occurrence) and a hard ceiling on the time since the last analysis (default
4 hours). A **re-judgment** — a fresh analysis whose finding replaces the old one
in place — runs only when an escalation trigger fires: a severity rise, a new
alert type joining the incident, a cadence spike, or a time/occurrence ceiling.
The occurrence ledger is what makes "how often, and since when?" answerable, so
the recurrence count and cadence a recall shows are computed facts, never guesses.

## Memory recall

When a *new* incident's key matches a past analysis — the same condition
recurring after the collapse horizon has closed, or a closely related one — the
prior findings are injected into the new analysis as a **memory** section, beside
the live logs, changes, and error-source sections. The model judges the incident
with "we have seen this before" in hand.

### What gets recalled

Recall carries a small, fixed set of facts about each prior finding — the
incident it came from, when it was analyzed, its confidence, its root-cause
statement, and how many times the condition has recurred with what cadence. Same-
key priors fold into a single entry carrying the recurrence count and cadence;
at most a couple of weaker, related matches follow. Whole past findings and raw
alert labels never cross into the new prompt — only the distilled facts above.

### Recalled findings are hypotheses, not evidence

A recalled finding is a *past hypothesis*, not a verified fact and not live
evidence. It renders under an explicit notice saying exactly that, and it never
counts toward the analysis's evidence basis: an annotations-only re-fire is still
held to the metadata-only confidence ceiling even when the recalled prior was
highly confident. Yesterday's confidence cannot be smuggled into today's
evidence-free re-fire.

### Confirm and refute — memory that corrects itself

Each analysis that sees a recalled root cause returns a verdict on it —
*confirms*, *refutes*, or *silent*. A cause that is refuted twice is demoted, so
a newer finding displaces a stale one instead of the first mistake hardening
forever. The verdict is advisory bookkeeping: a missing or malformed verdict is
treated as silent and never blocks a good analysis.

### Disposition

If a recalled finding pointed at a specific application error, AlertINT makes one
bounded check of that error's current status at analysis time. An error that was
resolved but is firing again reads as a likely **regression**; one that is
ignored reads as **known-tolerated**. The check is best-effort — if the status
cannot be read, the recall proceeds with a short "status unavailable" note.

## Inspecting what the model saw

The memory a given analysis saw is visible over MCP: the get-incident payload
carries a `memory` block with the same recurrence count, cadence, and prior-
finding references the analysis was given. What the operator inspects and what the
model saw are computed by one method, so they cannot drift.

## Measuring memory

Every collapse and every recall lands a count-shaped row in the hash-chained
audit log, so the numbers that matter are plain SQL over `audit_log` — no metrics
endpoint required.

Analyses avoided by collapse (plain attaches that spent no LLM call):

```sql
SELECT COUNT(*) AS analyses_avoided
FROM audit_log
WHERE kind = 'incident.occurrence_attached'
  AND json_extract(payload_json, '$.trigger') = 'none';
```

How often recall fired, and how the recalled causes held up (the flywheel signal
— a healthy memory confirms far more than it refutes):

```sql
SELECT json_extract(payload_json, '$.verdict') AS verdict, COUNT(*) AS n
FROM audit_log
WHERE kind = 'incident.memory_recalled'
GROUP BY verdict;
```

Recall coverage — how many analyses were given prior context:

```sql
SELECT COUNT(DISTINCT json_extract(payload_json, '$.incident_id')) AS analyses_with_recall
FROM audit_log
WHERE kind = 'incident.memory_recalled';
```

## Shadow classifier

Recall matches on the **verbatim** group key. When the key misses but a prior
finding is only one group-label value away — the same `cluster` and `namespace`,
a different `service` — the deterministic prefilter still surfaces it as a weak
"one label off" signal. Whether that weak signal is *actually* the same
underlying condition is a fuzzy judgment, and the **shadow classifier** is the
optional, opt-in way to make it: one small extra Haiku call that answers a single
question — "same underlying condition?" — for the top weak candidate.

It renders only the structured group-key delta (the shared labels and the one
that differs) plus a short, capped summary of the prior hypothesis — never raw
alert labels — so the call is ~250 tokens, roughly **$0.0003 on Haiku**. The
verdict enum is fail-open (`matched` / `no-match` / `unsure-timeout` /
`unsure-error`): a timeout or a malformed reply can never produce a match.

The classifier ships **dark**, governed by one knob,
[`memory.classifier.mode`](../getting-started/configuration.md#memory):

- **`off`** (default) — no call is ever made.
- **`shadow`** — the call runs and every verdict lands in the audit log
  (`memory.classifier_verdict`), but the analysis prompt is **byte-identical** to
  the deterministic recall. Nothing the model sees changes; you are only
  gathering evidence.
- **`on`** — a `matched` verdict tags the recalled candidate
  "LLM-matched, probably related" in the analysis prompt.

### Graduating from shadow to on

Because AlertINT is self-hosted with no telemetry, the only evidence that the
classifier is accurate enough lives in **your** audit log. Fuzzy-match quality is
per-shop — it depends on your alert-naming vocabulary — so graduation is a local
decision, not a vendor default. Run `shadow` for a few weeks, then check its
precision: join each `matched` verdict to the confirm/refute ground truth that
memory recall already records (`memory_verdict`) for the same prior when it later
surfaces as an exact-key recall.

```sql
-- Shadow-classifier precision: of the weak candidates it called `matched`,
-- how many were later confirmed vs refuted by a full analysis (ground truth).
-- Graduate off → on once precision ≥ 0.90 over ≥ 100 matched verdicts (ADR-0018).
SELECT
  SUM(json_extract(v.payload_json, '$.verdict') = 'confirms') AS confirmed,
  SUM(json_extract(v.payload_json, '$.verdict') = 'refutes')  AS refuted,
  ROUND(
    1.0 * SUM(json_extract(v.payload_json, '$.verdict') = 'confirms')
        / NULLIF(COUNT(*), 0), 2) AS precision
FROM audit_log c
JOIN audit_log v
  ON  v.kind = 'incident.memory_recalled'
  AND json_extract(v.payload_json, '$.recalled')
      = json_extract(c.payload_json, '$.candidates[0]')
  AND json_extract(v.payload_json, '$.verdict') IN ('confirms', 'refutes')
WHERE c.kind = 'memory.classifier_verdict'
  AND json_extract(c.payload_json, '$.verdict') = 'matched';
```

Flipping to `on` before the gate is met is your prerogative — your key, your
render — but it is not recommended. The vendor never flips a render remotely.

## Configuration

Both halves share the [`memory`](../getting-started/configuration.md#memory)
config block. Recall reuses the same `lookback_days` horizon as the occurrence
ledger. The recurrence key is the verbatim group key with no normalization, so
grouping on volatile labels (a pod name, a job id) makes a condition rarely
repeat — `alertint validate` warns when a group label looks volatile.
