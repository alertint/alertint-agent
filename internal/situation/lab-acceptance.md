# Plan 2 lab acceptance — Situation controller / Acute Triage coordination

**Status: structure only in this file — the lab step has run.** This
file's evidence table is a *structure*, seeded by Task 10 (`test(situation):
prove controller crash boundaries`) alongside the real-store replay fixture
(`controller_replay_test.go`). It deliberately carries no lab evidence
(no Situation/Incident IDs, digests, or audit sequence numbers); the
canonical, dated evidence record lives beside the Plan 2 spec in the
private planning directory (`02-controller-triage-coordination/
lab-acceptance.md`) and is what the completion gate reads.

State of that record as of 2026-09-04 (two lab runs against a fresh
database each, Slack disabled, stdout notifier on, spans exported to the
lab's own OpenTelemetry Collector): checks 1, 2, 3, 4, 5, 8 and 9 pass on
live evidence; check 7 passed on the first run's evidence (content-failure
class) and is to be repeated for the transport class; check 6 was not
reached (no in-flight Acute Triage attempt occurred in the window); check
10 agreed across audit, SQLite, logs and the collector's span metrics but
**failed on the MCP column** — the Situation read projected consumed Triage
attempts from the schedule row that a persisted Finding deletes. That
projection now reads the durable attempt ledger (`internal/store/
situation_views.go`) and is re-verified in the next run. The first run
also exposed that the L2 prompt never stated the nested proposal shapes,
so every proposal was rejected and the controller fell back
deterministically as designed; fixed in `assessment_prompt.go` before the
second run.

Do not fill in a cell with a guess, an extrapolation from the local replay
run, or a number that cannot be independently re-verified from the lab
tenant's own durable state. In particular: **never claim an unverifiable
provider receipt count.** Every "consumed L2 dispatch slots" / "consumed
Triage attempts" figure below must be read back from
`situation_assessment_calls`, `situation_assessment_attempts`, and
`incident_triage` (attempts) directly — not asserted from memory of how many
calls a drill "should" have made — and cross-checked against the same
Situation/Incident's own audit trail, MCP read, and OTel trace before the row
is marked `pass`.

## How to fill this in (lab-deployment step)

For each of the ten checks below, once the corresponding drill/scenario has
run against the lab tenant:

1. Identify the exact Situation ID(s) and Incident ID(s) the check exercised.
2. Read the durable state directly: `alertint_get_situation` /
   `alertint_get_incident` over MCP, a read-only `sqlite3` query against the
   lab database (`situations`, `situation_assessment_attempts`,
   `situation_assessment_calls`, `incident_triage`, `situation_facts`,
   `audit_log`), `task lab:logs` (the per-cycle log lines carry the
   trace/span IDs), and the lab Prometheus span-metrics series the
   collector derives from the exported spans (see the OTel note below).
3. Record every column with the exact value read back — not a paraphrase.
4. Set **Result** to `pass` only once every column is filled with real,
   cross-checked evidence and the check's own pass condition (stated in its
   row) holds; otherwise `fail` with a one-line reason in **Evidence
   location**, or leave `TODO` if the check has not been run yet.
5. Record **Date** as the UTC date the evidence was actually gathered (not
   the date this structure was created).

## Evidence table

| # | Check | Date (UTC) | Situation ID | Incident ID(s) | Input version | Material fact hash | Assessment basis hash | Membership digest | Incident-input digest | Assessment derivation | Triage phase | Consumed L2 dispatch slots | Consumed Triage attempts | Audit IDs | OTel trace ID | OTel span ID | Restart point | Result | Evidence location |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Receiver-to-Situation | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |
| 2 | Within-class hash stability | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |
| 3 | Unchanged-basis L2 reuse | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |
| 4 | Deterministic request/skip | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |
| 5 | Same-key attachment until first judgment | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |
| 6 | Finding/Triage restart without another consumed Acute Triage attempt | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO |
| 7 | Deterministic L2 fallback | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |
| 8 | Stale-claim rejection | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |
| 9 | Concurrent due/checkpoint preservation | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |
| 10 | Agreement across MCP/audit/SQLite/logs/OTel | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | TODO | n/a | TODO | TODO |

## Per-check pass condition (for the lab-deployment step to evaluate against)

1. **Receiver-to-Situation.** A real Alertmanager (or Zabbix) webhook POST
   against the lab tenant durably produces a Situation with a due reason,
   with no hand-seeded row anywhere in the chain — confirmed by reading the
   Situation back over MCP and by a direct SQLite read of `situations` and
   `situation_input_outbox`.
2. **Within-class hash stability.** Two reconcile cycles of the same
   unchanged input (same duration class, same membership) produce byte-
   identical `current_material_fact_hash`/`current_assessment_basis_hash`.
3. **Unchanged-basis L2 reuse.** A reconcile cycle against an unchanged,
   trustworthy basis consumes zero L2 dispatch slots (no new row in
   `situation_assessment_calls`) yet still writes a fresh input-bound
   `situation_assessment_attempts` row with `derivation = 'revalidated_reuse'`.
4. **Deterministic request/skip.** `catalog-failure`/`payment-failure` (or
   equivalent) drills produce the expected `request`/`skip` Triage decisions,
   reproducibly, for the same Incident state.
5. **Same-key attachment until first judgment.** A same-key repeat fired
   before an Incident's first judgment attaches as membership on the
   existing Incident/Triage schedule rather than minting a new one or
   accelerating the due time.
6. **Finding/Triage restart without another consumed Acute Triage attempt.**
   A controlled process restart mid-Triage-attempt (`task lab:fire` followed
   by a restart during the attempt window) recovers cleanly on the next
   `RunOnce`/`Drain` pass, and the eventual Finding is produced by exactly
   one *effective* consumed Acute Triage attempt (the interrupted attempt is
   recorded as failed/backed-off, never silently repeated as a second billed
   attempt for the same due work).
7. **Deterministic L2 fallback.** With the configured LLM made unavailable
   (or via a drill that forces an L2 failure) and no trustworthy prior
   Assessment, the controller commits a deterministic fallback Assessment —
   never a stale/absent one — and Attention is forced `urgent` when the
   deterministic floor applies.
8. **Stale-claim rejection.** A reconcile cycle whose claim has been
   superseded by a concurrent newer input fails closed
   (`ErrSituationVersionConflict`/`ErrSituationLeaseLost`) rather than
   committing — confirmed via the audit log's `situation.controller.
   commit_failed` row and the fact that the newer input's own due reason
   survives.
9. **Concurrent due/checkpoint preservation.** A concurrent Situation input
   arriving mid-cycle is never lost: its due reason (and any earlier
   checkpoint) survives a stale-claim rejection and is picked up by the next
   cycle — confirmed by comparing `due_reasons_json`/`next_assessment_at`
   before and after.
10. **Agreement across MCP/audit/SQLite/logs/OTel.** For one representative
    Situation/Incident pair, the consumed L2 dispatch slot count and
    consumed Triage attempt count read identically from: `alertint_get_
    situation`/`alertint_get_incident` (MCP), `alertint_verify_audit` (audit
    log), a direct read-only SQLite query, `task lab:logs`, and the
    configured OTel backend's trace/span attributes for the same cycle.

## Notes

- Check 8 (stale-claim rejection) covers a lease that changes hands
  *between* cycles. The harder variant — a lease lost *mid-cycle* with no
  process restart (heartbeat `ExtendControllerLease` failure cancelling the
  in-flight reconcile after the L2 dispatch row is durable but before
  `CommitController`; a stall outliving the 300s lease; a `CommitController`
  error) used to let the next claimant re-mint the stranded call's own
  `(retry_epoch, work_attempt, call_number)` and collide on
  `situation_assessment_calls`' UNIQUE index, wasting one cycle on a
  `deterministic_fallback` Assessment, because `RecoverInterruptedAssessmentCalls`
  is startup-only and never ran. `BeginControllerAttempt` now reconciles
  against the dispatched-call ledger inside its own fenced claim
  transaction, so this needs no restart and no lab step: it is pinned by
  `TestControllerAttemptHealsStrandedDispatchWithoutRestart` and its
  siblings in `internal/store/situation_controller_test.go`, which drive
  the exact worker-A-dispatch / lease-expired / worker-B-claim sequence
  against the real schema. Known, accepted edge: a stranded *fifth* attempt
  leaves the Situation exhausted for that basis with no park marker until
  the basis changes — identical to what the startup recovery pass already
  produces for the same crash, not a new behaviour.
- **OTel columns (check 10).** The controller and Triage worker emit the
  three spans `docs/concepts/architecture.md#3a` names, with the attributes
  check 10 cross-checks (Situation/Incident/attempt IDs, input version,
  hashes, digests, dispatch slot, attempt number, result class, duration)
  — pinned by `internal/situation/telemetry_test.go` against an in-memory
  span recorder — and export them over OTLP when the lab config enables
  `telemetry.otlp` (`docs/getting-started/configuration.md#telemetry`),
  pointed at the lab's own OpenTelemetry Collector. The lab collector's
  traces pipeline feeds its span-metrics connector only (there is no trace
  store in the lab), so the two OTel columns are filled from two places
  that must agree: the **trace/span IDs** come from the agent's own
  structured log lines for that cycle (`situation: controller reconcile`,
  `situation: assessment dispatch`, `situation: triage worker: attempt
  finished` — each carries `trace_id`/`span_id` next to the Situation/
  Incident/attempt IDs), and the **consumed counts** come from the
  collector-derived series in the lab Prometheus, e.g.
  `traces_span_metrics_calls_total{service_name="alertint-agent",
  span_name="situation.assessment.dispatch"}` and
  `{span_name="incident.triage.attempt"}`, whose deltas over the drill
  window must equal the `situation_assessment_calls` /
  `incident_triage_attempts` row counts read back from SQLite. A span
  count that disagrees with the ledger is a `fail`, not a rounding note.
  Do not fill those columns from the unit test — they are for IDs and
  counts read back from the live lab.
- **Clean skip (checks 4 and 6).** A below-minimum-member Incident is
  clean-skipped by the Triage worker BEFORE any attempt claim
  (`CleanSkipIncidentTriageBelowMinimumMembers`): the schedule closes to
  `skipped`, `incident_triage.attempts` stays at its pre-skip value, and
  `incident_triage_attempts` gains no row. When reading back "consumed
  Triage attempts" for a skipped Incident, expect zero for that skip; a
  nonzero count there is a regression, not evidence.
- **Installation LLM health (check 7).** The `assessment` capability under
  `/health` reflects the controller's *classified* L2 outcome — a malformed
  or policy-rejected proposal is a content failure (unhealthy only once two
  distinct Situations corroborate it), a transport failure is unhealthy at
  once, a stale-basis discard is a success. When forcing an L2 failure for
  check 7, record which class the health snapshot reported alongside the
  fallback Assessment.
- `notify.slack.enabled` must read `false` and stdout must read enabled in
  the lab config before any of the above is exercised — verified by the
  lab-deployment step before firing anything, and re-confirmed by "exactly
  zero Slack messages" once every check has run.
- This structure intentionally never lists "provider receipt count" as a
  column: the spec's own instruction is "do not claim unverifiable provider
  receipt counts" — every consumed-slot/attempt figure here is read from
  this system's own durable ledger (`situation_assessment_calls`,
  `situation_assessment_attempts`, `incident_triage`), never from an
  external provider dashboard or invoice this system cannot itself verify.
- See `docs/concepts/architecture.md#3a-situation-foundation-and-controller`
  for what "wired" vs. "not yet" means at the time this structure was
  created, and `doctopus/agents/alertint-agent/planning/2026-08-19-proactive-
  situation-controller/02-controller-triage-coordination/spec.md` for this
  table's own ground-truth source.
