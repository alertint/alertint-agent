# Plan 2 lab acceptance — Situation controller / Acute Triage coordination

**Status: structure only — TODO.** This file's evidence table is a
*structure*, seeded by Task 10 (`test(situation): prove controller crash
boundaries`) alongside the real-store replay fixture
(`controller_replay_test.go`) and this task's docs updates. It does **not**
yet contain lab evidence: every data cell below is a placeholder. The
follow-on lab-deployment step (a separate, carefully-scoped dispatch —
`task lab:agent:snapshot` / `task lab:agent:ship` / `task lab:agent:switch` /
`task lab:check` / `task lab:pause`, then firing real drill scenarios against
the lab VPS) fills in every `TODO` cell with real evidence gathered from the
live lab tenant, and that second pass is the one that actually closes this
document out.

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
   `audit_log`), `task lab:logs`, and the configured OTel backend for the
   trace/span IDs covering the same cycle.
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
