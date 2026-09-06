// SPDX-License-Identifier: FSL-1.1-ALv2

// package situation_test (external test package) — see
// controller_replay_test.go's own header for the import-cycle constraint
// that forces every real-Store replay fixture in this package to live
// outside `package situation`.
//
// Plan 3 Task 10, Step 1: real-Store crash-boundary replay proof for
// Situation HISTORY. controller_replay_test.go already proves Plan 2's
// controller/Triage convergence across nine crash boundaries; this file
// reuses that file's fixture (replayFixture), its fault-injecting
// faultyControllerStore decorator, its crash points, and its
// simulateCrash harness verbatim — never a second harness — and extends
// them along the one axis Plan 3 added: the immutable Transition ledger,
// the versioned Episode-summary projection, the durable notification
// intents, the persisted Slack root coordinates, and the Delivery-gap
// generations.
//
// Every scenario below runs TWICE against two independent on-disk
// databases, through the same script:
//
//   - the reference run restarts (close/reopen/advance) at each scripted
//     boundary but never crashes;
//   - the replay run crashes at that same boundary — inside the fenced
//     controller commit, immediately after it, or between a delivery's
//     Slack call and its durable acknowledgement — then restarts and
//     replays.
//
// Both runs therefore see the IDENTICAL logical-clock schedule, so the
// only difference between them is the crash itself. (A reference run that
// simply never closed the database would drift on elapsed time, and
// elapsed time feeds DurationClass, which feeds MaterialFactHash — the
// comparison would then be measuring clock drift, not crash tolerance.
// See longClassMargin's own doc comment in controller_replay_test.go for
// the same hazard in Plan 2's fixture.)
//
// The two runs are then compared on canonicalHistory: the normalized,
// ID-independent projection of every Situation's Transition ledger,
// Episode summary, notification intents, root coordinates, and gap
// generations. Raw UUID/digest identities are normalized away (they are
// derived from the Situation ID, which differs between two independent
// databases by construction); everything an operator can actually observe
// — sequence, reason, journal kind, lifecycle, Attention, actor, poke
// authority, Interruption priority, intent status, summary version,
// whether a root is published — is compared verbatim.

package situation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Steerable L2 (Situation Assessment) client.
//
// controller_replay_test.go's newAcceptingL2Client always answers with the
// same observe-grade proposal, which is all Plan 2's convergence proofs
// needed. Plan 3's history catalog needs Attention to move and a
// Sufficient reason to be claimed, so this client reads the eligible
// reason candidates back out of the prompt the controller actually built
// (BuildAssessmentPrompt renders them into its snapshot body) and answers
// against them — exactly as a real model must, and with the same
// validation consequences: a candidate ID that is not in this snapshot's
// eligible_reasons is rejected as reason_id_unknown.
// ----------------------------------------------------------------------

// l2Script is what the fixture wants the next L2 answer to claim. The zero
// value is the plain observe-grade proposal newAcceptingL2Client returns.
type l2Script struct {
	// Attention the proposal claims. Empty means observe.
	//
	// Note: a snapshot carrying a deterministic floor candidate
	// (critical_anchor) has its Attention raised to urgent by
	// validateProposalContent regardless of what is claimed here, and a
	// claim of urgent WITHOUT such a floor is rejected outright
	// (urgent_without_floor). This field therefore only ever moves
	// Attention between observe and investigate.
	Attention situationmodel.Attention
	// ClaimNonFloorReason selects the first non-floor eligible candidate
	// the prompt offers, when one exists, as the proposal's Sufficient
	// reason. With Attention=investigate that is what makes the controller
	// derive an operator handoff (assessment.go's operatorActionRequired:
	// a validated, non-floor Sufficient reason accepted while Attention is
	// investigate).
	ClaimNonFloorReason bool
}

type steerableL2Client struct {
	t      *testing.T
	script func() l2Script
	calls  int
}

func newSteerableL2Client(t *testing.T, script func() l2Script) *steerableL2Client {
	t.Helper()
	return &steerableL2Client{t: t, script: script}
}

// promptSnapshotDTO is the narrow projection this client reads back out of
// the rendered prompt. It deliberately decodes only the two fields it
// needs — the prompt body carries the whole bounded snapshot, but a test
// client that decoded all of it would couple to every future snapshot
// field.
type promptSnapshotDTO struct {
	EligibleReasons []situationmodel.ReasonCandidate `json:"eligible_reasons"`
}

const promptSnapshotMarker = "Situation snapshot:\n"

// eligibleReasonsFromPrompt decodes the eligible reason candidates out of
// the prompt the controller built. json.Decoder stops at the end of the
// first complete JSON value, so the schema instructions that follow the
// snapshot body in the same prefix are simply never read.
func eligibleReasonsFromPrompt(t *testing.T, prompt llm.Prompt) []situationmodel.ReasonCandidate {
	t.Helper()
	idx := strings.Index(prompt.Prefix, promptSnapshotMarker)
	if idx < 0 {
		t.Fatalf("assessment prompt does not carry the %q marker; the prompt shape changed", promptSnapshotMarker)
	}
	var dto promptSnapshotDTO
	dec := json.NewDecoder(strings.NewReader(prompt.Prefix[idx+len(promptSnapshotMarker):]))
	if err := dec.Decode(&dto); err != nil {
		t.Fatalf("decode assessment prompt snapshot body: %v", err)
	}
	return dto.EligibleReasons
}

func (c *steerableL2Client) CompleteOnce(_ context.Context, _ string, prompt llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
	c.calls++
	script := c.script()

	proposal := situationmodel.AssessmentProposal{
		SchemaVersion: situationmodel.AssessmentSchemaVersion,
		Persistence:   situationmodel.PersistenceSustained,
		Impact:        situationmodel.ImpactSuspected,
		Novelty:       situationmodel.NoveltyFamiliar,
		Causality:     situationmodel.CausalityCorrelated,
		Attention:     situationmodel.AttentionObserve,
	}
	if script.Attention != "" {
		proposal.Attention = script.Attention
	}
	if script.ClaimNonFloorReason {
		for _, cand := range eligibleReasonsFromPrompt(c.t, prompt) {
			if cand.DeterministicFloor {
				continue
			}
			proposal.SufficientReason = &situationmodel.SufficientReason{
				Code:        cand.Code,
				CandidateID: cand.ID,
				Summary:     "Elapsed duration is a statistical outlier against this group's own history.",
				// Deliberately empty: every ref must exist in this exact
				// snapshot's facts, and the candidate's own refs are the
				// only set guaranteed to. Claiming none is always valid
				// and keeps this client independent of fact identity.
				EvidenceRefs: nil,
			}
			break
		}
	}

	raw, err := json.Marshal(proposal)
	if err != nil {
		c.t.Fatalf("marshal steered proposal: %v", err)
	}
	return llm.OneShotCompletion{
		Completion:     llm.Completion{Raw: raw, Model: "history-replay-model", Latency: 5 * time.Millisecond},
		RequestStarted: llm.RequestStartStatusTrue,
	}, nil
}

// ----------------------------------------------------------------------
// Notification delivery: a deterministic in-test deliverer plus the one
// extra crash boundary Plan 3 adds beyond Plan 2's controller boundaries —
// the process dying between a successful Slack call and the durable
// MarkNotificationDelivered that records its coordinates.
//
// This file's deliverer is intentionally trivial (it fabricates a
// coordinate, it renders nothing). Step 2's fake-Slack end-to-end test
// drives the REAL cmd/alertint SituationDeliverer against a real
// slack.Client and an httptest Slack server; this fixture's job is the
// STORE side of the boundary — what survives a crash and what replay
// converges to — which is exactly what a rendering-free deliverer isolates.
// ----------------------------------------------------------------------

type replayDeliverer struct {
	// crashAfterCall makes Deliver panic AFTER it has decided its result
	// but BEFORE returning it to the worker — modeling "Slack accepted the
	// call, the process died before the acknowledgement was durable."
	crashAfterCall bool
	posted         []string
	seq            int
}

func (d *replayDeliverer) Probe(context.Context) error { return nil }

func (d *replayDeliverer) Deliver(_ context.Context, intent situationmodel.NotificationIntent) (situation.NotificationDelivery, error) {
	d.seq++
	d.posted = append(d.posted, intent.ClientMessageID)
	delivery := situation.NotificationDelivery{
		Channel:     "C-REPLAY",
		MessageTS:   fmt.Sprintf("17000000%02d.000100", d.seq),
		DeliveredAs: deliveredAsFor(intent.EffectClass),
	}
	if d.crashAfterCall {
		panic(replayCrash{boundary: crashBoundaryDeliveryAcknowledgement})
	}
	return delivery, nil
}

const crashBoundaryDeliveryAcknowledgement = "crash_after_slack_call_before_durable_acknowledgement"

func deliveredAsFor(class situationmodel.EffectClass) string {
	switch class {
	case situationmodel.EffectRootSync:
		return "root"
	case situationmodel.EffectBroadcastHandoff:
		return "broadcast"
	case situationmodel.EffectInstallationGapRecovery:
		return "system"
	case situationmodel.EffectThreadAppend:
		return "thread"
	default:
		return "thread"
	}
}

// ----------------------------------------------------------------------
// historyFixture: replayFixture plus the Plan 3 driving surface.
// ----------------------------------------------------------------------

type historyFixture struct {
	*replayFixture

	script    l2Script
	deliverer *replayDeliverer
	// crashAt names the boundary this run crashes at, or "" for the
	// reference (restart-only) run.
	crashAt crashPoint
	// crashDelivery makes the next delivery round crash between the Slack
	// call and its durable acknowledgement.
	crashDelivery bool
}

func newHistoryFixture(t *testing.T, owner string, crashAt crashPoint, crashDelivery bool) *historyFixture {
	t.Helper()
	return &historyFixture{
		replayFixture: newReplayFixture(t, owner),
		deliverer:     &replayDeliverer{},
		crashAt:       crashAt,
		crashDelivery: crashDelivery,
	}
}

func (f *historyFixture) l2() *steerableL2Client {
	return newSteerableL2Client(f.t, func() l2Script { return f.script })
}

// postAlert POSTs one Alertmanager v4 alert over real HTTP through the real
// Receiver, with an explicit status and severity label — replayFixture's own
// postGroup always posts a firing alert with no severity, which is all Plan
// 2's fixture needed. Severity matters here because a critical-severity
// delivery makes critical_anchor eligible, which is a DETERMINISTIC FLOOR:
// validateProposalContent then raises Attention to urgent unconditionally,
// and operatorActionRequired never fires for a floor candidate — so the
// handoff scenario must post a non-critical alert.
//
//nolint:unparam // alertname is a general fixture parameter; every current scenario happens to use "HighLatency".
func (f *historyFixture) postAlert(group, alertname, fingerprint, status, severity string) {
	f.t.Helper()
	labels := map[string]string{"alertname": alertname, "group": group}
	if severity != "" {
		labels["severity"] = severity
	}
	alert := map[string]any{
		"status":      status,
		"labels":      labels,
		"annotations": map[string]string{},
		"startsAt":    f.clock.Now().Format(time.RFC3339Nano),
		"fingerprint": fingerprint,
	}
	if status == "resolved" {
		alert["endsAt"] = f.clock.Now().Format(time.RFC3339Nano)
	}
	f.postJSON(map[string]any{
		"version":     "4",
		"status":      status,
		"groupLabels": map[string]string{"group": group},
		"alerts":      []map[string]any{alert},
	})
}

func (f *historyFixture) postJSON(payload map[string]any) {
	f.t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		f.t.Fatalf("marshal alertmanager payload: %v", err)
	}
	req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.srv.URL+"/webhook/alertmanager", bytes.NewReader(body))
	if err != nil {
		f.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+replayToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := f.srv.Client().Do(req)
	if err != nil {
		f.t.Fatalf("post alert: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNoContent {
		f.t.Fatalf("post alert status = %d, want 204", resp.StatusCode)
	}
}

// converge runs one full quiescence pass: dispatch/input/controller/Triage
// (replayFixture.convergeAll) followed by delivery rounds until the
// notification ledger is quiescent too.
// converge drives the whole pipeline to quiescence at Plan 2's own
// convergeAll definition (a round that dispatched, applied, reconciled, and
// triaged nothing), then drains delivery. Every warranted scenario here
// runs at observe Attention on the slow cadence (openWarrantedSituation),
// so a round with nothing due is reachable.
func (f *historyFixture) converge() {
	f.t.Helper()
	f.convergeAll(f.l2(), newAcceptingAnalyzer(), &countingAfterCommitter{}, nil)
	f.deliver()
}

// oneRound runs exactly ONE dispatch/input/controller/Triage pass at one
// clock step, then delivers. converge() loops to quiescence, which
// repeatedly advances the clock — enough, on a recovery-pending Situation,
// to run the 120s recovery grace out and terminalize it before the scenario
// meant to. A scenario that needs to observe an intermediate lifecycle
// state (recovery_pending before a refire; a nonterminal owner before an
// artifact is applied) steps it one round at a time instead.
func (f *historyFixture) oneRound() {
	f.t.Helper()
	f.oneControllerDrainPass(f.l2())
	f.deliver()
}

// deliver drains the notification ledger with the real
// situation.NotificationWorker against the real *store.Store, honoring this
// fixture's own delivery crash boundary exactly once.
func (f *historyFixture) deliver() {
	f.t.Helper()
	// The crash boundary sits BETWEEN a Slack call and its acknowledgement,
	// so it can only be exercised by a round that actually makes one. Arm
	// it on the first round with a claimable intent; runHistoryScenario
	// fails a scenario that never produced one.
	if f.crashDelivery && f.claimableIntents() > 0 {
		f.crashDelivery = false
		f.deliverer.crashAfterCall = true
		simulateCrash(f.t, crashBoundaryDeliveryAcknowledgement, func() {
			_, _ = f.newNotificationWorker().RunOnce(f.ctx)
		})
		f.deliverer.crashAfterCall = false
		f.restartAndReplay()
	}
	for round := 0; round < 8; round++ {
		n, err := f.newNotificationWorker().RunOnce(f.ctx)
		if err != nil {
			f.t.Fatalf("notification worker round: %v", err)
		}
		if n == 0 {
			return
		}
	}
	f.t.Fatal("deliver: notification ledger did not reach quiescence within bounded rounds")
}

// claimableIntents counts pending intents that are due now and, for a
// reply, whose root is published — what one worker round could deliver.
func (f *historyFixture) claimableIntents() int {
	f.t.Helper()
	return scalarInt(f.t, f.st, `
		SELECT COUNT(*) FROM notification_intents ni
		LEFT JOIN situations s ON s.id = ni.situation_id
		WHERE ni.status = 'pending'
		  AND (ni.retry_at IS NULL OR ni.retry_at <= ?)
		  AND (ni.requires_root = 0 OR s.slack_root_ts IS NOT NULL)`,
		f.clock.Now().UTC().Format(time.RFC3339Nano))
}

func (f *historyFixture) newNotificationWorker() *situation.NotificationWorker {
	return situation.NewNotificationWorker(f.st, f.deliverer,
		situation.NotificationWorkerConfig{Owner: f.owner + ":notify"}, f.clock.Now, nil)
}

// crashControllerCycle claims exactly one due Situation and crashes the
// controller at this fixture's armed boundary while reconciling it, then
// restarts and replays. It is a no-op for the reference run (crashAt == "")
// beyond the restart itself, so both runs see the same clock schedule.
func (f *historyFixture) crashControllerCycle() {
	f.t.Helper()
	if f.crashAt == "" {
		f.restartAndReplay()
		return
	}
	f.clock.Advance(advanceMargin)
	claims, err := f.st.ClaimControllerWork(f.ctx, f.owner+":controller", f.clock.Now(), 300*time.Second, 1)
	if err != nil {
		f.t.Fatalf("claim controller work: %v", err)
	}
	if len(claims) == 0 {
		// Nothing is due at this point in the script; the crash boundary
		// simply does not arise here. The restart still happens so the two
		// runs stay clock-identical.
		f.restartAndReplay()
		return
	}
	faulty := &faultyControllerStore{Store: f.st, armed: f.crashAt}
	controller := situation.NewController(faulty, f.l2(), situation.ControllerConfig{},
		f.clock.Now, audit.New(f.st.DB()), nil)
	simulateOptionalCrash(f.t, string(f.crashAt), func() {
		_ = controller.Reconcile(f.ctx, claims[0])
	})
	f.restartAndReplay()
}

// simulateOptionalCrash is simulateCrash's scenario-driven sibling. Whether
// a given cycle reaches a given fault site is a property of the SCENARIO,
// not of the code under test: a reuse cycle dispatches no L2 call at all,
// so crashPointRecordAssessmentCall simply never fires in one. Reaching it
// is therefore not required — the cycle completing normally is a legitimate
// outcome, and the scenario then continues as a restart-only run, which
// must still converge to the same canonical history.
//
// What is NOT tolerated is a panic that is not our own sentinel: exactly
// like simulateCrash, a genuine bug in the code under test is re-panicked,
// never swallowed.
func simulateOptionalCrash(t *testing.T, boundary string, fn func()) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		rc, ok := r.(replayCrash)
		if !ok || rc.boundary != boundary {
			panic(r)
		}
	}()
	fn()
}

// restartAndReplay is the shared close/reopen/advance + real startup
// recovery sequence both runs perform at every scripted boundary.
func (f *historyFixture) restartAndReplay() {
	f.t.Helper()
	f.restart()
	f.bootReplay()
}

// ----------------------------------------------------------------------
// Canonical, ID-independent history state.
// ----------------------------------------------------------------------

// canonicalHistory renders every operator-observable Plan 3 record in this
// database as a normalized, comparable text block. Situation IDs are
// replaced by stable ordinals (S1, S2, ...) in creation order and derived
// identities (Transition IDs, intent IDs, idempotency keys, client message
// IDs, Slack timestamps) are omitted, because all of them are digests of
// the Situation ID and so differ by construction between two independent
// databases. Everything else is compared verbatim.
func canonicalHistory(t *testing.T, st *store.Store) string {
	t.Helper()
	ctx := context.Background()
	ordinals := map[string]string{}
	sits := canonicalSituationRows(t, st, ctx)
	lines := make([]string, 0, 8*len(sits)+1)

	for i, s := range sits {
		ordinals[s.id] = fmt.Sprintf("S%d", i+1)
	}
	for _, s := range sits {
		lines = append(lines, fmt.Sprintf("situation %s group=%s lifecycle=%s attention=%s terminal_reason=%s current_sequence=%d root_published=%d",
			ordinals[s.id], s.group, s.lifecycle, s.attention, s.terminalReason, s.seq, s.rooted))
		lines = append(lines, canonicalTransitions(t, st, ordinals[s.id], s.id)...)
		lines = append(lines, canonicalEpisode(t, st, ordinals[s.id], s.id)...)
		lines = append(lines, canonicalIntents(t, st, ordinals[s.id], s.id)...)
		lines = append(lines, canonicalArtifactInputs(t, st, ordinals[s.id], s.id)...)
	}
	lines = append(lines, canonicalInstallationDelivery(t, st)...)
	return strings.Join(lines, "\n")
}

// canonicalSituationRow is one Situation's own normalized header line data.
type canonicalSituationRow struct {
	id, group, lifecycle, attention, terminalReason string
	seq, rooted                                     int
}

func canonicalSituationRows(t *testing.T, st *store.Store, ctx context.Context) []canonicalSituationRow { //nolint:revive // ctx after t matches this file's own testing-helper convention.
	t.Helper()
	rows, err := st.DB().QueryContext(ctx,
		`SELECT id, group_key, lifecycle, attention,
		        COALESCE(terminal_reason,''), current_transition_sequence,
		        CASE WHEN slack_channel IS NULL THEN 0 ELSE 1 END
		   FROM situations ORDER BY created_at ASC, id ASC`)
	if err != nil {
		t.Fatalf("read situations: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []canonicalSituationRow
	for rows.Next() {
		var s canonicalSituationRow
		if err := rows.Scan(&s.id, &s.group, &s.lifecycle, &s.attention, &s.terminalReason, &s.seq, &s.rooted); err != nil {
			t.Fatalf("scan situation: %v", err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate situations: %v", err)
	}
	return out
}

func canonicalTransitions(t *testing.T, st *store.Store, ordinal, situationID string) []string {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT sequence, reason, journal_kind, lifecycle, attention, actor,
		        COALESCE(interruption_priority,''), drill,
		        CASE WHEN operator_artifact_input_id IS NULL THEN 0 ELSE 1 END,
		        COALESCE(json_extract(journal_json,'$.headline'),''),
		        COALESCE(json_extract(action_contract_json,'$.next_actor'),''),
		        COALESCE(json_extract(action_contract_json,'$.alertint_action'),''),
		        COALESCE(json_extract(action_contract_json,'$.operator_action_required'),'')
		   FROM situation_transitions WHERE situation_id = ? ORDER BY sequence ASC`, situationID)
	if err != nil {
		t.Fatalf("read transitions: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var seq, drill, artifact int
		var reason, kind, lifecycle, attention, actor, priority, headline string
		var nextActor, alertintAction, operatorAction string
		if err := rows.Scan(&seq, &reason, &kind, &lifecycle, &attention, &actor, &priority, &drill, &artifact,
			&headline, &nextActor, &alertintAction, &operatorAction); err != nil {
			t.Fatalf("scan transition: %v", err)
		}
		out = append(out, fmt.Sprintf("  transition %s#%d reason=%s journal=%s lifecycle=%s attention=%s actor=%s priority=%s drill=%d artifact=%d next_actor=%s alertint_action=%s operator_action=%s headline=%q",
			ordinal, seq, reason, kind, lifecycle, attention, actor, priority, drill, artifact,
			nextActor, alertintAction, operatorAction, headline))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate transitions: %v", err)
	}
	return out
}

func canonicalEpisode(t *testing.T, st *store.Store, ordinal, situationID string) []string {
	t.Helper()
	row := st.DB().QueryRowContext(context.Background(),
		`SELECT version, source_transition_sequence,
		        json_extract(summary_json,'$.current_attention'),
		        json_extract(summary_json,'$.peak_attention'),
		        json_extract(summary_json,'$.investigation_started'),
		        json_extract(summary_json,'$.recurrence_count'),
		        COALESCE(json_extract(summary_json,'$.initial_publication_reason'),''),
		        COALESCE(json_extract(summary_json,'$.latest_material_reason'),''),
		        COALESCE(json_extract(summary_json,'$.final_outcome'),''),
		        COALESCE(json_extract(summary_json,'$.remaining_uncertainty'),''),
		        COALESCE(json_array_length(summary_json,'$.investigation_work'),0),
		        COALESCE(json_array_length(summary_json,'$.recorded_operator_context'),0)
		   FROM situation_episode_summaries WHERE situation_id = ?`, situationID)
	var version, seq, started, recurrence, work, operatorContext int
	var current, peak, initial, latest, outcome, uncertainty string
	if err := row.Scan(&version, &seq, &current, &peak, &started, &recurrence,
		&initial, &latest, &outcome, &uncertainty, &work, &operatorContext); err != nil {
		return []string{fmt.Sprintf("  episode %s none", ordinal)}
	}
	return []string{fmt.Sprintf(
		"  episode %s version=%d source_sequence=%d attention=%s peak=%s investigation_started=%d recurrence=%d initial=%q latest=%q outcome=%q uncertainty=%q work_entries=%d operator_entries=%d",
		ordinal, version, seq, current, peak, started, recurrence, initial, latest, outcome, uncertainty, work, operatorContext)}
}

// canonicalIntents renders this Situation's LIVE notification intents. A
// superseded intent is deliberately excluded: supersession is precisely the
// mechanism that absorbs a crash between a fenced commit and the moment its
// result was observed (controller_replay_test.go's boundary 9 — the commit
// landed, the process died, the replayed cycle recommitted and its newer
// root projection superseded the older one). A superseded intent never
// reaches Slack, so it is not operator-observable state; what MUST match
// across a crash is the set of effects that actually deliver.
// assertOnlyRootSyncSuperseded separately proves the far stronger property
// the spec actually promises: only a coalescible root projection may ever
// be superseded — an immutable journal entry never is.
func canonicalIntents(t *testing.T, st *store.Store, ordinal, situationID string) []string {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT i.effect_class, i.status, i.main_channel_poke,
		        COALESCE(i.interruption_priority,''), i.requires_root,
		        COALESCE(i.summary_version,0), COALESCE(t.sequence,0),
		        COALESCE(i.delivered_as,'')
		   FROM notification_intents i
		   LEFT JOIN situation_transitions t ON t.id = i.transition_id
		  WHERE i.situation_id = ? AND i.status != 'superseded'
		  ORDER BY COALESCE(t.sequence,0) ASC, i.effect_class ASC, i.summary_version ASC, i.created_at ASC`, situationID)
	if err != nil {
		t.Fatalf("read intents: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var poke, requiresRoot, summaryVersion, seq int
		var deliveredAs string
		var class, status, priority string
		if err := rows.Scan(&class, &status, &poke, &priority, &requiresRoot, &summaryVersion, &seq, &deliveredAs); err != nil {
			t.Fatalf("scan intent: %v", err)
		}
		out = append(out, fmt.Sprintf("  intent %s class=%s status=%s poke=%d priority=%s requires_root=%d summary_version=%d transition_sequence=%d delivered_as=%q",
			ordinal, class, status, poke, priority, requiresRoot, summaryVersion, seq, deliveredAs))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate intents: %v", err)
	}
	return out
}

func canonicalArtifactInputs(t *testing.T, st *store.Store, ordinal, situationID string) []string {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT o.kind, o.status, o.journal_state,
		        CASE WHEN o.journaled_transition_id IS NULL THEN 0 ELSE 1 END
		   FROM situation_input_outbox o
		  WHERE o.kind IN ('operator_annotation_recorded','captured_verdict_recorded')
		    AND (o.applied_situation_id = ?
		         OR o.incident_id IN (SELECT incident_id FROM situation_incidents WHERE situation_id = ?))
		  ORDER BY o.kind ASC, o.occurred_at ASC, o.id ASC`, situationID, situationID)
	if err != nil {
		t.Fatalf("read artifact inputs: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var kind, status, journalState string
		var journaled int
		if err := rows.Scan(&kind, &status, &journalState, &journaled); err != nil {
			t.Fatalf("scan artifact input: %v", err)
		}
		out = append(out, fmt.Sprintf("  artifact %s kind=%s status=%s journal_state=%s journaled=%d",
			ordinal, kind, status, journalState, journaled))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate artifact inputs: %v", err)
	}
	return out
}

func canonicalInstallationDelivery(t *testing.T, st *store.Store) []string {
	t.Helper()
	ctx := context.Background()
	var gaps int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM slack_delivery_gaps`).Scan(&gaps); err != nil {
		t.Fatalf("count delivery gaps: %v", err)
	}
	var openGap int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT CASE WHEN open_gap_generation IS NULL THEN 0 ELSE 1 END FROM slack_delivery_state WHERE id = 1`).Scan(&openGap); err != nil {
		t.Fatalf("read delivery state: %v", err)
	}
	var systemIntents int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM notification_intents WHERE effect_class = 'installation_gap_recovery'`).Scan(&systemIntents); err != nil {
		t.Fatalf("count gap recovery intents: %v", err)
	}
	var streamPending int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*) FROM situation_transition_stream WHERE status != 'delivered'`).Scan(&streamPending); err != nil {
		t.Fatalf("count transition stream rows: %v", err)
	}
	return []string{fmt.Sprintf("installation gaps=%d open_gap=%d gap_recovery_intents=%d stream_undelivered=%d",
		gaps, openGap, systemIntents, streamPending)}
}

// ----------------------------------------------------------------------
// Assertion helpers over the canonical projection.
// ----------------------------------------------------------------------

// transitionReasons returns every recorded Transition reason across every
// Situation, in (situation creation, sequence) order.
func transitionReasons(t *testing.T, st *store.Store) []string {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT tr.reason FROM situation_transitions tr
		   JOIN situations s ON s.id = tr.situation_id
		  ORDER BY s.created_at ASC, s.id ASC, tr.sequence ASC`)
	if err != nil {
		t.Fatalf("read transition reasons: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var reason string
		if err := rows.Scan(&reason); err != nil {
			t.Fatalf("scan transition reason: %v", err)
		}
		out = append(out, reason)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate transition reasons: %v", err)
	}
	return out
}

func requireReason(t *testing.T, st *store.Store, want string) {
	t.Helper()
	got := transitionReasons(t, st)
	for _, r := range got {
		if r == want {
			return
		}
	}
	t.Fatalf("no %q Transition was recorded; reasons = %v", want, got)
}

func requireJournalKind(t *testing.T, st *store.Store, want string) {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM situation_transitions WHERE journal_kind = ?`, want).Scan(&n); err != nil {
		t.Fatalf("count journal kind %s: %v", want, err)
	}
	if n == 0 {
		t.Fatalf("no Transition carries journal kind %q", want)
	}
}

// assertSequencesContiguous proves the immutable ledger has no hole and no
// duplicate for any Situation — the single invariant a replayed commit
// would break first if a crash could ever double-apply one.
func assertSequencesContiguous(t *testing.T, st *store.Store) {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT situation_id, sequence FROM situation_transitions ORDER BY situation_id ASC, sequence ASC`)
	if err != nil {
		t.Fatalf("read transition sequences: %v", err)
	}
	defer func() { _ = rows.Close() }()
	seen := map[string]int{}
	for rows.Next() {
		var sit string
		var seq int
		if err := rows.Scan(&sit, &seq); err != nil {
			t.Fatalf("scan transition sequence: %v", err)
		}
		if want := seen[sit] + 1; seq != want {
			t.Fatalf("situation %s transition sequence %d, want %d (the ledger has a hole or a duplicate)", sit, seq, want)
		}
		seen[sit] = seq
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate transition sequences: %v", err)
	}
}

// assertSummaryTracksLedger proves every Situation with a Transition also
// has exactly one Episode summary whose source sequence is the Situation's
// current Transition sequence — the projection fence.
func assertSummaryTracksLedger(t *testing.T, st *store.Store) {
	t.Helper()
	var bad int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM situations s
		 WHERE s.current_transition_sequence > 0
		   AND NOT EXISTS (
		     SELECT 1 FROM situation_episode_summaries e
		      WHERE e.situation_id = s.id
		        AND e.source_transition_sequence = s.current_transition_sequence)`).Scan(&bad); err != nil {
		t.Fatalf("check summary fence: %v", err)
	}
	if bad != 0 {
		t.Fatalf("%d situation(s) have a current Transition with no matching Episode summary version", bad)
	}
}

// assertNoStrandedIntent proves no valid intent was left permanently
// failed: Plan 3's `failed` status is reserved for an invalid durable
// intent, and no scenario in this file ever creates one.
func assertNoStrandedIntent(t *testing.T, st *store.Store) {
	t.Helper()
	var n int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM notification_intents WHERE status IN ('failed','blocked_configuration')`).Scan(&n); err != nil {
		t.Fatalf("count stranded intents: %v", err)
	}
	if n != 0 {
		t.Fatalf("%d notification intent(s) ended failed/blocked_configuration; a valid effect must never exhaust", n)
	}
}

// assertOneRootIntentPerSituation proves a Situation never accumulates two
// simultaneously live root projections: at most one root_sync per Situation
// may be pending at rest, and every superseded one is explicitly marked.
func assertOneRootIntentPerSituation(t *testing.T, st *store.Store) {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT situation_id, COUNT(*) FROM notification_intents
		  WHERE effect_class = 'root_sync' AND status = 'pending'
		  GROUP BY situation_id HAVING COUNT(*) > 1`)
	if err != nil {
		t.Fatalf("read pending roots: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var sit string
		var n int
		if err := rows.Scan(&sit, &n); err != nil {
			t.Fatalf("scan pending roots: %v", err)
		}
		t.Fatalf("situation %s carries %d pending root_sync intents, want at most 1", sit, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate pending roots: %v", err)
	}
}

// assertConverged runs every structural invariant this file's scenarios
// share, then returns the canonical projection for cross-run comparison.
// assertOnlyRootSyncSuperseded proves the supersession rule the spec
// states: only a coalescible current-state root projection may ever be
// superseded. An immutable historical effect — a thread append or a
// broadcast handoff — carries one exact Transition's own journal data and
// must never be dropped because a newer one exists.
func assertOnlyRootSyncSuperseded(t *testing.T, st *store.Store) {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT effect_class, COUNT(*) FROM notification_intents
		  WHERE status = 'superseded' AND effect_class != 'root_sync' GROUP BY effect_class`)
	if err != nil {
		t.Fatalf("read superseded intents: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var class string
		var n int
		if err := rows.Scan(&class, &n); err != nil {
			t.Fatalf("scan superseded intent: %v", err)
		}
		t.Fatalf("%d %s intent(s) were superseded; only a coalescible root_sync may ever be", n, class)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate superseded intents: %v", err)
	}
}

func assertConverged(t *testing.T, st *store.Store) string {
	t.Helper()
	assertSequencesContiguous(t, st)
	assertSummaryTracksLedger(t, st)
	assertNoStrandedIntent(t, st)
	assertOneRootIntentPerSituation(t, st)
	assertOnlyRootSyncSuperseded(t, st)
	return canonicalHistory(t, st)
}

// ----------------------------------------------------------------------
// Scenario driver.
// ----------------------------------------------------------------------

// historyScenario is one scripted episode. run drives the fixture; the
// driver below runs it once with no crash and once with each armed
// boundary, then requires the canonical history to match.
type historyScenario struct {
	name string
	// run drives one full episode to quiescence. It must call
	// f.crashControllerCycle() (or f.deliver() with crashDelivery armed)
	// at every point the scenario wants a crash boundary, so both runs see
	// the same clock schedule.
	run func(f *historyFixture)
	// assert runs extra scenario-specific expectations against the
	// converged database. Called for both runs.
	assert func(t *testing.T, st *store.Store)
}

// crashBoundaries are the controller crash points every scenario is
// replayed against, plus the reference (restart-only) run. The delivery
// acknowledgement boundary is driven separately, by crashDelivery.
var historyCrashBoundaries = []crashPoint{
	crashPointCommitController,
	crashPointCommitControllerAfterCommit,
	crashPointRecordAssessmentCall,
}

func runHistoryScenario(t *testing.T, sc historyScenario) {
	t.Helper()

	reference := newHistoryFixture(t, sanitizeOwner(sc.name)+"-ref", "", false)
	sc.run(reference)
	want := assertConverged(t, reference.st)
	if testing.Verbose() {
		// The reference projection is the whole point of this fixture; a
		// maintainer changing history derivation wants to read it, not
		// reverse-engineer it out of a diff.
		t.Logf("uninterrupted canonical history for %s:\n%s", sc.name, want)
	}
	if sc.assert != nil {
		sc.assert(t, reference.st)
	}

	for _, boundary := range historyCrashBoundaries {
		t.Run(string(boundary), func(t *testing.T) {
			t.Parallel()
			f := newHistoryFixture(t, sanitizeOwner(sc.name)+"-"+sanitizeOwner(string(boundary)), boundary, false)
			sc.run(f)
			got := assertConverged(t, f.st)
			if got != want {
				t.Fatalf("canonical history after crashing at %s differs from the uninterrupted run.\n--- uninterrupted ---\n%s\n--- after crash+replay ---\n%s", boundary, want, got)
			}
			if sc.assert != nil {
				sc.assert(t, f.st)
			}
		})
	}

	t.Run(crashBoundaryDeliveryAcknowledgement, func(t *testing.T) {
		t.Parallel()
		f := newHistoryFixture(t, sanitizeOwner(sc.name)+"-delivery", "", true)
		sc.run(f)
		if f.crashDelivery {
			t.Fatal("the scenario never delivered anything, so the delivery crash boundary was never exercised; a scenario proving delivery replay must publish")
		}
		got := assertConverged(t, f.st)
		if got != want {
			t.Fatalf("canonical history after crashing between the Slack call and its durable acknowledgement differs from the uninterrupted run.\n--- uninterrupted ---\n%s\n--- after crash+replay ---\n%s", got, want)
		}
		if sc.assert != nil {
			sc.assert(t, f.st)
		}
	})
}

func sanitizeOwner(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, " ", "-"), "_", "-")
}

// ----------------------------------------------------------------------
// TestSituationHistoryRealStoreReplay: the Plan 3 history/delivery replay
// catalog. Each subtest is one scripted episode replayed against every
// crash boundary in historyCrashBoundaries plus the delivery-acknowledgement
// boundary, and compared against its own uninterrupted (restart-only) run.
// ----------------------------------------------------------------------

func TestSituationHistoryRealStoreReplay(t *testing.T) {
	t.Parallel()
	t.Run("first_publication", func(t *testing.T) { t.Parallel(); runHistoryScenario(t, scenarioFirstPublication()) })
	t.Run("operator_artifacts", func(t *testing.T) { t.Parallel(); runHistoryScenario(t, scenarioOperatorArtifacts()) })
	t.Run("artifact_after_closure", func(t *testing.T) { t.Parallel(); runHistoryScenario(t, scenarioArtifactAfterClosure()) })
	t.Run("recovery_refire_recovered", func(t *testing.T) { t.Parallel(); runHistoryScenario(t, scenarioRecoveryRefireRecovered()) })
	t.Run("closed_unknown", func(t *testing.T) { t.Parallel(); runHistoryScenario(t, scenarioClosedUnknown()) })
	t.Run("deadline_refresh", func(t *testing.T) { t.Parallel(); runHistoryScenario(t, scenarioDeadlineRefresh()) })
	t.Run("investigation", func(t *testing.T) { t.Parallel(); runHistoryScenario(t, scenarioInvestigation()) })
	t.Run("recurrence_handoff", func(t *testing.T) { t.Parallel(); runHistoryScenario(t, scenarioRecurrenceLineageAndHandoff()) })
}

// scenarioFirstPublication: one warranted Situation reaches its first
// authoritative state, which must produce exactly one
// first_authoritative_state Transition, one Episode summary at version 1,
// and one root_sync intent that actually delivers.
func scenarioFirstPublication() historyScenario {
	return historyScenario{
		name: "first-publication",
		run: func(f *historyFixture) {
			f.openWarrantedSituation("hist-first", "fp-hist-first")
			f.crashControllerCycle()
			f.converge()
		},
		assert: func(t *testing.T, st *store.Store) {
			t.Helper()
			requireReason(t, st, "first_authoritative_state")
			requireJournalKind(t, st, "publication")
		},
	}
}

// controllerOnlyDrain drains the controller worker alone — never the
// dispatch or input workers convergeAll/oneControllerDrainPass run first.
// R2's ownership race needs exactly this: an artifact input already
// enqueued in the outbox, a controller cycle that terminalizes the owning
// Situation, and only THEN the input worker that applies the artifact
// against an owner that has meanwhile gone terminal.
func (f *historyFixture) controllerOnlyDrain() {
	f.t.Helper()
	f.clock.Advance(advanceMargin)
	cw := situation.NewControllerWorker(f.st, f.st, f.l2(), situation.ControllerConfig{},
		situation.ControllerWorkerConfig{Owner: f.owner + ":controller", Now: f.clock.Now}, f.clock.Now,
		audit.New(f.st.DB()), nil)
	if _, err := cw.Drain(f.ctx); err != nil {
		f.t.Fatalf("controller-only drain: %v", err)
	}
	f.assertNoReconcileFailed()
}

// annotate appends one real operator annotation through the production
// store write path (store.InsertIncidentAnnotation), which is what enqueues
// the operator_annotation_recorded Situation input.
func (f *historyFixture) annotate(incidentID, note string) {
	f.t.Helper()
	if _, err := f.st.InsertIncidentAnnotation(f.ctx, incidentID, "observation", note); err != nil {
		f.t.Fatalf("insert incident annotation: %v", err)
	}
}

// captureVerdict records one real Captured verdict through the production
// store write path (store.PersistVerdictCapture).
func (f *historyFixture) captureVerdict(incidentID, note string) {
	f.t.Helper()
	if _, _, err := f.st.PersistVerdictCapture(f.ctx, store.VerdictCapture{
		IncidentID:      incidentID,
		Verdict:         "confirmation",
		Source:          "history-replay-test",
		LabelConfidence: 0.9,
		ExpectationJSON: `{"expected":"replay"}`,
		AnnotationNote:  note,
	}); err != nil {
		f.t.Fatalf("persist verdict capture: %v", err)
	}
}

// scenarioOperatorArtifacts: R1 — two operator artifacts (one annotation,
// one Captured verdict) land between two controller cycles and are both
// journaled, in application order, by the next fenced commit, ahead of any
// controller-state Transition in the same commit.
func scenarioOperatorArtifacts() historyScenario {
	return historyScenario{
		name: "operator-artifacts",
		run: func(f *historyFixture) {
			f.openWarrantedSituation("hist-artifacts", "fp-hist-artifacts")
			f.converge()

			inc := f.newestIncidentID()
			f.annotate(inc, "api-2 is the canary host; rollout paused.")
			f.captureVerdict(inc, "confirmed: this is the known canary pattern.")

			f.crashControllerCycle()
			f.converge()
		},
		assert: func(t *testing.T, st *store.Store) {
			t.Helper()
			requireReason(t, st, "operator_artifact_recorded")
			requireJournalKind(t, st, "operator_note")
			requireJournalKind(t, st, "captured_verdict")
			assertArtifactJournalStates(t, st, map[string]int{"journaled": 2})
			assertArtifactTransitionsPrecedeControllerState(t, st)
		},
	}
}

// scenarioArtifactAfterClosure: R2 — an artifact enqueued while its owner
// was nonterminal, but applied only after that owner terminalized, is
// recorded as owner_terminal: never journaled, never lost, and it creates
// no Transition, Episode version, or intent.
func scenarioArtifactAfterClosure() historyScenario {
	return historyScenario{
		name: "artifact-after-closure",
		run: func(f *historyFixture) {
			f.openWarrantedSituation("hist-closure", "fp-hist-closure")
			// The crash boundary sits on the first publication commit: the
			// R2 sequence below must run against an already-converged,
			// published Situation, because a crash INSIDE it would (quite
			// correctly) roll the terminalization back and let the artifact
			// journal normally — a different, already-covered outcome.
			f.crashControllerCycle()
			f.converge()

			// One round only: converge() would run the 120s recovery grace
			// out and terminalize before the artifact is ever enqueued.
			f.postAlert("hist-closure", "HighLatency", "fp-hist-closure", "resolved", "warning")
			f.oneRound()
			assertLifecycle(f.t, f.st, "recovery_pending")

			// The owner is still nonterminal here, so this annotation IS
			// enqueued. Nothing applies it yet: controllerOnlyDrain below
			// deliberately runs the controller WITHOUT the input worker, so
			// the owner terminalizes first — exactly R2's race.
			f.annotate(f.newestIncidentID(), "checked the dashboards after recovery.")
			f.clock.Advance(10 * time.Minute)
			f.controllerOnlyDrain()
			assertLifecycle(f.t, f.st, "recovered")

			f.converge()
		},
		assert: func(t *testing.T, st *store.Store) {
			t.Helper()
			assertArtifactJournalStates(t, st, map[string]int{"owner_terminal": 1})
			var journaled int
			if err := st.DB().QueryRowContext(context.Background(),
				`SELECT COUNT(*) FROM situation_transitions WHERE reason = 'operator_artifact_recorded'`).Scan(&journaled); err != nil {
				t.Fatalf("count artifact transitions: %v", err)
			}
			if journaled != 0 {
				t.Fatalf("%d operator_artifact_recorded Transition(s) exist; an artifact applied after closure must never be journaled", journaled)
			}
			requireReason(t, st, "recovered")
		},
	}
}

// scenarioRecoveryRefireRecovered: the full recovery arc — recovery
// observed, a refire that returns the Situation to active, a second
// recovery observation, and clean grace expiry to recovered.
func scenarioRecoveryRefireRecovered() historyScenario {
	return historyScenario{
		name: "recovery-refire-recovered",
		run: func(f *historyFixture) {
			f.openWarrantedSituation("hist-recovery", "fp-hist-recovery")
			f.converge()

			// One round per lifecycle step: converge() loops to quiescence,
			// which would run the 120s recovery grace out and terminalize
			// the Situation before it could ever refire.
			f.postAlert("hist-recovery", "HighLatency", "fp-hist-recovery", "resolved", "warning")
			f.oneRound()
			assertLifecycle(f.t, f.st, "recovery_pending")

			// Refire: the same symptom fires again before grace expires.
			f.postAlert("hist-recovery", "HighLatency", "fp-hist-recovery", "firing", "warning")
			f.oneRound()
			assertLifecycle(f.t, f.st, "active")

			f.crashControllerCycle()

			f.postAlert("hist-recovery", "HighLatency", "fp-hist-recovery", "resolved", "warning")
			f.oneRound()

			// Clean grace expiry (default webhook grace is 120s).
			f.clock.Advance(10 * time.Minute)
			f.converge()
		},
		assert: func(t *testing.T, st *store.Store) {
			t.Helper()
			requireReason(t, st, "recovery_observed")
			requireReason(t, st, "recovery_failed")
			requireReason(t, st, "recovered")
			requireJournalKind(t, st, "recovery_pending")
			requireJournalKind(t, st, "recovery_refired")
			requireJournalKind(t, st, "recovered")
			assertTerminalIsLast(t, st)
		},
	}
}

// scenarioClosedUnknown: a Situation whose symptoms stopped reporting and
// whose source-aware lifecycle-observation deadline then expired closes as
// closed_unknown, with its terminal reason recorded and no invented
// Monitoring phase.
func scenarioClosedUnknown() historyScenario {
	return historyScenario{
		name: "closed-unknown",
		run: func(f *historyFixture) {
			f.openWarrantedSituation("hist-unknown", "fp-hist-unknown")
			f.converge()

			// Resolve, then let the observation deadline pass BEFORE any
			// controller cycle observes the resolution — the one path that
			// reaches closed_unknown straight from active (controller.go's
			// resolveLifecycle checks pastDeadline before recovery
			// observation). The long duration class's deadline is 7 days.
			f.postAlert("hist-unknown", "HighLatency", "fp-hist-unknown", "resolved", "warning")
			f.drainFoundation()
			f.clock.Advance(8 * 24 * time.Hour)

			f.crashControllerCycle()
			f.converge()
		},
		assert: func(t *testing.T, st *store.Store) {
			t.Helper()
			requireReason(t, st, "closed_unknown")
			requireJournalKind(t, st, "closed_unknown")
			var reason string
			if err := st.DB().QueryRowContext(context.Background(),
				`SELECT COALESCE(terminal_reason,'') FROM situations WHERE lifecycle = 'closed_unknown'`).Scan(&reason); err != nil {
				t.Fatalf("read terminal reason: %v", err)
			}
			if reason == "" {
				t.Fatal("a closed_unknown Situation carries no terminal reason")
			}
			assertTerminalIsLast(t, st)
		},
	}
}

// scenarioDeadlineRefresh: R4 — a published root whose delivered promise
// has expired gets exactly one coalescible root_sync refresh from the next
// NON-material reconciliation, and that refresh is never a poke and never a
// thread entry.
func scenarioDeadlineRefresh() historyScenario {
	return historyScenario{
		name: "deadline-refresh",
		run: func(f *historyFixture) {
			f.openWarrantedSituation("hist-refresh", "fp-hist-refresh")
			f.converge()

			// Let the delivered root's promised update time pass, then run
			// a reconciliation that changes nothing material.
			f.clock.Advance(45 * time.Minute)
			f.crashControllerCycle()
			f.converge()
		},
		assert: func(t *testing.T, st *store.Store) {
			t.Helper()
			var roots, pokes int
			if err := st.DB().QueryRowContext(context.Background(),
				`SELECT COUNT(*), COALESCE(SUM(main_channel_poke),0) FROM notification_intents
				  WHERE effect_class = 'root_sync'`).Scan(&roots, &pokes); err != nil {
				t.Fatalf("count root intents: %v", err)
			}
			if roots < 2 {
				t.Fatalf("root_sync intents = %d, want at least 2 (the first publication plus one R4 deadline refresh)", roots)
			}
			if pokes != 1 {
				t.Fatalf("main-channel pokes across %d root_sync intents = %d, want exactly 1 (only the first publication pokes; a deadline refresh never does)", roots, pokes)
			}
			// The refresh must not have created a second Transition: a
			// non-material reconciliation creates no history at all. Scoped
			// to the live Situation: its five prior episodes have history
			// of their own.
			reasons := liveTransitionReasons(t, st)
			if len(reasons) != 1 || reasons[0] != "first_authoritative_state" {
				t.Fatalf("transition reasons = %v, want exactly [first_authoritative_state]: an R4 refresh must create no Transition", reasons)
			}
		},
	}
}

// ----------------------------------------------------------------------
// Scenario-specific assertion helpers.
// ----------------------------------------------------------------------

// liveTransitionReasons is transitionReasons scoped to the newest
// Situation — the one a warranted scenario is about, after its lineage.
func liveTransitionReasons(t *testing.T, st *store.Store) []string {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(), `
		SELECT reason FROM situation_transitions
		 WHERE situation_id = (SELECT id FROM situations ORDER BY created_at DESC, id DESC LIMIT 1)
		 ORDER BY sequence ASC`)
	if err != nil {
		t.Fatalf("read live transition reasons: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			t.Fatalf("scan live transition reason: %v", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate live transition reasons: %v", err)
	}
	return out
}

func assertArtifactJournalStates(t *testing.T, st *store.Store, want map[string]int) {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT journal_state, COUNT(*) FROM situation_input_outbox
		  WHERE kind IN ('operator_annotation_recorded','captured_verdict_recorded')
		  GROUP BY journal_state`)
	if err != nil {
		t.Fatalf("read artifact journal states: %v", err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]int{}
	for rows.Next() {
		var state string
		var n int
		if err := rows.Scan(&state, &n); err != nil {
			t.Fatalf("scan artifact journal state: %v", err)
		}
		got[state] = n
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate artifact journal states: %v", err)
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("artifact journal states = %v, want %v", got, want)
	}
}

// assertArtifactTransitionsPrecedeControllerState proves R1's ordering
// rule: within one Situation, every operator_artifact_recorded Transition
// committed in the same cycle sits BEFORE the controller-state Transition
// that cycle produced — i.e. no controller-state Transition ever carries a
// lower sequence than an artifact Transition committed after it.
func assertArtifactTransitionsPrecedeControllerState(t *testing.T, st *store.Store) {
	t.Helper()
	rows, err := st.DB().QueryContext(context.Background(),
		`SELECT situation_id, sequence, reason, created_at FROM situation_transitions
		  ORDER BY situation_id ASC, sequence ASC`)
	if err != nil {
		t.Fatalf("read transitions for ordering: %v", err)
	}
	defer func() { _ = rows.Close() }()
	type rec struct {
		seq       int
		reason    string
		createdAt string
	}
	perSituation := map[string][]rec{}
	for rows.Next() {
		var sit, reason, createdAt string
		var seq int
		if err := rows.Scan(&sit, &seq, &reason, &createdAt); err != nil {
			t.Fatalf("scan transition for ordering: %v", err)
		}
		perSituation[sit] = append(perSituation[sit], rec{seq, reason, createdAt})
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate transitions for ordering: %v", err)
	}
	for sit, recs := range perSituation {
		byCommit := map[string][]rec{}
		for _, r := range recs {
			byCommit[r.createdAt] = append(byCommit[r.createdAt], r)
		}
		for at, commit := range byCommit {
			seenControllerState := false
			for _, r := range commit {
				if r.reason == "operator_artifact_recorded" {
					if seenControllerState {
						t.Fatalf("situation %s commit at %s: artifact Transition #%d follows a controller-state Transition in the same fenced commit", sit, at, r.seq)
					}
					continue
				}
				seenControllerState = true
			}
		}
	}
}

// assertTerminalIsLast proves a terminal Transition is always the last one
// in its Situation's ledger — a terminal Situation never reopens and never
// journals anything afterwards.
func assertTerminalIsLast(t *testing.T, st *store.Store) {
	t.Helper()
	var bad int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT COUNT(*) FROM situation_transitions t
		 WHERE t.lifecycle IN ('recovered','closed_unknown')
		   AND EXISTS (SELECT 1 FROM situation_transitions later
		                WHERE later.situation_id = t.situation_id AND later.sequence > t.sequence)`).Scan(&bad); err != nil {
		t.Fatalf("check terminal ordering: %v", err)
	}
	if bad != 0 {
		t.Fatalf("%d terminal Transition(s) are followed by a later Transition in the same Situation", bad)
	}
}

// assertLifecycle pins the NEWEST Situation's lifecycle mid-scenario, so a
// scenario that depends on observing an intermediate state fails loudly at
// the exact step that stopped producing it rather than silently proving a
// weaker property later.
func assertLifecycle(t *testing.T, st *store.Store, want string) {
	t.Helper()
	var got string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT lifecycle FROM situations ORDER BY created_at DESC, id DESC LIMIT 1`).Scan(&got); err != nil {
		t.Fatalf("read situation lifecycle: %v", err)
	}
	if got != want {
		t.Fatalf("situation lifecycle = %q, want %q", got, want)
	}
}

// scenarioInvestigation: a Situation whose member Incident becomes ready
// has Acute Triage requested, which moves the Operator contract to
// run_acute_triage — the durable basis for the root's Investigating phase —
// and then concludes.
func scenarioInvestigation() historyScenario {
	return historyScenario{
		name: "investigation",
		run: func(f *historyFixture) {
			f.openWarrantedSituation("hist-investigation", "fp-hist-investigation")
			f.converge()

			// A collecting Incident is a clean minimum-member Triage skip;
			// a ready one is what makes the controller request Acute Triage.
			f.markReady(f.newestIncidentID())

			f.crashControllerCycle()
			f.converge()
		},
		assert: func(t *testing.T, st *store.Store) {
			t.Helper()
			requireReason(t, st, "investigation_started")
			requireJournalKind(t, st, "investigation_started")
			var started int
			if err := st.DB().QueryRowContext(context.Background(),
				`SELECT json_extract(summary_json,'$.investigation_started') FROM situation_episode_summaries
				  WHERE situation_id = (SELECT id FROM situations ORDER BY created_at DESC, id DESC LIMIT 1)`).Scan(&started); err != nil {
				t.Fatalf("read investigation_started: %v", err)
			}
			if started != 1 {
				t.Fatal("the Episode summary does not record that investigation started")
			}
		},
	}
}

// shortEpisode drives one complete firing -> resolved -> recovered episode
// for group, leaving a terminal Situation behind. Five of them are what
// makes the SIXTH Situation's own recurrence count reach the first
// milestone rung and its elapsed duration eligible for the only non-floor
// Sufficient-reason candidate this build can reach (duration_outlier).
func (f *historyFixture) shortEpisode(group, fingerprint string) {
	f.t.Helper()
	f.postAlert(group, "HighLatency", fingerprint, "firing", "warning")
	f.drainFoundation()
	// Close this episode's correlation window explicitly. The Correlator's
	// own fixed-window flush runs on the real wall clock, which this
	// fixture never advances, so without this every episode's deliveries
	// would keep landing in ONE forever-collecting Incident and only one
	// Situation would ever exist — the lineage this scenario needs would
	// silently never form.
	f.markReady(f.newestIncidentID())
	f.converge()
	f.postAlert(group, "HighLatency", fingerprint, "resolved", "warning")
	f.converge()
	assertLifecycle(f.t, f.st, "recovered")
}

// openWarrantedSituation opens the Situation a scenario is about in a state
// that carries publication authority at its FIRST controller cycle.
//
// A quiet Situation — observe Attention, no accepted Sufficient reason —
// has state, Transitions, and MCP history but no claim on Slack at all
// (PlanNotificationIntents, review round 1), and a fresh group can reach no
// Sufficient reason on its own: critical_anchor needs a critical delivery
// (whose urgent fast cadence is exactly advanceMargin, so the R4 deadline
// refresh would re-edit the root on every round of this harness and it
// could never look quiescent), novel_symptom and terminal_uncertainty are
// unreachable in this build, and duration_outlier needs at least five
// comparable prior durations. So this helper builds exactly that lineage —
// five short quiet episodes for group — posts the live alert, and lets
// enough time pass that its elapsed duration is an outlier before the
// first cycle claims duration_outlier at observe Attention: the lowest
// interruption priority a warranted Situation can publish at, on the slow
// cadence that lets the harness converge.
func (f *historyFixture) openWarrantedSituation(group, fingerprint string) {
	f.t.Helper()
	for i := 0; i < 5; i++ {
		f.shortEpisode(group, fmt.Sprintf("%s-prior-%d", fingerprint, i))
	}
	f.postAlert(group, "HighLatency", fingerprint, "firing", "warning")
	f.drainFoundation()
	// 45 minutes: an outlier against the minutes-long priors, but still
	// inside the "medium" duration class, so a scenario that later needs a
	// fresh L2 judgment (the handoff) can cross into "long" and change the
	// Assessment basis — a reuse cycle never consults the model.
	f.clock.Advance(45 * time.Minute)
	f.script = l2Script{ClaimNonFloorReason: true}
}

func (f *historyFixture) newestIncidentID() string {
	f.t.Helper()
	return scalarString(f.t, f.st, `SELECT id FROM incidents ORDER BY created_at DESC, id DESC LIMIT 1`)
}

// scenarioRecurrenceLineageAndHandoff: the five completed episodes every
// warranted scenario opens with make the sixth Situation carry a recurrence
// count at the first milestone rung; claiming duration_outlier while
// Attention is investigate is exactly what makes the controller derive an
// operator handoff (assessment.go's operatorActionRequired), which is the
// one transition class that earns a broadcast reply.
func scenarioRecurrenceLineageAndHandoff() historyScenario {
	return historyScenario{
		name: "recurrence-handoff",
		run: func(f *historyFixture) {
			f.openWarrantedSituation("hist-lineage", "fp-hist-lineage-live")
			f.converge()

			// Cross into the "long" duration class so the next cycle's
			// Assessment basis changes and the model is consulted again;
			// investigate while still claiming duration_outlier: a
			// validated non-floor reason accepted at investigate Attention
			// is what derives the operator handoff.
			f.clock.Advance(3 * time.Hour)
			f.script = l2Script{Attention: situationmodel.AttentionInvestigate, ClaimNonFloorReason: true}

			f.crashControllerCycle()
			f.converge()
		},
		assert: func(t *testing.T, st *store.Store) {
			t.Helper()
			assertRecurrenceMilestoneReached(t, st, 5)
			assertOperatorHandoffRecorded(t, st)
		},
	}
}

// assertRecurrenceMilestoneReached proves the live Situation's durable
// recurrence count reached want, and that its Episode summary carries it.
//
// The count is prior terminal Situations for this exact group plus member
// Incidents' recurrence-collapse occurrences; this scenario drives only the
// lineage half, so the rung is reached at the first Transition rather than
// by a later `recurrence_milestone` Transition. That later path — a re-fire
// attaching as an occurrence, the membership input, the milestone
// Transition and its quiet thread entry — is driven end to end by
// cmd/alertint's fake-Slack test
// (TestSituationSlackE2ERecurrenceMilestoneStaysInThread). What replay
// must prove here is that the durable recurrence count and its milestone
// rung survive a crash unchanged.
func assertRecurrenceMilestoneReached(t *testing.T, st *store.Store, want int) {
	t.Helper()
	var got int
	if err := st.DB().QueryRowContext(context.Background(), `
		SELECT json_extract(e.summary_json,'$.recurrence_count')
		  FROM situation_episode_summaries e
		  JOIN situations s ON s.id = e.situation_id
		 WHERE s.lifecycle IN ('active','recovery_pending')`).Scan(&got); err != nil {
		t.Fatalf("read live episode recurrence count: %v", err)
	}
	if got != want {
		t.Fatalf("live Episode summary recurrence_count = %d, want %d", got, want)
	}
}

// assertOperatorHandoffRecorded proves the handoff actually happened: a
// Transition whose Operator contract names an operator action, and one
// broadcast_handoff intent for it. A handoff is the only journal reply the
// spec lets broadcast to the main channel.
func assertOperatorHandoffRecorded(t *testing.T, st *store.Store) {
	t.Helper()
	var handoffs int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM situation_transitions
		  WHERE json_extract(action_contract_json,'$.operator_action_required') IS NOT NULL`).Scan(&handoffs); err != nil {
		t.Fatalf("count handoff transitions: %v", err)
	}
	if handoffs == 0 {
		t.Fatal("no Transition records an operator action; the handoff never happened")
	}
	var broadcasts int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM notification_intents WHERE effect_class = 'broadcast_handoff'`).Scan(&broadcasts); err != nil {
		t.Fatalf("count broadcast intents: %v", err)
	}
	if broadcasts == 0 {
		t.Fatal("no broadcast_handoff intent was created for the operator handoff")
	}
}
