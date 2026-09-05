// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// End-to-end Controller.Reconcile tests against a REAL *Store — Finding C1's
// primary required test. controller_test.go's own fake-store tests never
// enforce migration 0015's schema CHECK constraints at all, which is exactly
// what let C1 (reuse/deterministic-floor commits passing workAttempt=0)
// through undetected. *Store structurally satisfies situation.ControllerStore
// (situation_controller.go's own methods), so Controller.Reconcile can run
// against it directly here, with no fake in the loop.
// ----------------------------------------------------------------------

// scriptedAssessmentClient is a minimal situation.AssessmentClient scripting
// one llm.OneShotCompletion/error pair per CompleteOnce call, consumed in
// order — this package's own local equivalent of
// internal/situation's controller_test.go fakeAssessmentClient (that type is
// unexported and lives in a different package this one must not import back
// into, per this file's own "internal/store depends on internal/situation,
// never the reverse" direction).
type scriptedAssessmentClient struct {
	calls     int
	responses []func() (llm.OneShotCompletion, error)
}

func (c *scriptedAssessmentClient) CompleteOnce(ctx context.Context, systemPrompt string, prompt llm.Prompt, requiredKeys []string) (llm.OneShotCompletion, error) {
	idx := c.calls
	c.calls++
	if idx >= len(c.responses) {
		return llm.OneShotCompletion{}, errors.New("scriptedAssessmentClient: no more scripted responses")
	}
	return c.responses[idx]()
}

// acceptedProposalResponse builds one accepted (non-floor, non-urgent)
// model.AssessmentProposal response — schema-valid, no SufficientReason
// needed since Attention stays observe.
func acceptedProposalResponse(t *testing.T) func() (llm.OneShotCompletion, error) {
	t.Helper()
	p := situationmodel.AssessmentProposal{
		SchemaVersion: situationmodel.AssessmentSchemaVersion,
		Persistence:   situationmodel.PersistenceSustained,
		Impact:        situationmodel.ImpactSuspected,
		Novelty:       situationmodel.NoveltyFamiliar,
		Causality:     situationmodel.CausalityCorrelated,
		Attention:     situationmodel.AttentionObserve,
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal accepted proposal: %v", err)
	}
	return func() (llm.OneShotCompletion, error) {
		return llm.OneShotCompletion{
			Completion:     llm.Completion{Raw: raw, Model: "test-model"},
			RequestStarted: llm.RequestStartStatusTrue,
		}, nil
	}
}

// seedReconcileSituation seeds one fresh, active, non-floor (default
// severity) Situation with one member Incident/delivery via a real
// AcceptDeliveries + ApplySituationInput round trip, and returns its id.
func seedReconcileSituation(t *testing.T, st *Store, groupKey string, now time.Time) string {
	t.Helper()
	ctx := context.Background()
	deliveryID := "delivery-" + groupKey
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{deliveryFixtureWithSource(
		deliveryID, "fp-"+groupKey, now, now, situationmodel.SourceTimeBasisSourcePayload,
	)}); err != nil {
		t.Fatalf("accept delivery: %v", err)
	}
	incID := "inc-" + groupKey
	insertIncidentAndDeliveryInput(t, st, incID, "input-"+groupKey, groupKey, deliveryID, now)
	claim := claimOneInput(t, st, "seed:"+groupKey, now)
	if err := st.ApplySituationInput(ctx, claim); err != nil {
		t.Fatalf("apply situation input: %v", err)
	}
	var sitID string
	if err := st.db.QueryRowContext(ctx, `SELECT id FROM situations WHERE group_key = ?`, groupKey).Scan(&sitID); err != nil {
		t.Fatalf("find situation for group %s: %v", groupKey, err)
	}
	return sitID
}

// currentAssessmentID reads situationID's current_assessment_id pointer
// directly — a raw Plan 2 column model.Situation carries no Go struct field
// for (see BeginControllerAttempt's own doc comment). Returns "" when unset.
func currentAssessmentID(t *testing.T, st *Store, situationID string) string {
	t.Helper()
	var id sql.NullString
	if err := st.db.QueryRowContext(context.Background(), `SELECT current_assessment_id FROM situations WHERE id = ?`, situationID).Scan(&id); err != nil {
		t.Fatalf("read current_assessment_id for %s: %v", situationID, err)
	}
	if !id.Valid {
		return ""
	}
	return id.String
}

// TestControllerReconcileEndToEndReuseCommitsAgainstRealSchema is Finding
// C1's primary required test: it drives a real *Store through
// Controller.Reconcile for two cycles — cycle 1 dispatches L2 and commits
// model_validated; cycle 2 (same basis) hits RevalidateReuse and commits
// revalidated_reuse WITHOUT any further L2 call — and asserts BOTH commits
// succeed against the real schema. Before the fix, cycle 2's commit
// (controller.go's revalidated-reuse call site) passed workAttempt=0,
// violating migration 0015's situation_assessment_attempts CHECK
// (work_attempt BETWEEN 1 AND 5) — this reproduces exactly that call path,
// with no fake store in the loop to hide the failure.
//
// The controller's own clock is pinned to the SAME instant for both cycles
// (only the store-level claim "now" advances, to satisfy ClaimDueSituations'
// own due-schedule filter) — deliberately, so BuildSnapshot's own
// elapsed-time-derived DurationClass (and therefore MaterialFactHash/
// AssessmentBasisHash) stays byte-identical between cycles, which is exactly
// what RevalidateReuse's own basis-hash equality check requires to succeed.
func TestControllerReconcileEndToEndReuseCommitsAgainstRealSchema(t *testing.T) {
	st := newTestStore(t)
	now := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	groupKey := "group-e2e-reuse"

	sitID := seedReconcileSituation(t, st, groupKey, now)

	client := &scriptedAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedProposalResponse(t)}}
	controllerNow := now.Add(5 * time.Minute)
	clock := func() time.Time { return controllerNow }
	controller := situation.NewController(st, client, situation.ControllerConfig{}, clock, nil, nil)

	// Cycle 1: work-bearing dispatch, model_validated commit.
	c1 := claimSituation(t, st, sitID, "controller-e2e-1", now.Add(time.Minute))
	if err := controller.Reconcile(context.Background(), c1); err != nil {
		t.Fatalf("cycle 1 Reconcile: %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("cycle 1 CompleteOnce calls = %d, want 1", client.calls)
	}
	sit1 := getSituationByID(t, st, sitID)
	if sit1.LeaseOwner != nil {
		t.Fatal("cycle 1 must clear the lease on commit")
	}
	firstAttemptID := currentAssessmentID(t, st, sitID)
	if firstAttemptID == "" {
		t.Fatal("cycle 1 must set a current assessment id")
	}
	var derivation1 string
	var workAttempt1 int
	if err := st.db.QueryRowContext(context.Background(), `SELECT derivation, work_attempt FROM situation_assessment_attempts WHERE id = ?`, firstAttemptID).
		Scan(&derivation1, &workAttempt1); err != nil {
		t.Fatalf("read cycle 1 attempt: %v", err)
	}
	if derivation1 != string(situationmodel.DerivationModelValidated) {
		t.Fatalf("cycle 1 derivation = %q, want %q", derivation1, situationmodel.DerivationModelValidated)
	}
	if workAttempt1 != 1 {
		t.Fatalf("cycle 1 work_attempt = %d, want 1 (BeginControllerAttempt's own first-attempt value)", workAttempt1)
	}

	// Cycle 2: claimed at a much later store-side "now" (satisfying the due
	// schedule cycle 1's own commit set), but the CONTROLLER's clock is
	// pinned identical — same basis, so reuse applies.
	c2 := claimSituation(t, st, sitID, "controller-e2e-2", now.Add(time.Hour))
	if err := controller.Reconcile(context.Background(), c2); err != nil {
		t.Fatalf("cycle 2 Reconcile (revalidated reuse): %v", err)
	}
	if client.calls != 1 {
		t.Fatalf("cycle 2 CompleteOnce calls = %d, want still 1 (reuse must spend zero L2 dispatch slots)", client.calls)
	}

	secondAttemptID := currentAssessmentID(t, st, sitID)
	if secondAttemptID == "" {
		t.Fatal("cycle 2 must set a current assessment id")
	}
	if secondAttemptID == firstAttemptID {
		t.Fatal("reuse must still write a NEW authoritative attempt row, not just repoint the existing one")
	}

	var derivation2, status2 string
	var workAttempt2 int
	var reusedFrom sql.NullString
	if err := st.db.QueryRowContext(context.Background(),
		`SELECT derivation, status, work_attempt, reused_from_assessment_id FROM situation_assessment_attempts WHERE id = ?`, secondAttemptID).
		Scan(&derivation2, &status2, &workAttempt2, &reusedFrom); err != nil {
		t.Fatalf("read cycle 2 attempt: %v", err)
	}
	if status2 != "authoritative" {
		t.Fatalf("cycle 2 status = %q, want authoritative", status2)
	}
	if derivation2 != string(situationmodel.DerivationRevalidatedReuse) {
		t.Fatalf("cycle 2 derivation = %q, want %q", derivation2, situationmodel.DerivationRevalidatedReuse)
	}
	// Finding C1's core assertion: the FIXED nominal work_attempt (1, not the
	// pre-fix 0 that migration 0015's CHECK — work_attempt BETWEEN 1 AND 5 —
	// would have rejected outright).
	if workAttempt2 != 1 {
		t.Fatalf("cycle 2 (reuse) work_attempt = %d, want 1", workAttempt2)
	}
	if !reusedFrom.Valid || reusedFrom.String != firstAttemptID {
		t.Fatalf("cycle 2 reused_from_assessment_id = %v, want %s", reusedFrom, firstAttemptID)
	}
}
