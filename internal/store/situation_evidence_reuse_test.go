// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
)

// This catches current-cycle-only material identity: rotating the reads must
// not erase still-valid evidence or purchase another assessment of the same facts.
func TestPreparedEvidenceStableAcrossRotatingReadCycles(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	var warmHash string
	for i := 0; i < 8; i++ {
		capability := observationmodel.CapabilityPrometheusQuery
		kind := "metric_summary"
		if i%2 == 1 {
			capability, kind = observationmodel.CapabilityLokiQuery, "log_summary"
		}
		at := now.Add(time.Duration(i) * time.Minute)
		seedEvidenceCycle(t, st, claim, at, "config-a", capability, kind, `{"count":0}`, observationmodel.ResultConfirmedEmpty)
		in, err := st.LoadReconciliationInput(context.Background(), claim, at)
		if err != nil {
			t.Fatal(err)
		}
		hash := situation.BuildSnapshot(in).MaterialFactHash
		if i == 1 {
			warmHash = hash
		}
		if i > 1 && hash != warmHash {
			t.Fatalf("cycle %d changed material hash on unchanged evidence: got %s want %s", i, hash, warmHash)
		}
	}
	seedEvidenceCycle(t, st, claim, now.Add(8*time.Minute), "config-a", observationmodel.CapabilityPrometheusQuery, "metric_summary", `{"count":9}`, observationmodel.ResultConfirmedValue)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now.Add(8*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if situation.BuildSnapshot(in).MaterialFactHash == warmHash {
		t.Fatal("genuine new evidence did not invalidate reuse")
	}
}

func TestPreparedEvidenceExpiryInvalidatesReuse(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	seedEvidenceCycle(t, st, claim, now, "config-a", observationmodel.CapabilityPrometheusQuery, "metric_summary", `{"count":0}`, observationmodel.ResultConfirmedEmpty)
	fresh, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := st.LoadReconciliationInput(context.Background(), claim, now.Add(31*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if situation.BuildSnapshot(fresh).MaterialFactHash == situation.BuildSnapshot(expired).MaterialFactHash {
		t.Fatal("expired evidence was still treated as fresh material")
	}
}

func TestPreparedEvidenceFailedRefreshInvalidatesReuse(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	seedEvidenceCycle(t, st, claim, now, "config-a", observationmodel.CapabilityPrometheusQuery, "metric_summary", "", observationmodel.ResultConfirmedEmpty)
	fresh, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	seedEvidenceCycle(t, st, claim, now.Add(time.Minute), "config-a", observationmodel.CapabilityPrometheusQuery, "metric_summary", "", observationmodel.ResultFailed)
	failed, err := st.LoadReconciliationInput(context.Background(), claim, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if situation.BuildSnapshot(fresh).MaterialFactHash == situation.BuildSnapshot(failed).MaterialFactHash {
		t.Fatal("failed refresh with no facts was indistinguishable from a successful empty check")
	}
}

func TestPreparedEvidenceActuallyReachesAssessmentPrompt(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	seedEvidenceCycle(t, st, claim, now, "config-a", observationmodel.CapabilityPrometheusQuery, "metric_summary", `{"checkout_errors":73}`, observationmodel.ResultConfirmedValue)
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := situation.BuildAssessmentPrompt(situation.BuildSnapshot(in))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(strings.Fields(prompt.Text()), ""), `"checkout_errors":73`) {
		t.Fatal("evidence changes invalidate reuse but the resulting model prompt cannot see that evidence")
	}
}

func evidenceReuseFixture(t *testing.T) (*Store, situation.Claim, time.Time) {
	t.Helper()
	st := newTestStore(t)
	now := time.Date(2026, 9, 7, 10, 0, 0, 0, time.UTC)
	id := newSituationForGroup(t, st, "service=checkout", now.Add(-2*time.Hour))
	claim := claimSituation(t, st, id, "reuse-test", now)
	return st, claim, now
}

func seedEvidenceCycle(t *testing.T, st *Store, claim situation.Claim, now time.Time, config string, capability observationmodel.Capability, kind, value string, status observationmodel.ResultStatus, subjects ...string) {
	t.Helper()
	plan := testPlan(now)
	if len(subjects) > 0 {
		plan.Scope.SubjectID = subjects[0]
	}
	plan.Capability = capability
	seedEvidencePlanCycle(t, st, claim, now, config, plan, kind, value, status)
}

func seedEvidencePlanCycle(t *testing.T, st *Store, claim situation.Claim, now time.Time, config string, plan observationmodel.Plan, kind, value string, status observationmodel.ResultStatus) {
	t.Helper()
	ctx := context.Background()
	fence := observationmodel.Fence{SituationID: claim.Situation.ID, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{Anchor: now, ConfigDigest: config, Plans: []observationmodel.Plan{plan}}, 4)
	if err != nil {
		t.Fatal(err)
	}
	plan = cycle.Draft.Plans[0]
	run := observationmodel.Run{ID: "run:" + plan.ID, CycleID: cycle.ID, PlanID: plan.ID, Status: status,
		Coverage:   observationmodel.Coverage{Start: plan.Start, End: plan.End, Complete: status != observationmodel.ResultFailed},
		ObservedAt: now, ExpiresAt: now.Add(30 * time.Minute)}
	if value != "" {
		run.Facts = []observationmodel.Fact{{ID: "fact:" + plan.ID, RunID: run.ID, Kind: kind, Subject: plan.Scope.SubjectID,
			Digest: fmt.Sprintf("digest:%s", value), SchemaVersion: observationmodel.FactSchemaVersion, Value: []byte(value),
			ResultStatus: status, Freshness: observationmodel.FreshnessFresh, ObservedAt: now, ExpiresAt: run.ExpiresAt, Material: true}}
	}
	if err := st.CommitObservationRun(ctx, fence, run, now); err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := sealPreparationCycleTx(ctx, tx, claim.Situation.ID, cycle.ID, now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedEvidenceKeepsDistinctQuerySlots(t *testing.T) {
	for _, variation := range []string{"labels", "parameters", "window", "subsecond-window"} {
		t.Run(variation, func(t *testing.T) {
			st, claim, now := evidenceReuseFixture(t)
			first, second := testPlan(now), testPlan(now.Add(time.Minute))
			switch variation {
			case "labels":
				second.Scope.Labels = map[string]string{"service": "payments"}
			case "parameters":
				second.Parameters = []byte(`{"expression":"up{service=\"payments\"}"}`)
			case "window":
				second.Start = second.Start.Add(-time.Minute)
			case "subsecond-window":
				second.Start = second.Start.Add(-time.Nanosecond)
			}
			seedEvidencePlanCycle(t, st, claim, now, "config-a", first, "metric_summary", `{"count":0}`, observationmodel.ResultConfirmedEmpty)
			seedEvidencePlanCycle(t, st, claim, now.Add(time.Minute), "config-a", second, "metric_summary", `{"count":0}`, observationmodel.ResultConfirmedEmpty)
			in, err := st.LoadReconciliationInput(context.Background(), claim, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if len(in.Prepared.Runs) != 2 {
				t.Fatalf("distinct %s slots collapsed: got %d want 2", variation, len(in.Prepared.Runs))
			}
		})
	}
}

func TestPreparedEvidenceBoundsOversizedMetadata(t *testing.T) {
	for _, field := range []string{"labels", "labels_with_parameters"} {
		t.Run(field, func(t *testing.T) {
			st, claim, now := evidenceReuseFixture(t)
			plan := testPlan(now)
			large := strings.Repeat("x", 300*1024)
			plan.Scope.Labels["large_label"] = large
			if field == "labels_with_parameters" {
				plan.Parameters = json.RawMessage(`{"expression":"` + strings.Repeat("p", 8000) + `"}`)
			}
			seedEvidencePlanCycle(t, st, claim, now, "config-a", plan, "metric_summary", "", observationmodel.ResultConfirmedEmpty)
			in, err := st.LoadReconciliationInput(context.Background(), claim, now)
			if err != nil {
				t.Fatal(err)
			}
			snap := situation.BuildSnapshot(in)
			body, err := json.Marshal(struct { //nolint:musttag // observation facts are the existing transport-neutral prompt shape
				Checks []situation.ObservationCheck `json:"checks"`
				Facts  []observationmodel.Fact      `json:"facts"`
			}{snap.ObservationChecks, snap.Observations})
			if err != nil {
				t.Fatal(err)
			}
			if len(body) > observationmodel.MaxNormalizedBytesPerCycle {
				t.Fatalf("truncated evidence exposes %d bytes, cap %d", len(body), observationmodel.MaxNormalizedBytesPerCycle)
			}
			if !strings.Contains(string(body), "evidence_view_truncated") || strings.Contains(string(body), large) {
				t.Fatal("oversized metadata must become an explicit bounded evidence gap")
			}
		})
	}
}

func TestPreparedEvidenceBoundsAggregateMetadata(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	for i := range 4 {
		at := now.Add(time.Duration(i) * time.Second)
		plan := testPlan(at)
		plan.Scope.SubjectID = fmt.Sprintf("subject-%d", i)
		plan.Scope.Labels["large_label"] = strings.Repeat("x", 100*1024)
		seedEvidencePlanCycle(t, st, claim, at, "config-a", plan, "metric_summary", "", observationmodel.ResultConfirmedEmpty)
	}
	in, err := st.LoadReconciliationInput(context.Background(), claim, now.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	size, err := situation.PreparedEvidenceSize(in.Prepared)
	if err != nil {
		t.Fatal(err)
	}
	if size > observationmodel.MaxNormalizedBytesPerCycle {
		t.Fatalf("combined metadata is %d bytes, cap %d", size, observationmodel.MaxNormalizedBytesPerCycle)
	}
	snap := situation.BuildSnapshot(in)
	if len(snap.ObservationChecks) != 2 || len(in.Prepared.Runs) != 4 {
		t.Fatalf("want two readable checks and two explicit gaps, got %d checks / %d runs", len(snap.ObservationChecks), len(in.Prepared.Runs))
	}
}

func TestPreparedEvidenceEmptyCheckPromptNamesScopeAndWindow(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	seedEvidenceCycle(t, st, claim, now, "config-a", observationmodel.CapabilityPrometheusQuery, "metric_summary", "", observationmodel.ResultConfirmedEmpty, "checkout-api")
	in, err := st.LoadReconciliationInput(context.Background(), claim, now)
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := situation.BuildAssessmentPrompt(situation.BuildSnapshot(in))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"checkout-api", now.Add(-time.Minute).Format(time.RFC3339), "expression"} {
		if !strings.Contains(prompt.Text(), want) {
			t.Errorf("empty check prompt lacks %q", want)
		}
	}
}

func TestPreparedEvidenceKeepsDistinctSubjectsAndFencesConfiguration(t *testing.T) {
	st, claim, now := evidenceReuseFixture(t)
	for i, subject := range []string{"checkout-a", "checkout-b"} {
		seedEvidenceCycle(t, st, claim, now.Add(time.Duration(i)*time.Minute), "config-a", observationmodel.CapabilityPrometheusQuery, "metric_summary", `{"count":0}`, observationmodel.ResultConfirmedEmpty, subject)
	}
	in, err := st.LoadReconciliationInput(context.Background(), claim, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Prepared.Runs) != 2 {
		t.Fatalf("different subjects collapsed: got %d runs want 2", len(in.Prepared.Runs))
	}
	seedEvidenceCycle(t, st, claim, now.Add(3*time.Minute), "config-b", observationmodel.CapabilityPrometheusQuery, "metric_summary", `{"count":1}`, observationmodel.ResultConfirmedValue, "checkout-a")
	in, err = st.LoadReconciliationInput(context.Background(), claim, now.Add(3*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(in.Prepared.Runs) != 1 {
		t.Fatalf("old configuration evidence leaked: %d runs", len(in.Prepared.Runs))
	}
}

func TestAssessmentPersistsProviderUsageIncludingCache(t *testing.T) {
	for _, rejected := range []bool{false, true} {
		t.Run(fmt.Sprintf("rejected=%v", rejected), func(t *testing.T) {
			st := newTestStore(t)
			now := time.Now().UTC()
			id := seedReconcileSituation(t, st, "usage", now.Add(-2*time.Hour))
			response, err := acceptedProposalResponse(t)()
			if err != nil {
				t.Fatal(err)
			}
			response.InputTokens, response.CacheCreationInputTokens, response.CacheReadInputTokens, response.OutputTokens = 3, 100, 20, 11
			if rejected {
				response.Raw = []byte(`{}`)
			}
			client := &scriptedAssessmentClient{responses: []func() (llm.OneShotCompletion, error){func() (llm.OneShotCompletion, error) { return response, nil }}}
			controller := situation.NewController(st, client, situation.ControllerConfig{MaxL2CallsPerAttempt: 1}, func() time.Time { return now }, nil, nil)
			claim := claimSituation(t, st, id, "usage", now)
			if err := controller.Reconcile(context.Background(), claim); err != nil {
				t.Fatal(err)
			}
			var input, output sql.NullInt64
			if err := st.db.QueryRowContext(context.Background(), `SELECT usage_input_tokens, usage_output_tokens FROM situation_assessment_attempts WHERE situation_id = ? AND call_id IS NOT NULL`, id).Scan(&input, &output); err != nil {
				t.Fatal(err)
			}
			if !input.Valid || input.Int64 != 123 || !output.Valid || output.Int64 != 11 {
				t.Fatalf("lost provider usage: input=%v output=%v, want 123/11", input, output)
			}
		})
	}
}

func TestControllerRotatingEvidencePerformsNoFurtherModelCalls(t *testing.T) {
	st := newTestStore(t)
	now := time.Now().UTC()
	id := seedReconcileSituation(t, st, "quiet-replay", now.Add(-2*time.Hour))
	client := &scriptedAssessmentClient{responses: []func() (llm.OneShotCompletion, error){acceptedProposalResponse(t)}}
	controller := situation.NewController(st, client, situation.ControllerConfig{Cadence: situation.CadenceTempo{Fast: time.Minute, Normal: time.Minute, Slow: time.Minute}}, func() time.Time { return now }, nil, nil)
	for i := 0; i < 8; i++ {
		claim := claimSituation(t, st, id, "quiet-replay", now)
		if i == 0 {
			seedEvidenceCycle(t, st, claim, now, "config-a", observationmodel.CapabilityLokiQuery, "log_summary", `{"count":0}`, observationmodel.ResultConfirmedEmpty)
		}
		capability, kind := observationmodel.CapabilityPrometheusQuery, "metric_summary"
		if i%2 == 1 {
			capability, kind = observationmodel.CapabilityLokiQuery, "log_summary"
		}
		seedEvidenceCycle(t, st, claim, now, "config-a", capability, kind, `{"count":0}`, observationmodel.ResultConfirmedEmpty)
		if err := controller.Reconcile(context.Background(), claim); err != nil {
			t.Fatalf("cycle %d: %v", i, err)
		}
		if client.calls != 1 {
			t.Fatalf("cycle %d: %d provider calls, want only the first assessment", i, client.calls)
		}
		now = now.Add(2 * time.Minute)
	}
	var calls, reused int
	if err := st.db.QueryRowContext(context.Background(), `SELECT count(*) FROM situation_assessment_calls WHERE situation_id = ?`, id).Scan(&calls); err != nil {
		t.Fatal(err)
	}
	if err := st.db.QueryRowContext(context.Background(), `SELECT count(*) FROM situation_assessment_attempts WHERE situation_id = ? AND derivation = 'revalidated_reuse'`, id).Scan(&reused); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || reused != 7 {
		t.Fatalf("durable results: calls=%d reuse=%d, want 1/7", calls, reused)
	}
}
