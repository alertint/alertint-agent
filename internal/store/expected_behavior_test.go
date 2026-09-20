// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

type expectedBehaviorFixture struct {
	situationID string
	judgmentID  string
	now         time.Time
	policy      situationmodel.ExpectedBehaviorPolicy
}

func newExpectedBehaviorFixture(t *testing.T, st *Store) expectedBehaviorFixture {
	t.Helper()
	ctx := context.Background()
	now := time.Date(2026, 9, 21, 19, 5, 0, 0, time.UTC)
	situationID := zabbixJudgmentSituationFixture(t, st, now)
	claim := claimSituation(t, st, situationID, "expected-behavior-source", now)
	fence := observationmodel.Fence{SituationID: situationID, InputVersion: claim.Situation.InputVersion, Owner: claim.ClaimOwner, Token: claim.ClaimToken}
	plan := testPlan(now)
	plan.Capability, plan.Scope.Source = observationmodel.CapabilityZabbixProblemHist, "zabbix"
	plan.Parameters = json.RawMessage(`{"host":"db-01","trigger_id":"18422","source_instance_id":"prod-zbx"}`)
	cycle, err := st.BeginPreparation(ctx, fence, observationmodel.CycleDraft{
		Anchor: now, ConfigDigest: "cfg-expected-behavior", RefreshInterval: 5 * time.Minute,
		Plans: []observationmodel.Plan{plan},
	}, 6)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CommitObservationRun(ctx, fence, sourceDefinitionRun(t, cycle.Draft.Plans[0], "run:expected-behavior", "fact:expected-behavior", "sha256:v1", "sha256:fact-v1", now), now); err != nil {
		t.Fatal(err)
	}
	if err := st.ReleaseSituationClaim(ctx, claim.Situation, now); err != nil {
		t.Fatal(err)
	}
	sit, err := st.GetSituation(ctx, situationID)
	if err != nil {
		t.Fatal(err)
	}
	judgment, err := st.WriteSituationJudgment(ctx, audit.New(st.DB()), SituationJudgmentWrite{
		Operation: situationmodel.JudgmentOperationRecord, SituationID: situationID,
		SituationInputVersion: sit.InputVersion, ExpectedJudgmentVersion: 0,
		RequestID: "expected-behavior-source-judgment", AssertedOperator: "Janis", Confirmed: true,
		ValidUntil: now.Add(4 * time.Hour), Now: now.Add(time.Second),
	})
	if err != nil {
		t.Fatal(err)
	}
	return expectedBehaviorFixture{
		situationID: situationID, judgmentID: judgment.Judgment.ID, now: now.Add(2 * time.Second),
		policy: situationmodel.ExpectedBehaviorPolicy{
			Scope: situationmodel.ExpectedBehaviorScope{
				GroupKey: "host=db-01", Source: "zabbix", SourceInstanceID: "prod-zbx", Host: "db-01",
				PrimaryTriggerID: "18422", PrimaryTriggerVersion: "sha256:v1",
			},
			Conditions: situationmodel.ExpectedBehaviorConditions{
				Workload: "nightly_reconciliation",
				Schedule: situationmodel.ExpectedBehaviorSchedule{
					Days:       []situationmodel.ExpectedBehaviorWeekday{situationmodel.ExpectedBehaviorMonday},
					LocalStart: "22:00", LocalEnd: "06:00", Timezone: "Europe/Riga", StartToleranceMinutes: 10,
				},
				MaxDurationMinutes: 55,
			},
			ReviewDueAt: now.Add(30 * 24 * time.Hour),
		},
	}
}

func (f expectedBehaviorFixture) confirmRequest(t *testing.T, st *Store, requestID string) ExpectedBehaviorWrite {
	t.Helper()
	sit, err := st.GetSituation(context.Background(), f.situationID)
	if err != nil {
		t.Fatal(err)
	}
	return ExpectedBehaviorWrite{
		Operation:        situationmodel.ExpectedBehaviorOperationConfirm,
		SourceJudgmentID: f.judgmentID, SituationID: f.situationID, SituationInputVersion: sit.InputVersion,
		ExpectedCurrentVersion: 0, RequestID: requestID, AssertedOperator: "Janis", Confirmed: true,
		Policy: &f.policy, Now: f.now,
	}
}

func TestWriteExpectedBehaviorConfirmIsAtomicVersionedAndIdempotent(t *testing.T) {
	st := newTestStore(t)
	fixture := newExpectedBehaviorFixture(t, st)
	req := fixture.confirmRequest(t, st, "expected-confirm")
	first, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), req)
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if first.Revision.Version != 1 || first.Revision.State != situationmodel.ExpectedBehaviorStateActive || first.Revision.EnvelopeID == "" {
		t.Fatalf("first result = %+v", first)
	}
	after, _ := st.GetSituation(context.Background(), fixture.situationID)
	if !hasDueReason(after.DueReasons, situationmodel.DueEnvelopeChanged) || after.InputVersion != req.SituationInputVersion+1 {
		t.Fatalf("situation after confirm = version %d due %v", after.InputVersion, after.DueReasons)
	}
	replay, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), req)
	if err != nil || !replay.IdempotentReplay || replay.Revision.ID != first.Revision.ID {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	changed := req
	changed.Policy = cloneExpectedBehaviorPolicy(req.Policy)
	changed.Policy.Conditions.MaxDurationMinutes++
	if _, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), changed); !errors.Is(err, ErrExpectedBehaviorRequestConflict) {
		t.Fatalf("changed replay error = %v, want request conflict", err)
	}
}

func TestWriteExpectedBehaviorAuditFailureRollsBackRevisionAndWake(t *testing.T) {
	st := newTestStore(t)
	fixture := newExpectedBehaviorFixture(t, st)
	req := fixture.confirmRequest(t, st, "expected-rollback")
	before, _ := st.GetSituation(context.Background(), fixture.situationID)
	injected := errors.New("audit unavailable")
	_, err := st.WriteExpectedBehavior(context.Background(), failingJudgmentAuditor{injected}, req)
	if !errors.Is(err, injected) {
		t.Fatalf("write error = %v, want injected", err)
	}
	assertTableCount(t, st.DB(), "expected_behavior_envelope_revisions", 0)
	after, _ := st.GetSituation(context.Background(), fixture.situationID)
	if after.InputVersion != before.InputVersion || !after.NextAssessmentAt.Equal(before.NextAssessmentAt) {
		t.Fatalf("partial wake persisted: before=%+v after=%+v", before, after)
	}
}

func TestWriteExpectedBehaviorReplaceRevokeRestoreKeepsImmutableHistory(t *testing.T) {
	st := newTestStore(t)
	fixture := newExpectedBehaviorFixture(t, st)
	first, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), fixture.confirmRequest(t, st, "expected-history-confirm"))
	if err != nil {
		t.Fatal(err)
	}

	replace := fixture.confirmRequest(t, st, "expected-history-replace")
	replace.Operation = situationmodel.ExpectedBehaviorOperationReplace
	replace.EnvelopeID = first.Revision.EnvelopeID
	replace.ExpectedCurrentVersion = 1
	replace.Policy = cloneExpectedBehaviorPolicy(replace.Policy)
	replace.Policy.Conditions.MaxDurationMinutes = 65
	replace.Now = fixture.now.Add(time.Minute)
	second, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), replace)
	if err != nil || second.Revision.Version != 2 {
		t.Fatalf("replace = %+v, %v", second, err)
	}

	revoke := ExpectedBehaviorWrite{
		Operation: situationmodel.ExpectedBehaviorOperationRevoke, EnvelopeID: first.Revision.EnvelopeID,
		ExpectedCurrentVersion: 2, RequestID: "expected-history-revoke", AssertedOperator: "Janis", Confirmed: true,
		Now: fixture.now.Add(2 * time.Minute),
	}
	third, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), revoke)
	if err != nil || third.Revision.Version != 3 || third.Revision.State != situationmodel.ExpectedBehaviorStateRevoked {
		t.Fatalf("revoke = %+v, %v", third, err)
	}
	head, err := st.GetExpectedBehavior(context.Background(), first.Revision.EnvelopeID)
	if err != nil || head.State != situationmodel.ExpectedBehaviorStateRevoked || head.Policy != nil || head.Scope.GroupKey != fixture.policy.Scope.GroupKey {
		t.Fatalf("revoked head = %+v, %v", head, err)
	}

	restore := fixture.confirmRequest(t, st, "expected-history-restore")
	restore.Operation = situationmodel.ExpectedBehaviorOperationRestore
	restore.EnvelopeID = first.Revision.EnvelopeID
	restore.ExpectedCurrentVersion = 3
	restore.Now = fixture.now.Add(3 * time.Minute)
	fourth, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), restore)
	if err != nil || fourth.Revision.Version != 4 || fourth.Revision.State != situationmodel.ExpectedBehaviorStateActive {
		t.Fatalf("restore = %+v, %v", fourth, err)
	}
	history, err := st.ListExpectedBehaviorHistory(context.Background(), first.Revision.EnvelopeID, 0, 10)
	if err != nil || len(history) != 4 || history[0].ID != first.Revision.ID || history[3].ID != fourth.Revision.ID {
		t.Fatalf("history = %+v, %v", history, err)
	}
}

func TestWriteExpectedBehaviorRejectsStaleSituationJudgmentAndEnvelopeVersions(t *testing.T) {
	st := newTestStore(t)
	fixture := newExpectedBehaviorFixture(t, st)
	req := fixture.confirmRequest(t, st, "expected-stale-situation")
	req.SituationInputVersion--
	if _, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), req); !errors.Is(err, ErrSituationVersionConflict) {
		t.Fatalf("stale Situation error = %v", err)
	}
	req = fixture.confirmRequest(t, st, "expected-stale-judgment")
	req.SourceJudgmentID = "missing-judgment"
	if _, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), req); !errors.Is(err, ErrExpectedBehaviorNotAllowed) {
		t.Fatalf("stale judgment error = %v", err)
	}
	first, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), fixture.confirmRequest(t, st, "expected-current"))
	if err != nil {
		t.Fatal(err)
	}
	revoke := ExpectedBehaviorWrite{
		Operation: situationmodel.ExpectedBehaviorOperationRevoke, EnvelopeID: first.Revision.EnvelopeID,
		ExpectedCurrentVersion: 2, RequestID: "expected-stale-envelope", AssertedOperator: "Janis", Confirmed: true,
		Now: fixture.now.Add(time.Minute),
	}
	if _, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), revoke); !errors.Is(err, ErrExpectedBehaviorVersionConflict) {
		t.Fatalf("stale envelope error = %v", err)
	}
}

func TestInvalidateExpectedBehaviorIsAtomicMonotonicAndWakesScope(t *testing.T) {
	st := newTestStore(t)
	fixture := newExpectedBehaviorFixture(t, st)
	created, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), fixture.confirmRequest(t, st, "expected-invalidate-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := st.GetSituation(context.Background(), fixture.situationID)
	changed, err := st.InvalidateExpectedBehavior(context.Background(), audit.New(st.DB()), created.Revision.EnvelopeID, 1,
		situationmodel.ExpectedBehaviorPrimaryDefinitionChanged, map[string]any{"observed_version": "sha256:v2"}, fixture.now.Add(time.Minute))
	if err != nil || !changed {
		t.Fatalf("invalidate = changed %v, err %v", changed, err)
	}
	head, err := st.GetExpectedBehavior(context.Background(), created.Revision.EnvelopeID)
	if err != nil || head.InvalidatedAt == nil || head.InvalidationReason != situationmodel.ExpectedBehaviorPrimaryDefinitionChanged {
		t.Fatalf("invalidated head = %+v, %v", head, err)
	}
	after, _ := st.GetSituation(context.Background(), fixture.situationID)
	if after.InputVersion != before.InputVersion+1 || !hasDueReason(after.DueReasons, situationmodel.DueEnvelopeChanged) {
		t.Fatalf("scope was not woken: before=%d after=%d due=%v", before.InputVersion, after.InputVersion, after.DueReasons)
	}
	changed, err = st.InvalidateExpectedBehavior(context.Background(), audit.New(st.DB()), created.Revision.EnvelopeID, 1,
		situationmodel.ExpectedBehaviorPrimaryDefinitionChanged, map[string]any{"observed_version": "sha256:v2"}, fixture.now.Add(2*time.Minute))
	if err != nil || changed {
		t.Fatalf("repeat invalidation = changed %v, err %v", changed, err)
	}
	assertTableCount(t, st.DB(), "expected_behavior_system_events", 1)
	events, err := st.ListExpectedBehaviorSystemEvents(context.Background(), created.Revision.EnvelopeID)
	if err != nil || len(events) != 1 {
		t.Fatalf("system events = %+v, %v", events, err)
	}
	if events[0].EnvelopeVersion != 1 || events[0].Reason != situationmodel.ExpectedBehaviorPrimaryDefinitionChanged || events[0].Evidence["observed_version"] != "sha256:v2" {
		t.Fatalf("invalidation event = %+v", events[0])
	}
}

func TestExpectedBehaviorOverviewCountsDistinctSituations(t *testing.T) {
	st := newTestStore(t)
	f := newExpectedBehaviorFixture(t, st)
	created, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), f.confirmRequest(t, st, "overview-count-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		_, err = st.DB().ExecContext(context.Background(), `INSERT INTO expected_behavior_evaluations
			(id,situation_id,situation_input_version,disposition,reason,chosen_envelope_id,chosen_version,evaluation_json,basis_hash,evaluated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?)`,
			"usage-evaluation-"+string(rune('a'+i)), f.situationID, i+1, "matched", "matched", created.Revision.EnvelopeID, 1,
			`{"disposition":"matched","candidates":[]}`, "usage-basis-"+string(rune('a'+i)), canonicalTime(f.now.Add(time.Duration(i)*time.Minute)))
		if err != nil {
			t.Fatal(err)
		}
	}
	overview, err := st.GetExpectedBehaviorOverview(context.Background(), created.Revision.EnvelopeID, f.policy.ReviewDueAt)
	if err != nil {
		t.Fatal(err)
	}
	if overview.Usage.MatchCount != 1 || overview.Review.Status != "due" {
		t.Fatalf("overview = %+v", overview)
	}
}

func TestCommitExpectedBehaviorEvaluationFencesEnvelopeAndSituationVersions(t *testing.T) {
	st := newTestStore(t)
	fixture := newExpectedBehaviorFixture(t, st)
	created, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), fixture.confirmRequest(t, st, "expected-evaluation-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	sit, _ := st.GetSituation(context.Background(), fixture.situationID)
	evaluation := situationmodel.ExpectedBehaviorEvaluation{
		SituationID: fixture.situationID, SituationVersion: sit.InputVersion,
		Disposition: situationmodel.ExpectedBehaviorDispositionMatched, Reason: situationmodel.ExpectedBehaviorReasonMatched,
		ChosenEnvelopeID: created.Revision.EnvelopeID, ChosenVersion: 1, BasisHash: "sha256:evaluation-v1",
		Candidates:  []situationmodel.ExpectedBehaviorCandidate{{EnvelopeID: created.Revision.EnvelopeID, Version: 1, Status: situationmodel.ExpectedBehaviorMatched, Reason: situationmodel.ExpectedBehaviorReasonMatched}},
		EvaluatedAt: fixture.now.Add(time.Minute),
	}
	committed, err := st.CommitExpectedBehaviorEvaluation(context.Background(), evaluation)
	if err != nil || committed.ID == "" {
		t.Fatalf("commit evaluation = %+v, %v", committed, err)
	}
	current, found, err := st.GetCurrentExpectedBehaviorEvaluation(context.Background(), fixture.situationID)
	if err != nil || !found || current.ID != committed.ID || current.BasisHash != evaluation.BasisHash {
		t.Fatalf("current evaluation = %+v found=%v err=%v", current, found, err)
	}

	revoke := ExpectedBehaviorWrite{
		Operation: situationmodel.ExpectedBehaviorOperationRevoke, EnvelopeID: created.Revision.EnvelopeID,
		ExpectedCurrentVersion: 1, RequestID: "expected-evaluation-revoke", AssertedOperator: "Janis", Confirmed: true,
		Now: fixture.now.Add(2 * time.Minute),
	}
	if _, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), revoke); err != nil {
		t.Fatal(err)
	}
	evaluation.BasisHash = "sha256:stale-evaluation"
	evaluation.SituationVersion = getSituationByID(t, st, fixture.situationID).InputVersion
	if _, err := st.CommitExpectedBehaviorEvaluation(context.Background(), evaluation); !errors.Is(err, ErrExpectedBehaviorStale) {
		t.Fatalf("stale envelope evaluation error = %v", err)
	}
}

func TestExpectedBehaviorBoundaryExpiresAfterRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "expected-restart.db")
	st, err := openTestStoreWithMigrations(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	f := newExpectedBehaviorFixture(t, st)
	created, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), f.confirmRequest(t, st, "expected-restart-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	sit, err := st.GetSituation(context.Background(), f.situationID)
	if err != nil {
		t.Fatal(err)
	}
	boundary := f.now.Add(time.Hour)
	evaluation := situationmodel.ExpectedBehaviorEvaluation{
		SituationID: f.situationID, SituationVersion: sit.InputVersion, Disposition: situationmodel.ExpectedBehaviorDispositionMatched,
		Reason: situationmodel.ExpectedBehaviorReasonMatched, ChosenEnvelopeID: created.Revision.EnvelopeID, ChosenVersion: 1,
		Occurrence: &situationmodel.ExpectedBehaviorOccurrence{Start: f.now, End: boundary, Boundary: boundary},
		Candidates: []situationmodel.ExpectedBehaviorCandidate{{EnvelopeID: created.Revision.EnvelopeID, Version: 1, Status: situationmodel.ExpectedBehaviorMatched, Reason: situationmodel.ExpectedBehaviorReasonMatched}},
		BasisHash:  "sha256:restart-boundary", EvaluatedAt: f.now,
	}
	if _, err := st.CommitExpectedBehaviorEvaluation(context.Background(), evaluation); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = openTestStoreWithMigrations(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	current, found, err := st.GetCurrentExpectedBehaviorEvaluationAt(context.Background(), f.situationID, boundary)
	if err != nil || !found || current.Disposition != situationmodel.ExpectedBehaviorDispositionViolated || current.ChosenEnvelopeID != "" {
		t.Fatalf("current after restart/boundary = %+v, found=%v err=%v", current, found, err)
	}
}

func TestListExpectedBehaviorsFiltersInactiveHeads(t *testing.T) {
	st := newTestStore(t)
	fixture := newExpectedBehaviorFixture(t, st)
	created, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), fixture.confirmRequest(t, st, "expected-list-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	active, err := st.ListExpectedBehaviors(context.Background(), ExpectedBehaviorListFilter{GroupKey: "host=db-01"}, 10)
	if err != nil || len(active) != 1 || active[0].EnvelopeID != created.Revision.EnvelopeID {
		t.Fatalf("active list = %+v, %v", active, err)
	}
	revoke := ExpectedBehaviorWrite{
		Operation: situationmodel.ExpectedBehaviorOperationRevoke, EnvelopeID: created.Revision.EnvelopeID,
		ExpectedCurrentVersion: 1, RequestID: "expected-list-revoke", AssertedOperator: "Janis", Confirmed: true,
		Now: fixture.now.Add(time.Minute),
	}
	if _, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), revoke); err != nil {
		t.Fatal(err)
	}
	active, err = st.ListExpectedBehaviors(context.Background(), ExpectedBehaviorListFilter{GroupKey: "host=db-01"}, 10)
	if err != nil || len(active) != 0 {
		t.Fatalf("active list after revoke = %+v, %v", active, err)
	}
	all, err := st.ListExpectedBehaviors(context.Background(), ExpectedBehaviorListFilter{GroupKey: "host=db-01", IncludeInactive: true}, 10)
	if err != nil || len(all) != 1 || all[0].State != situationmodel.ExpectedBehaviorStateRevoked {
		t.Fatalf("inactive list = %+v, %v", all, err)
	}
}

func TestConcurrentExpectedBehaviorReplacementAllowsOneWriter(t *testing.T) {
	st := newTestStore(t)
	fixture := newExpectedBehaviorFixture(t, st)
	created, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), fixture.confirmRequest(t, st, "expected-race-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	base := fixture.confirmRequest(t, st, "expected-race-a")
	base.Operation = situationmodel.ExpectedBehaviorOperationReplace
	base.EnvelopeID = created.Revision.EnvelopeID
	base.ExpectedCurrentVersion = 1
	base.Now = fixture.now.Add(time.Minute)
	other := base
	other.RequestID = "expected-race-b"
	other.Policy = cloneExpectedBehaviorPolicy(base.Policy)
	other.Policy.Conditions.MaxDurationMinutes++

	errs := make(chan error, 2)
	for _, req := range []ExpectedBehaviorWrite{base, other} {
		go func(write ExpectedBehaviorWrite) {
			_, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), write)
			errs <- err
		}(req)
	}
	success, conflict := 0, 0
	for range 2 {
		err := <-errs
		switch {
		case err == nil:
			success++
		case errors.Is(err, ErrExpectedBehaviorVersionConflict) || errors.Is(err, ErrSituationVersionConflict):
			conflict++
		default:
			t.Fatalf("unexpected writer error: %v", err)
		}
	}
	if success != 1 || conflict != 1 {
		t.Fatalf("success=%d conflict=%d", success, conflict)
	}
}

func cloneExpectedBehaviorPolicy(in *situationmodel.ExpectedBehaviorPolicy) *situationmodel.ExpectedBehaviorPolicy {
	if in == nil {
		return nil
	}
	b, err := json.Marshal(in)
	if err != nil {
		return nil
	}
	var out situationmodel.ExpectedBehaviorPolicy
	_ = json.Unmarshal(b, &out)
	return &out
}
