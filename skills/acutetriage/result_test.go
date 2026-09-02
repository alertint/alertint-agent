// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// capturingAfterCommitNotifier records whether Notify was ever called — used
// to prove Analyze itself never reaches the notifier (that is AfterCommit's
// job, run only post-commit).
type spyNotifier struct {
	calls int
}

func (n *spyNotifier) Notify(_ context.Context, _ notify.Finding) error {
	n.calls++
	return nil
}
func (n *spyNotifier) Name() string { return "spy" }

// TestAnalyze_NoDurableSideEffects is Task 7's core side-effect test: a
// successful Analyze call must load only what it needs, return every
// durable AcuteResult field, and change NO Incident, Finding, role, memory
// mark, notifier, or terminal audit state. Analyze's own non-terminal
// action-trail audits (analysis_started, enrichment digests) ARE expected —
// only the terminal incident.analyzed / incident.memory_recalled rows (held
// in PostCommit.AuditRecords instead) must be absent until AfterCommit
// actually appends them.
func TestAnalyze_NoDurableSideEffects(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1, d1 := insertTestAlertDelivery(t, st, ctx, inc.ID, "fp-analyze-1",
		map[string]string{"alertname": "DiskFull", "host": "web1"}, map[string]string{"summary": "disk is full"})
	a2, d2 := insertTestAlertDelivery(t, st, ctx, inc.ID, "fp-analyze-2",
		map[string]string{"alertname": "DiskFull", "host": "web1"}, map[string]string{"summary": "disk is full"})

	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID})}
	auditor := audit.New(st.DB())
	notifier := &spyNotifier{}
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, fllm, auditor, notifier, nil)

	claim := situation.TriageAttemptClaim{IncidentID: inc.ID, AttemptID: "attempt-1", AttemptNumber: 1, MemberDeliveryIDs: []string{d1, d2}}
	result, err := skill.Analyze(ctx, claim)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}

	// -- durable AcuteResult data --
	if result.IncidentID != inc.ID {
		t.Errorf("IncidentID = %q, want %q", result.IncidentID, inc.ID)
	}
	if result.EvidencePackDigest == "" || !strings.HasPrefix(result.EvidencePackDigest, "sha256:") {
		t.Errorf("EvidencePackDigest = %q, want a sha256:... digest", result.EvidencePackDigest)
	}
	if len(result.OutputJSON) == 0 {
		t.Error("OutputJSON is empty, want the model's finding JSON")
	}
	if result.AnalysisName == "" {
		t.Error("AnalysisName is empty")
	}
	if result.Summary != result.AnalysisName {
		t.Errorf("Summary = %q, want it to mirror AnalysisName (%q) — the persisted 'summary' column convention", result.Summary, result.AnalysisName)
	}
	if result.RootCause == "" {
		t.Error("RootCause is empty")
	}
	if result.Confidence <= 0 {
		t.Errorf("Confidence = %v, want > 0", result.Confidence)
	}
	// AlertRoles: itemized (a1) plus defaulted (a2) — computed, not yet
	// written anywhere.
	if result.AlertRoles[a1.ID] != "primary" {
		t.Errorf("AlertRoles[a1] = %q, want primary (model itemized it)", result.AlertRoles[a1.ID])
	}
	if result.AlertRoles[a2.ID] != "correlated" {
		t.Errorf("AlertRoles[a2] = %q, want correlated (defaulted)", result.AlertRoles[a2.ID])
	}

	// -- no durable Incident change --
	after, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil || after == nil {
		t.Fatalf("reload incident: %v", err)
	}
	if after.Status != "ready" {
		t.Errorf("incident status = %q, want unchanged ready (Analyze must not write Incident state)", after.Status)
	}
	if after.OutputJSON != "" || after.Summary != "" || after.RootCause != "" {
		t.Errorf("incident output/summary/root_cause were written by Analyze: %+v", after)
	}

	// -- no role write --
	rows, err := st.DB().QueryContext(ctx, `SELECT role FROM incident_alerts WHERE incident_id = ?`, inc.ID)
	if err != nil {
		t.Fatalf("query roles: %v", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var role *string
		if err := rows.Scan(&role); err != nil {
			t.Fatalf("scan role: %v", err)
		}
		if role != nil {
			t.Errorf("incident_alerts.role = %q, want NULL (Analyze must not write roles)", *role)
		}
	}

	// -- no notifier call --
	if notifier.calls != 0 {
		t.Errorf("notifier called %d times, want 0 (Analyze must never notify)", notifier.calls)
	}

	// -- no terminal audit state --
	var analyzedCount int
	if err := st.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE kind = 'incident.analyzed'`).Scan(&analyzedCount); err != nil {
		t.Fatalf("count analyzed audit rows: %v", err)
	}
	if analyzedCount != 0 {
		t.Errorf("incident.analyzed audit rows = %d, want 0 (deferred to AfterCommit's PostCommit.AuditRecords)", analyzedCount)
	}

	// -- PostCommit carries what AfterCommit needs --
	if len(result.PostCommit.CompatibilityFindingJSON) == 0 {
		t.Fatal("PostCommit.CompatibilityFindingJSON is empty")
	}
	var f notify.Finding
	if err := json.Unmarshal(result.PostCommit.CompatibilityFindingJSON, &f); err != nil {
		t.Fatalf("unmarshal compatibility finding: %v", err)
	}
	if f.AnalysisName != result.AnalysisName {
		t.Errorf("compatibility finding AnalysisName = %q, want %q", f.AnalysisName, result.AnalysisName)
	}
	if f.OutputJSON != nil {
		t.Error("compatibility finding must carry no provider body (OutputJSON) — AfterCommit fills it from AcuteResult itself")
	}
	foundAnalyzedRecord := false
	for _, rec := range result.PostCommit.AuditRecords {
		if rec.Kind == "incident.analyzed" {
			foundAnalyzedRecord = true
		}
	}
	if !foundAnalyzedRecord {
		t.Error("PostCommit.AuditRecords missing a held incident.analyzed record for AfterCommit to append")
	}
}

// TestAnalyze_NoMemberAlertsReturnsErrCleanSkip: an incident with zero member
// alerts is a typed clean skip, never a zero result with a nil error.
func TestAnalyze_NoMemberAlertsReturnsErrCleanSkip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)

	skill := acutetriage.New(acutetriage.Config{}, st, &fakeLLM{}, nil, nil, nil)
	claim := situation.TriageAttemptClaim{IncidentID: inc.ID}
	result, err := skill.Analyze(ctx, claim)
	if !errors.Is(err, acutetriage.ErrCleanSkip) {
		t.Fatalf("Analyze err = %v, want ErrCleanSkip", err)
	}
	if !errors.Is(err, situation.ErrCleanSkip) {
		t.Fatalf("acutetriage.ErrCleanSkip must alias situation.ErrCleanSkip (TriageWorker checks the latter)")
	}
	if result.IncidentID != "" || result.OutputJSON != nil {
		t.Fatalf("result = %+v, want the zero value on a clean skip", result)
	}
}

// TestAnalyze_BelowMinAlertsReturnsErrCleanSkip mirrors the no-alerts case
// for the configured MinAlerts threshold.
func TestAnalyze_BelowMinAlertsReturnsErrCleanSkip(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	_, d1 := insertTestAlertDelivery(t, st, ctx, inc.ID, "fp-below-min",
		map[string]string{"alertname": "DiskFull"}, map[string]string{"summary": "disk is full"})

	skill := acutetriage.New(acutetriage.Config{MinAlerts: 2}, st, &fakeLLM{}, nil, nil, nil)
	claim := situation.TriageAttemptClaim{IncidentID: inc.ID, MemberDeliveryIDs: []string{d1}}
	_, err := skill.Analyze(ctx, claim)
	if !errors.Is(err, acutetriage.ErrCleanSkip) {
		t.Fatalf("Analyze err = %v, want ErrCleanSkip", err)
	}
}

// TestAnalyze_ShortCircuitSkipsDefaultedRoles proves a rule short-circuit's
// synthesized response (which already itemizes every member) does not get
// a spurious "correlated" default layered on top, matching the pre-Task-7
// defaultUnitemizedRoles gate.
func TestAnalyze_ShortCircuitSkipsDefaultedRoles(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1, d1 := insertTestAlertDelivery(t, st, ctx, inc.ID, "fp-sc-1",
		map[string]string{"alertname": "KnownDiskIssue"}, map[string]string{"summary": "disk is full"})
	a2, d2 := insertTestAlertDelivery(t, st, ctx, inc.ID, "fp-sc-2",
		map[string]string{"alertname": "KnownDiskIssue"}, map[string]string{"summary": "disk is full"})

	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1, Rules: newLocalRuleEngine(t)}, st, &fakeLLM{}, nil, nil, nil)
	claim := situation.TriageAttemptClaim{IncidentID: inc.ID, MemberDeliveryIDs: []string{d1, d2}}
	result, err := skill.Analyze(ctx, claim)
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if result.AlertRoles[a1.ID] != "correlated" || result.AlertRoles[a2.ID] != "correlated" {
		t.Errorf("AlertRoles = %+v, want both correlated (the rule's own itemization)", result.AlertRoles)
	}
}

// TestAnalyze_UsesFrozenClaimContentNotLaterAlertMutation is the Task 7 fix
// round's own regression proof for Finding #1: once a delivery is accepted
// and a claim names it, mutating the SHARED alerts row for the same
// fingerprint (the re-fire race Finding #1 describes — a fresh delivery for
// an already-attached alert changes the mutable alerts row in place via
// AcceptDeliveries' own ON CONFLICT(fingerprint)) must never change what
// Analyze actually sees for that claim: it must keep using the frozen,
// pre-mutation content, never the current mutated content. This is the
// test that would have caught the pre-fix bug (Analyze reading
// GetIncidentAlerts' current mutable projection).
func TestAnalyze_UsesFrozenClaimContentNotLaterAlertMutation(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1, d1 := insertTestAlertDelivery(t, st, ctx, inc.ID, "fp-frozen",
		map[string]string{"alertname": "DiskFull", "host": "web1"},
		map[string]string{"summary": "ORIGINAL FROZEN SUMMARY"})

	// Simulate the re-fire race: a LATER delivery for the same fingerprint
	// mutates the shared alerts row in place, without this claim's own
	// frozen membership/delivery set ever changing (this claim only ever
	// names d1).
	mutated := store.Alert{
		ID:          a1.ID,
		Fingerprint: "fp-frozen",
		Status:      "firing",
		Labels:      map[string]string{"alertname": "DiskFull", "host": "web1"},
		Annotations: map[string]string{"summary": "MUTATED SUMMARY AFTER CLAIM"},
		StartsAt:    time.Now().UTC(),
		ReceivedAt:  time.Now().UTC(),
	}
	if _, err := st.UpsertAlertByFingerprint(ctx, mutated); err != nil {
		t.Fatalf("mutate shared alerts row: %v", err)
	}
	current, err := st.GetAlertByFingerprint(ctx, "fp-frozen")
	if err != nil || current.Annotations["summary"] != "MUTATED SUMMARY AFTER CLAIM" {
		t.Fatalf("test setup broken: shared alerts row did not actually mutate: %+v, err=%v", current, err)
	}

	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID})}
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, fllm, nil, nil, nil)
	claim := situation.TriageAttemptClaim{IncidentID: inc.ID, AttemptID: "attempt-frozen", AttemptNumber: 1, MemberDeliveryIDs: []string{d1}}

	if _, err := skill.Analyze(ctx, claim); err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if !strings.Contains(fllm.lastUser, "ORIGINAL FROZEN SUMMARY") {
		t.Errorf("LLM prompt did not contain the frozen original content")
	}
	if strings.Contains(fllm.lastUser, "MUTATED SUMMARY AFTER CLAIM") {
		t.Errorf("LLM prompt contained the LATER mutated content — Analyze read the current mutable alerts row instead of the frozen claim")
	}
}
