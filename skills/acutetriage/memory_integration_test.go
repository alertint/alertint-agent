// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// absentVerdict signals respWithVerdict to omit the memory_verdict key entirely
// (the model rendered memory but returned no verdict).
const absentVerdict = "__absent__"

// respWithVerdict builds a valid triage response carrying an optional
// memory_verdict. alerts is empty (role assignment is irrelevant to these tests).
func respWithVerdict(t *testing.T, verdict string) json.RawMessage {
	t.Helper()
	resp := map[string]any{
		"analysis_name":        "recurrence",
		"overall_issue":        "same condition",
		"correlation_findings": []string{"c"},
		"severity":             "warning",
		"confidence":           0.5,
		"alerts":               []map[string]string{},
	}
	if verdict != absentVerdict {
		resp["memory_verdict"] = verdict
	}
	b, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	return b
}

func refuteMarks(t *testing.T, st *store.Store, id string) int {
	t.Helper()
	var m int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT memory_refute_marks FROM incidents WHERE id = ?`, id).Scan(&m); err != nil {
		t.Fatalf("read marks for %s: %v", id, err)
	}
	return m
}

// recallSkill wires a triage skill whose recall returns a fixed strong entry
// pointing at priorID, so a verdict routes marks onto that real incident row.
func recallSkill(st *store.Store, auditor *audit.Auditor, priorID string, response json.RawMessage) *acutetriage.Skill {
	reader := &stubMemoryReader{view: &store.MemoryView{
		GroupKey: "alertname=DiskFull,host=web1", Episodes: 3,
		PriorFindings: []store.PriorFinding{{IncidentID: priorID, AnalyzedAt: time.Now(), Confidence: 0.7, RootCause: "prior cause"}},
	}}
	return acutetriage.New(acutetriage.Config{
		MinAlerts: 1, Memory: reader, MemoryParams: acutetriage.MemoryParams{LookbackDays: 90},
	}, st, &fakeLLM{response: response}, auditor, nil, nil)
}

// runRecallTriage drives one triage of a fresh incident (with a member alert)
// through skill, so its verdict routes onto the recalled prior.
func runRecallTriage(t *testing.T, st *store.Store, skill *acutetriage.Skill, fp string) {
	t.Helper()
	ctx := context.Background()
	x := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, x.ID, fp, map[string]string{"alertname": "DiskFull", "host": "web1"})
	if err := skill.Run(ctx, x); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// Covers AE6 + AE9: two consecutive refutes drive the recalled prior's marks to
// the demotion threshold, and each rendered recall audits incident.memory_recalled.
func TestRun_RefutesRoutesMarksAndAudits(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	auditor := audit.New(st.DB())
	prior := insertTestIncident(t, st, ctx)

	skill := recallSkill(st, auditor, prior.ID, respWithVerdict(t, "refutes"))
	runRecallTriage(t, st, skill, "fp-a")
	runRecallTriage(t, st, skill, "fp-b")

	if got := refuteMarks(t, st, prior.ID); got != 2 {
		t.Errorf("recalled prior marks = %d, want 2 (two refutes)", got)
	}
	var recalls int
	var payload string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT COUNT(*), MAX(payload_json) FROM audit_log WHERE kind = 'incident.memory_recalled'`,
	).Scan(&recalls, &payload); err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if recalls != 2 {
		t.Errorf("memory_recalled audit rows = %d, want 2", recalls)
	}
	for _, want := range []string{`"rung":"2"`, `"verdict":"refutes"`, `"folded_count":3`} {
		if !strings.Contains(payload, want) {
			t.Errorf("audit payload missing %s: %s", want, payload)
		}
	}
}

func TestRun_ConfirmsClearsMarks(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	prior := insertTestIncident(t, st, ctx)
	if _, err := st.IncrementRefuteMarks(ctx, prior.ID); err != nil { // prime at 1
		t.Fatalf("prime marks: %v", err)
	}

	skill := recallSkill(st, nil, prior.ID, respWithVerdict(t, "confirms"))
	runRecallTriage(t, st, skill, "fp-c")

	if got := refuteMarks(t, st, prior.ID); got != 0 {
		t.Errorf("confirms should clear marks, got %d", got)
	}
}

func TestRun_MissingOrInvalidVerdictTreatedAsSilent(t *testing.T) {
	for _, tc := range []struct {
		name, verdict, note string
	}{
		{"absent", absentVerdict, "absent"},
		{"invalid", "maybe", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			st := newTestStore(t)
			auditor := audit.New(st.DB())
			prior := insertTestIncident(t, st, ctx)

			skill := recallSkill(st, auditor, prior.ID, respWithVerdict(t, tc.verdict))
			x := insertTestIncident(t, st, ctx)
			insertTestAlert(t, st, ctx, x.ID, "fp-x", map[string]string{"alertname": "DiskFull", "host": "web1"})
			if err := skill.Run(ctx, x); err != nil {
				t.Fatalf("Run must not fail on a missing/invalid verdict: %v", err)
			}

			// The triage still persisted its finding.
			var status string
			if err := st.DB().QueryRowContext(ctx, `SELECT status FROM incidents WHERE id = ?`, x.ID).Scan(&status); err != nil {
				t.Fatalf("scan status: %v", err)
			}
			if status != "analyzed" {
				t.Errorf("finding must persist despite a bad verdict, status = %q", status)
			}
			if got := refuteMarks(t, st, prior.ID); got != 0 {
				t.Errorf("a silent verdict must not touch marks, got %d", got)
			}
			var payload string
			if err := st.DB().QueryRowContext(ctx,
				`SELECT payload_json FROM audit_log WHERE kind = 'incident.memory_recalled'`).Scan(&payload); err != nil {
				t.Fatalf("query audit: %v", err)
			}
			if !strings.Contains(payload, `"verdict":"silent"`) || !strings.Contains(payload, `"verdict_note":"`+tc.note+`"`) {
				t.Errorf("audit must record silent + note %q, got %s", tc.note, payload)
			}
		})
	}
}

// Covers R17 storage half: a re-judgment that replaces the finding resets the
// incident's own contradiction marks (clean slate for the new hypothesis).
func TestRejudge_ResetsOwnMarks(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	x := insertTestIncident(t, st, ctx)
	insertTestAlert(t, st, ctx, x.ID, "fp-r", map[string]string{"alertname": "DiskFull", "host": "web1"})
	// No recall wired: isolate the reset-on-replacement effect.
	skill := acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, &fakeLLM{response: respWithVerdict(t, absentVerdict)}, nil, nil, nil)
	if err := skill.Run(ctx, x); err != nil { // x -> analyzed
		t.Fatalf("Run: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := st.IncrementRefuteMarks(ctx, x.ID); err != nil {
			t.Fatalf("mark: %v", err)
		}
	}
	if got := refuteMarks(t, st, x.ID); got != 2 {
		t.Fatalf("precondition marks = %d, want 2", got)
	}

	if err := skill.Rejudge(ctx, x, "cadence"); err != nil {
		t.Fatalf("Rejudge: %v", err)
	}
	if got := refuteMarks(t, st, x.ID); got != 0 {
		t.Errorf("replacement should reset own marks, got %d", got)
	}
}

// stubMemoryReader returns canned recall data through the exported MemoryReader
// interface so a full Run exercises the recall wiring end-to-end.
type stubMemoryReader struct {
	view      *store.MemoryView
	prefilter []store.PriorFinding
}

func (s *stubMemoryReader) MemoryView(_ context.Context, groupKey, _ string, _ bool, _ time.Time) (*store.MemoryView, error) {
	if s.view != nil {
		return s.view, nil
	}
	return &store.MemoryView{GroupKey: groupKey}, nil
}

func (s *stubMemoryReader) MemoryPrefilter(_ context.Context, _, _ string, _ bool, _ time.Time, _ int) ([]store.PriorFinding, error) {
	return s.prefilter, nil
}

// Covers AE5: an annotations-only re-fire recalling a 0.70 prior, with the model
// returning 0.85, persists at the 0.60 metadata-only cap — a recalled prior's
// confidence is never smuggled into an evidence-free re-fire. The memory section
// is persisted into the enrichment envelope (persist-as-rendered).
func TestRun_MemoryPresentStillClampsAndPersistsEnvelope(t *testing.T) {
	ctx := context.Background()
	st := newTestStore(t)
	inc := insertTestIncident(t, st, ctx)
	a1 := insertTestAlert(t, st, ctx, inc.ID, "fp-1", map[string]string{"alertname": "DiskFull", "host": "web1"})

	base := time.Date(2026, 7, 9, 2, 5, 0, 0, time.UTC)
	reader := &stubMemoryReader{view: &store.MemoryView{
		GroupKey: inc.GroupKey, Episodes: 14, CadenceMedian: 24 * time.Hour,
		FirstSeen: base.AddDate(0, 0, -14), LastSeen: base.AddDate(0, 0, -1),
		PriorFindings: []store.PriorFinding{
			{IncidentID: "inc_prior", AnalyzedAt: base.AddDate(0, 0, -1), Confidence: 0.70, RootCause: "backup rotation misconfigured"},
		},
	}}
	// validLLMResponse's fixture returns confidence 0.85; no live evidence is
	// configured (no Prometheus/logs/sentry), so the metadata-only cap applies.
	fllm := &fakeLLM{response: validLLMResponse([]string{a1.ID})}
	skill := acutetriage.New(acutetriage.Config{
		MinAlerts: 1, Memory: reader, MemoryParams: acutetriage.MemoryParams{LookbackDays: 90},
	}, st, fllm, nil, nil, nil)

	if err := skill.Run(ctx, inc); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if !strings.Contains(fllm.lastUser, "[folded ×14]") || !strings.Contains(fllm.lastUser, "backup rotation misconfigured") {
		t.Errorf("prompt missing the recalled memory section:\n%s", fllm.lastUser)
	}
	var confidence float64
	var enrichmentJSON string
	if err := st.DB().QueryRowContext(ctx,
		`SELECT confidence, COALESCE(enrichment_json,'') FROM incidents WHERE id = ?`, inc.ID,
	).Scan(&confidence, &enrichmentJSON); err != nil {
		t.Fatalf("scan incident: %v", err)
	}
	if confidence != acutetriage.MaxMetadataOnlyConfidence {
		t.Errorf("confidence = %v, want %v (memory must not lift the metadata-only cap)", confidence, acutetriage.MaxMetadataOnlyConfidence)
	}
	if !strings.Contains(enrichmentJSON, `"memory"`) || !strings.Contains(enrichmentJSON, "inc_prior") {
		t.Errorf("memory section must persist into the envelope, got: %s", enrichmentJSON)
	}
}
