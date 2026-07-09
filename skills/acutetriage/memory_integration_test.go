// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

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
