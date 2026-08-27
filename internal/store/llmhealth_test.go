// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"
)

func TestLLMHealthFreshDatabaseIsHealthy(t *testing.T) {
	s := newTestStore(t)
	rec, caps, err := s.GetLLMHealth(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rec.State != "healthy" || rec.OutageGeneration != 0 || rec.SlackDelivery != "none" || len(caps) != 0 {
		t.Fatalf("fresh = %+v caps=%d", rec, len(caps))
	}
}

func TestLLMHealthRoundTrip(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	since := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	rec := LLMHealthRecord{
		State: "unavailable", ReasonCode: "provider_unavailable", Detail: "HTTP 503",
		UnhealthySince: &since, OutageGeneration: 3, LastProbeOutcome: "failed",
		SlackTS: "1.2", SlackChannel: "C1", SlackDelivery: "delivered", SlackState: "unavailable", SlackGeneration: 3,
	}
	caps := []LLMCapabilityRecord{
		{Capability: "triage_draft", Healthy: false, ReasonCode: "provider_unavailable", Detail: "HTTP 503", UnhealthySince: &since, LastFailureAt: &since, ContentSubjects: []string{"inc-1", "inc-2"}},
		{Capability: "memory_classifier", Healthy: true, LastSuccessAt: &since},
	}
	if err := s.SaveLLMHealth(ctx, rec, caps); err != nil {
		t.Fatal(err)
	}
	got, gotCaps, err := s.GetLLMHealth(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "unavailable" || got.OutageGeneration != 3 || got.SlackTS != "1.2" || got.SlackDelivery != "delivered" || !got.UnhealthySince.Equal(since) {
		t.Fatalf("got %+v", got)
	}
	if len(gotCaps) != 2 || gotCaps[0].Capability != "memory_classifier" || gotCaps[1].Capability != "triage_draft" || gotCaps[1].Healthy {
		t.Fatalf("caps = %+v", gotCaps) // ordered by capability name
	}
	if want := []string{"inc-1", "inc-2"}; len(gotCaps[1].ContentSubjects) != 2 || gotCaps[1].ContentSubjects[0] != want[0] || gotCaps[1].ContentSubjects[1] != want[1] {
		t.Fatalf("content_subjects round-trip = %+v, want %v", gotCaps[1].ContentSubjects, want)
	}
	if gotCaps[0].ContentSubjects != nil {
		t.Fatalf("content_subjects default = %+v, want nil/empty", gotCaps[0].ContentSubjects)
	}
	// Second save overwrites (upsert), never duplicates.
	caps[0].Healthy = true
	if err := s.SaveLLMHealth(ctx, rec, caps); err != nil {
		t.Fatal(err)
	}
	_, gotCaps, _ = s.GetLLMHealth(ctx)
	if len(gotCaps) != 2 || !gotCaps[1].Healthy {
		t.Fatalf("after upsert caps = %+v", gotCaps)
	}
}

// TestLLMHealthMalformedContentSubjectsFailsLoud pins that corrupt
// corroboration evidence can never silently degrade the two-Incident rule:
// the column CHECK rejects a non-array value at write time, and — should one
// ever land anyway — the parser returns an error (so llmhealth.New fails
// loud, like every other unloadable field) instead of reading it as "no
// content failures recorded".
func TestLLMHealthMalformedContentSubjectsFailsLoud(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.SaveLLMHealth(ctx, LLMHealthRecord{State: "healthy", SlackDelivery: "none"},
		[]LLMCapabilityRecord{{Capability: "triage_draft", Healthy: true}}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, bad := range []string{`not json`, `"a string"`, `{"a":1}`} {
		if _, err := s.db.ExecContext(ctx, `UPDATE llm_health_capabilities SET content_subjects = ? WHERE capability = 'triage_draft'`, bad); err == nil {
			t.Fatalf("content_subjects CHECK must reject %q", bad)
		}
	}
	for _, bad := range []string{`not json`, `"a string"`, `[1, 2]`} {
		if _, err := unmarshalContentSubjects(bad); err == nil {
			t.Fatalf("unmarshalContentSubjects(%q) must return an error, not an empty set", bad)
		}
	}
}

func TestLLMHealthRejectsUnknownEnums(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	if err := s.SaveLLMHealth(ctx, LLMHealthRecord{State: "broken", SlackDelivery: "none"}, nil); err == nil {
		t.Fatal("state CHECK must reject 'broken'")
	}
	if err := s.SaveLLMHealth(ctx, LLMHealthRecord{State: "healthy", SlackDelivery: "none"},
		[]LLMCapabilityRecord{{Capability: "situation", Healthy: true}}); err == nil {
		t.Fatal("capability CHECK must reject unknown capability")
	}
}
