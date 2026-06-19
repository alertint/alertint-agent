// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"testing"
	"time"
)

func TestParseChange_HappyPath(t *testing.T) {
	now := time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)
	body := []byte(`{
		"source":"github-actions","kind":"deploy",
		"title":"checkout v1.42.0 deployed to prod",
		"labels":{"service":"checkout","namespace":"prod"},
		"version":"v1.42.0","link":"https://x/run/1",
		"occurred_at":"2026-06-18T10:42:00Z"
	}`)
	out, err := ParseChange(body, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 change, got %d", len(out))
	}
	c := out[0]
	if c.Kind != "deploy" || c.Source != "github-actions" || c.Title == "" {
		t.Fatalf("fields: %#v", c)
	}
	if !c.OccurredAt.Equal(time.Date(2026, 6, 18, 10, 42, 0, 0, time.UTC)) {
		t.Fatalf("occurred_at: %v", c.OccurredAt)
	}
	if !c.ReceivedAt.Equal(now) {
		t.Fatalf("received_at: %v", c.ReceivedAt)
	}
	if c.ID != "" {
		t.Fatal("ID must be stamped by the receiver, not ParseChange")
	}
}

func TestParseChange_FutureOccurredClampsToReceived(t *testing.T) {
	now := time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)
	body := []byte(`{"kind":"deploy","labels":{"service":"x"},"occurred_at":"2026-06-18T16:00:00Z"}`)
	out, err := ParseChange(body, now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !out[0].OccurredAt.Equal(now) {
		t.Fatalf("future occurred_at must clamp to received_at, got %v", out[0].OccurredAt)
	}
}

func TestParseChange_MissingOccurredFallsBack(t *testing.T) {
	now := time.Date(2026, 6, 18, 11, 0, 0, 0, time.UTC)
	out, err := ParseChange([]byte(`{"kind":"config","labels":{"a":"b"}}`), now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !out[0].OccurredAt.Equal(now) {
		t.Fatalf("missing occurred_at must fall back to received_at, got %v", out[0].OccurredAt)
	}
}

func TestParseChange_DefaultsSourceAndSynthesizesTitle(t *testing.T) {
	now := time.Now().UTC()
	out, err := ParseChange([]byte(`{"kind":"deploy","labels":{"service":"checkout"},"version":"v9"}`), now)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out[0].Source != "unknown" {
		t.Fatalf("source default: %q", out[0].Source)
	}
	if out[0].Title != "deploy checkout v9" {
		t.Fatalf("synth title: %q", out[0].Title)
	}
}

func TestParseChange_Rejects(t *testing.T) {
	now := time.Now().UTC()
	cases := map[string]string{
		"missing kind":   `{"labels":{"a":"b"}}`,
		"empty labels":   `{"kind":"deploy","labels":{}}`,
		"missing labels": `{"kind":"deploy"}`,
		"bad json":       `{`,
	}
	for name, body := range cases {
		if _, err := ParseChange([]byte(body), now); err == nil {
			t.Fatalf("%s: want error", name)
		}
	}
}
