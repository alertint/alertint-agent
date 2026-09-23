// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-3 repair regressions (lead review round 2, 2026-09-09, R1).
//
// Narrowing stopped at the empty selection: when delivered history rejected
// EVERY candidate, the deliverer posted the original Transition instead —
// candidates, legacy fallbacks and all. A reply earned by a changed symptom
// therefore carried facts the operator was never owed. The disposition for
// an empty selection is to deliver the reply narrowed, never to reinstate
// what was rejected.
// ----------------------------------------------------------------------

// ds3SymptomReply is a reply earned by the supported symptoms fallback
// alone: its only candidates are an uncommunicated clearance and a
// withdrawal of a request that was never made.
func ds3SymptomReply(t *testing.T, now time.Time) model.Transition {
	t.Helper()
	tr := dsSelectionTransition(t, now)
	tr.Projection.OperatorDelta.Candidates = tr.Projection.OperatorDelta.Candidates[1:]
	tr.Projection.OperatorDelta.SymptomsChanged = true
	tr.Projection.OperatorDelta.PreviousSymptoms = []string{"Checkout latency"}
	tr.Projection.Briefing.Symptoms = []string{"Checkout 500s"}
	return tr
}

// ds3Rejected reports the rejected facts found in one rendered surface.
func ds3Rejected(text string) []string {
	var found []string
	lower := strings.ToLower(text)
	for _, fact := range []string{"unavailable", "no longer recorded", "no longer needed",
		"automatic work cannot proceed", "human action request changed"} {
		if strings.Contains(lower, fact) {
			found = append(found, fact)
		}
	}
	return found
}

// R1/1: the earned symptom change is delivered; the rejected candidates are
// not, on either surface.
func TestSituationDelivererSymptomReplyDropsEveryRejectedCandidate(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	tr := ds3SymptomReply(t, now)
	if got := situation.ReplyEligible(tr.Projection.OperatorDelta.Candidates, situation.DeliveredHistory{}, true); len(got) != 0 {
		t.Fatalf("fixture: every candidate must be rejected, got %+v", got)
	}
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1"}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(api.posts) != 1 {
		t.Fatalf("want exactly one outbound PostMessage, got %d", len(api.posts))
	}
	for surface, text := range map[string]string{"fallback": api.posts[0].Text, "blocks": sdBlocksText(t, api.posts[0].Blocks)} {
		t.Logf("%s:\n%s", surface, text)
		if !strings.Contains(text, "Checkout 500s") {
			t.Errorf("%s dropped the earned symptom change", surface)
		}
		if got := ds3Rejected(text); len(got) > 0 {
			t.Errorf("%s resurrected rejected facts through the empty selection: %v", surface, got)
		}
	}
}

// R1/2: the same on the broadcast class, and with both legacy booleans set
// — an empty selection must take every rejected kind's legacy twin with it.
func TestSituationDelivererEmptySelectionClearsTheLegacyFallbacks(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	tr := ds3SymptomReply(t, now)
	tr.Projection.OperatorDelta.AbilityLost = true
	tr.Projection.OperatorDelta.HumanRequestChanged = true
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1"}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectBroadcastHandoff, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(api.posts) != 1 {
		t.Fatalf("want exactly one outbound PostMessage, got %d", len(api.posts))
	}
	for surface, text := range map[string]string{"fallback": api.posts[0].Text, "blocks": sdBlocksText(t, api.posts[0].Blocks)} {
		t.Logf("%s:\n%s", surface, text)
		if !strings.Contains(text, "Checkout 500s") {
			t.Errorf("%s dropped the earned symptom change", surface)
		}
		if got := ds3Rejected(text); len(got) > 0 {
			t.Errorf("%s resurrected rejected facts through a legacy boolean: %v", surface, got)
		}
	}
}

// R1/3, the explicit disposition for a fully narrowed reply that has no
// earned legacy content either: it is still delivered, and it still states
// this Transition's own current status and next step. What it never does is
// publish a fact delivered history rejected.
func TestSituationDelivererFullyNarrowedReplyStatesItsOwnStatus(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	tr := dsSelectionTransition(t, now)
	tr.Projection.OperatorDelta.Candidates = tr.Projection.OperatorDelta.Candidates[1:]
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1"}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(api.posts) != 1 {
		t.Fatalf("want exactly one outbound PostMessage, got %d", len(api.posts))
	}
	text := api.posts[0].Text + "\n" + sdBlocksText(t, api.posts[0].Blocks)
	t.Logf("rendered:\n%s", text)
	if got := ds3Rejected(text); len(got) > 0 {
		t.Fatalf("a fully narrowed reply published rejected facts: %v", got)
	}
	if !strings.Contains(text, "*AlertINT:*") || !strings.Contains(text, "Next status check:") {
		t.Fatalf("a narrowed reply must still carry its own status and next step:\n%s", text)
	}
}

// R1/4, positive control kept from the round-2 repair: a selection that is
// merely NARROWED, not emptied, still delivers what survived.
func TestSituationDelivererNarrowedSelectionKeepsTheEligibleFinding(t *testing.T) {
	now := sdMustTime(t, "2026-09-09T10:00:00Z")
	tr := dsSelectionTransition(t, now)
	fs := &fakeDelivererStore{transitions: map[string]model.Transition{tr.ID: tr},
		rootOK: true, rootChannel: "C", rootTS: "100.1"}
	api := &fakeSlackAPI{}
	d := NewSituationDeliverer(fs, api, "C", func() time.Time { return now })
	if _, err := d.Deliver(context.Background(), sdThreadIntent(model.EffectThreadAppend, tr.ID, tr.Sequence, now)); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	dsAssertSelected(t, api)
}
