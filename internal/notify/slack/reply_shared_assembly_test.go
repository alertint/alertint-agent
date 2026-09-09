// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"reflect"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ----------------------------------------------------------------------
// B5 round-6 renderer regressions (lead decisions, 2026-09-10, §46/1 and
// §46/3).
//
// Round 5 kept the reply renderer outside situation.go and restated that
// file's journal tail to reach it. One assembly now serves both entry
// points: validation, fallback text, block shape, staleness markers and
// the recorded instant have a single implementation, and the reply entry
// point adds one delivery-time presentation fact and nothing else.
//
// The replacement sentence also stops where its evidence stops. The root
// is refreshed by its own delivery, which the canonical thread gate keeps
// a separate decision ("Root can refresh without a thread post"), so a
// reply cannot assert that the main message already carries current
// status.
// ----------------------------------------------------------------------

// rsaShapes is every journal shape both entry points must render
// identically when no delivery-time answer is supplied.
func rsaShapes(t *testing.T) map[string]model.Transition {
	t.Helper()
	mixed, _ := bsaMixedStart(t)

	markers, _ := bsaMixedStart(t)
	markers.Journal.Delayed = true
	markers.Journal.NoLongerCurrent = true

	drill, _ := bsaMixedStart(t)
	drill.Drill = true

	plain, _ := bsaMixedStart(t)
	plain.Projection.Briefing = nil
	plain.Projection.OperatorDelta = nil

	empty, _ := bsaMixedStart(t)
	empty.JournalKind = model.JournalNone

	invalid, _ := bsaMixedStart(t)
	invalid.SituationID = ""

	return map[string]model.Transition{"mixed": mixed, "markers": markers, "drill": drill,
		"plain": plain, "no journal": empty, "invalid": invalid}
}

// §46/1, R1: one assembly. Without the presentation fact the two entry
// points agree on the rendered payload AND on the error, including the
// shapes that never reach the briefing path at all.
func TestReplyAndJournalShareOneAssembly(t *testing.T) {
	for name, tr := range rsaShapes(t) {
		t.Run(name, func(t *testing.T) {
			want, wantErr := RenderSituationJournal(tr)
			got, gotErr := RenderSituationReply(SituationReplyInput{Transition: tr})
			switch {
			case wantErr == nil && gotErr == nil:
			case wantErr == nil || gotErr == nil:
				t.Fatalf("error disagreement: journal %v, reply %v", wantErr, gotErr)
			case wantErr.Error() != gotErr.Error():
				t.Fatalf("error text drifted:\njournal %q\nreply   %q", wantErr, gotErr)
			}
			if !reflect.DeepEqual(want, got) {
				t.Fatalf("rendered payload drifted:\njournal %#v\nreply   %#v", want, got)
			}
		})
	}
}

// §46/1, R3: one implementation of validation. A reply that DOES carry the
// presentation fact must still fail exactly as the journal renderer fails —
// a second entry point may not grow a second validation or a second error
// vocabulary for the same rejected Transition.
func TestSupersededReplyFailsExactlyAsTheJournalRendererDoes(t *testing.T) {
	for name, tr := range map[string]model.Transition{
		"no journal": rsaShapes(t)["no journal"], "invalid": rsaShapes(t)["invalid"],
	} {
		t.Run(name, func(t *testing.T) {
			_, wantErr := RenderSituationJournal(tr)
			_, gotErr := RenderSituationReply(SituationReplyInput{Transition: tr, ExecutionSuperseded: true})
			if wantErr == nil || gotErr == nil {
				t.Fatalf("fixture: both renderers must reject this shape: journal %v, reply %v", wantErr, gotErr)
			}
			if wantErr.Error() != gotErr.Error() {
				t.Fatalf("the reply entry point grew its own validation error:\njournal %q\nreply   %q", wantErr, gotErr)
			}
		})
	}
}

// §46/1, R2: the presentation fact reaches the same assembly. A reply that
// carries it keeps every marker and the recorded instant the journal
// renderer produces, in the same block positions.
func TestSupersededReplyKeepsTheSharedMarkersAndInstant(t *testing.T) {
	tr, _ := bsaMixedStart(t)
	tr.Journal.Delayed = true
	tr.Journal.NoLongerCurrent = true

	base, err := RenderSituationJournal(tr)
	if err != nil {
		t.Fatalf("RenderSituationJournal: %v", err)
	}
	corrected, err := RenderSituationReply(SituationReplyInput{Transition: tr, ExecutionSuperseded: true})
	if err != nil {
		t.Fatalf("RenderSituationReply: %v", err)
	}
	wantTail, gotTail := bsaBlockTexts(base), bsaBlockTexts(corrected)
	if len(wantTail) != len(gotTail) {
		t.Fatalf("block count changed: journal %d, reply %d", len(wantTail), len(gotTail))
	}
	for _, tail := range []int{1, 2} {
		i := len(wantTail) - tail
		if wantTail[i] != gotTail[i] {
			t.Errorf("tail block %d drifted:\njournal %q\nreply   %q", i, wantTail[i], gotTail[i])
		}
	}
	if !strings.Contains(gotTail[len(gotTail)-2], "no longer current · delayed") {
		t.Errorf("the corrected reply lost its staleness markers: %q", gotTail[len(gotTail)-2])
	}
}

// §46/3, R1: the replacement sentence states the recorded supersession and
// stops. It makes no claim about the root, whose own refresh may be queued,
// blocked or failed at this instant.
func TestSupersededReplyClaimsNothingAboutTheRoot(t *testing.T) {
	tr, _ := bsaMixedStart(t)
	for surface, text := range bsaSurfaces(t, SituationReplyInput{Transition: tr, ExecutionSuperseded: true}) {
		if !strings.Contains(text, "superseded") {
			t.Fatalf("%s dropped the activity line without recording why: %s", surface, text)
		}
		for _, claim := range []string{"main message", "Main message", "carries the current",
			"is up to date", "has been updated", "see the root", "above"} {
			if strings.Contains(text, claim) {
				t.Errorf("%s asserts %q about a refresh this reply has not verified: %s", surface, claim, text)
			}
		}
	}
}
