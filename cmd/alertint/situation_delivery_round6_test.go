// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// B5 round-6 delivery regressions (lead decisions, 2026-09-10, §46/2 and
// §46/3), on the outbound payload itself.
//
// Round 5 asked delivery history only when the reply carried candidates to
// narrow. The lead's candidate-free overlay showed the consequence: a reply
// with nothing to select skips the read entirely and republishes an
// investigation the work has moved past, with its old checkpoint. The
// canonical thread gate asks the same question of EVERY reply — "Compare
// accepted information with what was already communicated" — so the read is
// what a reply is, not what a selection needs.
//
// The read can also fail. A reply then has no answer to the staleness
// question, and posting the old contract anyway would publish exactly the
// claim this correction exists to prevent: the attempt stops, retryably and
// locally, with nothing sent.
// ----------------------------------------------------------------------

// ds6NoDelta is the mixed start row with no operator delta at all — the
// shape a late operator note or captured verdict reply arrives in.
func ds6NoDelta(now time.Time) model.Transition {
	tr := ds4MixedStart(now)
	tr.Projection.OperatorDelta = nil
	return tr
}

// ds6EmptyCandidates is the same row with a delta that carries nothing:
// the second way a reply reaches delivery with no selection to make.
func ds6EmptyCandidates(now time.Time) model.Transition {
	tr := ds4MixedStart(now)
	tr.Projection.OperatorDelta = &model.OperatorDelta{}
	return tr
}

// ds6Harness is one deliverer over a fake Store and Slack, kept addressable
// so a test can drive a failure and then its retry against the same pair.
type ds6Harness struct {
	store *fakeDelivererStore
	api   *fakeSlackAPI
	d     *SituationDeliverer
}

func ds6New(tr model.Transition, history situation.DeliveredHistory, now time.Time) *ds6Harness {
	fs := &fakeDelivererStore{
		transitions: map[string]model.Transition{tr.ID: tr},
		rootOK:      true, rootChannel: "C", rootTS: "100.1",
		history: history,
		episode: store.SituationEpisodeView{
			Summary:          sdSummary(tr.Sequence, tr.ActionContract, now, now),
			SourceTransition: tr,
		},
	}
	api := &fakeSlackAPI{}
	return &ds6Harness{store: fs, api: api,
		d: NewSituationDeliverer(fs, api, "C", func() time.Time { return now })}
}

func (h *ds6Harness) deliver(class model.EffectClass, tr model.Transition, now time.Time) error {
	_, err := h.d.Deliver(context.Background(), sdThreadIntent(class, tr.ID, tr.Sequence, now))
	return err
}

// surfaces returns both operator-visible surfaces of the single post this
// harness is expected to have made.
func (h *ds6Harness) surfaces(t *testing.T) map[string]string {
	t.Helper()
	if len(h.api.posts) != 1 {
		t.Fatalf("want exactly one outbound PostMessage, got %d", len(h.api.posts))
	}
	return map[string]string{
		"fallback": h.api.posts[0].Text,
		"blocks":   sdBlocksText(t, h.api.posts[0].Blocks),
	}
}

// ds6LocalRetryable asserts err is this adapter's own local, retryable
// failure with the given code: no Slack attribution, no closed obligation.
func ds6LocalRetryable(t *testing.T, err error, code string) {
	t.Helper()
	var failure situation.DeliveryFailure
	if !errors.As(err, &failure) {
		t.Fatalf("delivery error %v carries no classification; an unclassified error cannot be attributed", err)
	}
	if got := failure.DeliveryErrorClass(); got != situation.DeliveryLocalRetryable {
		t.Errorf("delivery error class = %v, want %v", got, situation.DeliveryLocalRetryable)
	}
	if got := failure.DeliveryErrorCode(); got != code {
		t.Errorf("delivery error code = %q, want %q", got, code)
	}
}

// §46/2, R1: a reply with no candidate to select is still a reply, and it
// still asks what the operator has already been told. Both shapes, both
// classes, both surfaces.
func TestB5CandidateFreeReplyDropsTheSupersededExecution(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	for name, build := range map[string]func(time.Time) model.Transition{
		"nil delta": ds6NoDelta, "empty candidates": ds6EmptyCandidates,
	} {
		for _, class := range []model.EffectClass{model.EffectThreadAppend, model.EffectBroadcastHandoff} {
			t.Run(name+"/"+string(class), func(t *testing.T) {
				tr := build(now)
				h := ds6New(tr, situation.DeliveredHistory{AssuranceSuperseded: true}, now)
				if err := h.deliver(class, tr, now); err != nil {
					t.Fatalf("Deliver: %v", err)
				}
				for surface, text := range h.surfaces(t) {
					t.Logf("%s:\n%s", surface, text)
					if ds5StaleActivityStated(text) {
						t.Errorf("%s presents the superseded execution as current activity", surface)
					}
					if strings.Contains(text, "Next status check") {
						t.Errorf("%s republishes the superseded checkpoint", surface)
					}
					if !strings.Contains(text, "checkout + payments") {
						t.Errorf("%s lost the row's recorded scope", surface)
					}
				}
			})
		}
	}
}

// §46/2, R2, positive control: the unconditional read changes nothing when
// nothing was superseded, and it keeps the two answers separate. An
// assurance the operator has already SEEN is a duplicate question; it is
// not evidence that this reply's own investigation has been overtaken.
func TestB5CandidateFreeReplyKeepsItsStatusWhenNothingWasSuperseded(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	for name, history := range map[string]situation.DeliveredHistory{
		"nothing communicated": {},
		"assurance conveyed":   {AssuranceConveyed: true},
	} {
		t.Run(name, func(t *testing.T) {
			tr := ds6NoDelta(now)
			h := ds6New(tr, history, now)
			if err := h.deliver(model.EffectThreadAppend, tr, now); err != nil {
				t.Fatalf("Deliver: %v", err)
			}
			for surface, text := range h.surfaces(t) {
				if !ds5StaleActivityStated(text) {
					t.Errorf("%s suppressed an investigation nothing had overtaken: %s", surface, text)
				}
				if !strings.Contains(text, "Next status check") {
					t.Errorf("%s dropped a checkpoint that is this reply's own: %s", surface, text)
				}
			}
		})
	}
}

// §46/2, R3: an unavailable history leaves the staleness question
// unanswered. Nothing may be posted on the strength of the old contract —
// not the payload, not a partial one — and the attempt stays local and
// retryable so the obligation survives.
func TestB5ReplyIsNotPostedWhenTheDeliveryHistoryIsUnavailable(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	for _, class := range []model.EffectClass{model.EffectThreadAppend, model.EffectBroadcastHandoff} {
		t.Run(string(class), func(t *testing.T) {
			tr := ds6NoDelta(now)
			h := ds6New(tr, situation.DeliveredHistory{}, now)
			h.store.historyErr = errors.New("store: database is locked")
			err := h.deliver(class, tr, now)
			if err == nil {
				t.Fatal("a reply was acknowledged although its delivery history could not be read")
			}
			ds6LocalRetryable(t, err, "communicated_history_unavailable")
			if len(h.api.posts) != 0 {
				t.Fatalf("posted %d messages built on an unverified contract, want 0: %+v",
					len(h.api.posts), h.api.posts)
			}
		})
	}
}

// §46/2, R4: the retry after that failure delivers the same reply with its
// material content intact and the staleness question answered — including
// the candidate-free reply, which never reached the read at all before.
func TestB5ReplyRetryAfterAHistoryFailureLosesNoMaterialContent(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	for name, shape := range map[string]struct {
		build    func(time.Time) model.Transition
		material string
	}{
		"mixed":          {ds4MixedStart, "Affected scope changed from"},
		"candidate-free": {ds6NoDelta, "checkout + payments"},
	} {
		t.Run(name, func(t *testing.T) {
			tr := shape.build(now)
			h := ds6New(tr, situation.DeliveredHistory{AssuranceSuperseded: true}, now)
			h.store.historyErr = errors.New("store: database is locked")
			if err := h.deliver(model.EffectThreadAppend, tr, now); err == nil {
				t.Fatal("the first attempt was acknowledged although the history read failed")
			}

			h.store.historyErr = nil
			if err := h.deliver(model.EffectThreadAppend, tr, now); err != nil {
				t.Fatalf("retry: %v", err)
			}
			for surface, text := range h.surfaces(t) {
				if !strings.Contains(text, shape.material) {
					t.Errorf("%s lost the reply's material content across the retry: %s", surface, text)
				}
				if ds5StaleActivityStated(text) {
					t.Errorf("%s presents the superseded execution as current activity: %s", surface, text)
				}
			}
		})
	}
}

// §46/3: the reply states the supersession it has recorded and stops. The
// main message is refreshed by its own delivery, which may be queued,
// blocked or failed at this instant (canonical thread gate: "Root can
// refresh without a thread post"), so a reply that asserted the root
// already carries current status would publish an unverified claim.
func TestB5ReplyClaimsNothingAboutTheMainMessage(t *testing.T) {
	now := sdMustTime(t, "2026-09-10T10:00:00Z")
	tr := ds4MixedStart(now)
	h := ds6New(tr, situation.DeliveredHistory{AssuranceSuperseded: true}, now)

	// The root's own refresh is blocked: its edit never reaches Slack.
	h.api.updateErr = errors.New("slack: channel unavailable")
	deadline := now.Add(time.Minute)
	if _, err := h.d.Deliver(context.Background(),
		sdRootSyncIntent(tr.ID, tr.Sequence, &deadline, now)); err == nil {
		t.Fatal("fixture: the root refresh was expected to fail")
	}

	if err := h.deliver(model.EffectThreadAppend, tr, now); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if len(h.api.posts) != 1 {
		t.Fatalf("want exactly one outbound PostMessage, got %d", len(h.api.posts))
	}
	surfaces := map[string]string{
		"fallback": h.api.posts[0].Text,
		"blocks":   sdBlocksText(t, h.api.posts[0].Blocks),
	}
	for surface, text := range surfaces {
		t.Logf("%s:\n%s", surface, text)
		if !strings.Contains(text, "superseded") {
			t.Errorf("%s dropped the activity line without recording why: %s", surface, text)
		}
		for _, claim := range []string{"main message", "Main message", "carries the current status",
			"carries the current", "is up to date", "has been updated"} {
			if strings.Contains(text, claim) {
				t.Errorf("%s asserts %q although the root's own refresh has not landed: %s", surface, claim, text)
			}
		}
	}
}
