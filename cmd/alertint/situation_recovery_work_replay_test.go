// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"strings"
	"testing"
	"time"
)

// ----------------------------------------------------------------------
// §63 (lead review of the retry disclosure, 2026-09-10): the production
// reachability assertion for recovery confirmation while investigation work
// is still outstanding.
//
// Three rounds of renderer tests asserted this state through HANDCRAFTED
// verify_recovery contracts, which proved renderer capability and hid the
// fact that no such contract is derivable while work remains:
// deriveAlertINTBranch ranks every triage phase above the recovery-pending
// lifecycle, and ControllerState.TriagePhase aggregates the same schedules
// the work projection reduces. This file closes that hole at the only
// boundary that cannot be faked — the real controller deriving its own
// contract from durable state, and the real renderer and delivery path
// putting the result on the wire.
//
// The boundary is s5rFixture's (situation_slide5_replay_test.go): a real
// store on disk, the real controller, the real notification worker,
// deliverer and renderer, with the Slack Web API and the L2 client faked.
// Nothing about the lifecycle, the work projection, the Operator contract
// or the payload is injected.
//
// Canonical target: the "recovery-with-work" example — "Watching for
// sustained recovery through [recorded grace deadline]. One investigation
// is still running; next status check: [recorded checkpoint]" — under its
// own rule that "Recovery grace and investigation coexist. Lifecycle sets
// orientation; activity describes remaining work."
// ----------------------------------------------------------------------

// triageSchedule reads the Incident's durable Acute Triage row, so "work is
// still outstanding" and "this is its recorded readiness time" are facts of
// the record, never inferences from the rendered copy.
func (r *s5rFixture) triageSchedule() (phase string, nextAt time.Time) {
	r.t.Helper()
	var raw *string
	if err := r.st.DB().QueryRowContext(r.ctx,
		`SELECT phase, next_at FROM incident_triage WHERE incident_id = ?`, r.incidentID).Scan(&phase, &raw); err != nil {
		r.t.Fatalf("read triage schedule: %v", err)
	}
	if raw == nil {
		return phase, time.Time{}
	}
	at, err := time.Parse(time.RFC3339Nano, *raw)
	if err != nil {
		r.t.Fatalf("parse triage next_at %q: %v", *raw, err)
	}
	return phase, at
}

func TestS5ReplayRecoveryConfirmationStatesGraceWhileWorkIsOutstanding(t *testing.T) {
	r := newS5RFixture(t, "group=s5r-recovery-work")

	// The first root arrives. The controller's own cycle commits the Acute
	// Triage request, so the schedule is queued and nothing has claimed it:
	// no attempt exists, and no execution can be confused for one.
	ev1 := r.runEvent("event 1 · first root arrives", 1)
	if len(ev1.rootPosts) != 1 {
		t.Fatalf("event 1 posted %d root message(s), want exactly the initial overview", len(ev1.rootPosts))
	}
	r.rootTS = ev1.rootPosts[0].TS
	if phase, _ := r.triageSchedule(); phase != "pending" {
		t.Fatalf("triage phase = %q, want the queued schedule this replay needs", phase)
	}

	// Every monitored alert clears while that schedule is still outstanding.
	// This is the canonical "recovery-with-work" state, and the controller
	// derives its own contract for it with no help from the test.
	r.clock.advance(90 * time.Second)
	for _, a := range s5rAlerts() {
		r.accept(a, "resolved", r.clock.Now())
	}
	r.enqueueInput("membership_changed", "all-clear")
	out := r.runEvent("event 2 · all clear while investigation work is outstanding", 1)

	phase, readiness := r.triageSchedule()
	if phase != "pending" {
		t.Fatalf("triage phase = %q after the all-clear; recovery must not settle outstanding work", phase)
	}
	grace := r.mustSituationTime("grace_until")
	checkpoint := r.mustSituationTime("next_assessment_at")
	for _, pair := range [][2]time.Time{{grace, checkpoint}, {grace, readiness}, {checkpoint, readiness}} {
		if pair[0].Equal(pair[1]) {
			t.Fatalf("two of the three recorded times are both %s; this event cannot tell the clauses apart", pair[0])
		}
	}
	r.assertEvent("event 2", out, s5rExpect{
		lifecycle: "recovery_pending", orientation: "Confirming recovery", transitions: 2, replies: 1,
		rootMust: []string{
			"Watching for sustained recovery until " + slackDateToken(grace),
			"Investigation is queued",
			slackDateToken(readiness),
			"Next status check: " + slackDateToken(checkpoint),
		},
		// Recovery confirmation claims nothing about the work: the queued
		// schedule has never executed, and the episode has not recovered.
		rootMustNot: []string{"Investigating.", "Recovery confirmed", "is still running"},
		replyMust:   []string{slackDateToken(grace)},
	})

	// The grace deadline is stated once. Recovery and work are two clauses
	// of one activity line, never the same recorded fact reported twice.
	root, _ := out.currentRoot()
	for surface, text := range map[string]string{
		"fallback text": root.Text,
		"block kit":     r.blockText("event 2 root", root.Blocks),
	} {
		if got := strings.Count(text, "Watching for sustained recovery"); got != 1 {
			t.Errorf("%s watches for recovery %d time(s), want exactly 1:\n%s", surface, got, text)
		}
	}
}
