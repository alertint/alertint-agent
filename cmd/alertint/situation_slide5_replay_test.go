// SPDX-License-Identifier: FSL-1.1-ALv2

package main

// B6 repair, finding 1 (lead review 2026-09-10,
// evaluation/lead-b6-round1-2026-09-10/review.md): the canonical slide-5
// R3 seven-event drill, driven end to end through the REAL path — a real
// *store.Store on disk, the real situation.ControllerWorker deriving
// lifecycle and work for itself, the real Acute Triage claim/completion
// writers, the real notification worker, the real SituationDeliverer and
// renderer, and the real internal/notify/slack client. Both providers are
// faked, each with a call counter: the scripted Slack Web API
// (fakeSlackServer, which records every request's text AND blocks) and the
// L2 assessment client (e2eAssessmentClient.callCount).
//
// THE BOUNDARY, stated exactly (lead review round 2, 2026-09-10, finding
// 2). This is a controlled integration test, not a whole-daemon run. The
// test plays the parts that sit OUTSIDE the Situation controller: it
// inserts the Incident and its alert-delivery membership links, enqueues
// the situation_input_outbox rows a receiver would enqueue, and calls
// store.ClaimIncidentTriageAttempt / CompleteIncidentTriageAttempt
// directly. Those two are the real production writers, and their durable
// effects — the frozen investigation input set, the attempt result, the
// inputs they raise — are exactly what the controller then reads. But no
// Acute Triage worker and no investigation provider runs here. So this
// file is evidence about what the controller and the delivery path do with
// a real execution record, NOT that an executor produces one. "Nothing is
// injected" would be the wrong claim; the accurate one is that no
// lifecycle, work projection, Operator contract, candidate, intent or
// payload is injected — every one of those is derived by the product.
//
// The first B6 candidate proved the same narrative at the store's own
// bookkeeping boundary (internal/store/situation_s5_replay_test.go): it
// injected lifecycle/work/contracts and marked intents delivered without
// rendering anything. Those tests are kept — they pin candidate kinds and
// supersession the delivery layer cannot see — but they are NOT evidence
// about what an operator reads, which is what this file supplies.
//
// Event facts and target copy come from replay/replayTargets in the frozen
// canonical HTML (03-situation-history-slack-ownership/
// 2026-09-07-situation-state-map.html, SHA-256
// 60c255596f9e7fc96f616a30216edd35afc76ec8c3dba48793c816a06be28fbd):
//
//	1. 15:09:09 First root arrives     — Active 4/4 firing, root only, no reply
//	2. 15:10:33 Investigation starts   — root edit + one execution assurance
//	3. 15:10:58 Finding published      — root edit + one finding reply
//	4. 15:11:29 One of four clears     — root edit + one partial-recovery reply
//	5. 15:13:29 Quiet status checks    — root deadline refreshed, NO reply
//	6. 15:13:58 All four clear         — root edit + one all-clear reply
//	7. 15:15:59 Recovery confirmed     — root edit + one terminal-end reply
//
// FIXTURE CLOCK OFFSETS (stated explicitly, per the same review): the
// canonical wall-clock instants are R3's recorded history, not a policy.
// This replay preserves the canonical ORDER and each event's causal
// trigger, and derives every deadline from the shipped policy instead of
// restating R3's numbers:
//
//   - Events 1-4 and 6-7 run at the canonical inter-event offsets
//     (+84s, +25s, +31s, +29s from their predecessor).
//   - Event 5 runs at the Situation's OWN persisted next_assessment_at —
//     the "recorded checkpoint" the slide names. In this build that
//     checkpoint is the assessment cadence, so it lands ~15 minutes after
//     event 4 rather than R3's 2 minutes. Waking the controller earlier
//     would not be a status checkpoint at all.
//   - Event 7 runs at the Situation's OWN persisted grace_until, which
//     the controller derives from the recovery observation plus the
//     configured webhook recovery grace (120s by default). R3's own
//     recovery_pending 15:13:55 -> recovered 15:15:56 is the same 2
//     minutes, so the canonical narrative and the shipped policy agree
//     here; the deadline is still read from the row, never assumed.
//   - The Situation is 45 minutes old before event 1, because a
//     duration_outlier Sufficient reason (this build's only reachable
//     non-floor reason) is what authorizes publication at all.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// The canonical four-alert R3 scope.
// ----------------------------------------------------------------------

type s5rAlert struct{ id, fingerprint, name string }

func s5rAlerts() []s5rAlert {
	return []s5rAlert{
		{"alert-podcrash", "fp-podcrash", "PodCrashLooping"},
		{"alert-latency", "fp-latency", "LatencyP99"},
		{"alert-errorrate", "fp-errorrate", "HighErrorRate"},
		{"alert-queue", "fp-queue", "QueueBacklog"},
	}
}

const (
	s5rQueueBacklog = "QueueBacklog"
	s5rScope        = "checkout"
)

type s5rFixture struct {
	*e2eFixture

	groupKey   string
	incidentID string
	sitID      string
	rootTS     string
	episode    time.Time
	seen       int // fake-Slack calls already accounted for
}

// ----------------------------------------------------------------------
// Source facts: real deliveries through the real acceptance path.
// ----------------------------------------------------------------------

// accept records one immutable alert delivery for a and links it to this
// Situation's Incident, exactly as the Alertmanager receiver would. A
// resolved delivery keeps the episode's own SourceStartedAt and carries a
// later ReceivedAt, which is how latestDeliveryPerAlert orders the two.
func (r *s5rFixture) accept(a s5rAlert, status string, receivedAt time.Time) {
	r.t.Helper()
	id := fmt.Sprintf("del-%s-%s-%d", a.id, status, receivedAt.Unix())
	started := r.episode
	in := store.DeliveryInput{
		ID: id,
		Alert: store.Alert{
			ID: a.id, Fingerprint: a.fingerprint, Status: status,
			Labels:      map[string]string{"alertname": a.name, "service": s5rScope},
			Annotations: map[string]string{"summary": a.name + " on " + s5rScope},
			StartsAt:    started, ReceivedAt: receivedAt,
		},
		Source:                   "alertmanager",
		SourceEpisodeKey:         "alertmanager:" + a.fingerprint + ":" + started.UTC().Format(time.RFC3339Nano),
		SourceStartedAt:          &started,
		StartedAtBasis:           model.SourceTimeBasisSourcePayload,
		ResolvedAtBasis:          model.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: "group:" + r.groupKey,
		PayloadDigest:            "sha256:" + id,
		SourceProvenance:         store.SourceProvenance{AcquisitionMode: store.SourceAcquisitionWebhook},
	}
	if status == "resolved" {
		res := receivedAt
		in.SourceResolvedAt = &res
		in.ResolvedAtBasis = model.SourceTimeBasisSourcePayload
	}
	dels, err := r.st.AcceptDeliveries(r.ctx, []store.DeliveryInput{in})
	if err != nil || len(dels) != 1 {
		r.t.Fatalf("accept delivery %s: %v (%d accepted)", id, err, len(dels))
	}
	if _, err := r.st.DB().ExecContext(r.ctx,
		`INSERT INTO incident_alert_deliveries (incident_id, delivery_id, created_at) VALUES (?, ?, ?)`,
		r.incidentID, dels[0].ID, receivedAt.UTC().Format(time.RFC3339Nano)); err != nil {
		r.t.Fatalf("link delivery %s to incident: %v", id, err)
	}
}

// enqueueInput appends one pending Situation input of kind and applies it,
// which is what re-arms the Situation for its next controller cycle.
func (r *s5rFixture) enqueueInput(kind, suffix string) {
	r.t.Helper()
	now := r.clock.Now()
	inputID := "input-" + r.groupKey + "-" + suffix
	if _, err := r.st.DB().ExecContext(r.ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
		inputID, "idem:"+inputID, r.incidentID, kind, r.groupKey, now.UTC().Format(time.RFC3339Nano)); err != nil {
		r.t.Fatalf("insert %s situation input: %v", kind, err)
	}
	r.applyPendingInputs()
}

// applyPendingInputs drains the Situation input outbox through the real
// claim/apply pair. The Acute Triage writers append their own inputs
// (triage_retry_changed on a claim, finding_persisted on a completion), so
// this runs after every work event too, not only after a membership change.
func (r *s5rFixture) applyPendingInputs() {
	r.t.Helper()
	now := r.clock.Now()
	for i := 0; i < 20; i++ {
		claims, err := r.st.ClaimSituationInputs(r.ctx, fmt.Sprintf("s5r:%d:%d", now.UnixNano(), i), now, time.Minute, 5)
		if err != nil {
			r.t.Fatalf("claim situation inputs: %v", err)
		}
		if len(claims) == 0 {
			return
		}
		for _, c := range claims {
			if err := r.st.ApplySituationInput(r.ctx, c); err != nil {
				r.t.Fatalf("apply situation input: %v", err)
			}
		}
	}
	r.t.Fatal("situation input outbox did not drain")
}

// deliverNow runs notification-worker rounds at the CURRENT clock until one
// handles nothing. Every event below runs against a healthy fake provider
// unless it says otherwise, so nothing waits on a retry backoff and no
// clock advance is needed — deliverUntilQuiet's six-minute steps would move
// every canonical offset this replay asserts against.
func (r *s5rFixture) deliverNow() {
	r.t.Helper()
	for i := 0; i < 25; i++ {
		if r.deliverRound() == 0 {
			return
		}
	}
	r.t.Fatalf("delivery did not settle at a fixed clock: %s", r.intentSummary())
}

func (r *s5rFixture) advanceTo(target time.Time) {
	r.t.Helper()
	if now := r.clock.Now(); target.Before(now) {
		r.t.Fatalf("cannot rewind the fixture clock from %s to %s", now, target)
	} else {
		r.clock.advance(target.Sub(now))
	}
}

// ----------------------------------------------------------------------
// Durable readers.
// ----------------------------------------------------------------------

func (r *s5rFixture) lifecycle() string {
	r.t.Helper()
	var lifecycle string
	if err := r.st.DB().QueryRowContext(r.ctx, `SELECT lifecycle FROM situations WHERE id = ?`, r.sitID).Scan(&lifecycle); err != nil {
		r.t.Fatalf("read lifecycle: %v", err)
	}
	return lifecycle
}

// situationTime reads one nullable RFC3339 column off the Situation row.
func (r *s5rFixture) situationTime(column string) (time.Time, bool) {
	r.t.Helper()
	var raw *string
	//nolint:gosec // column is a fixed literal chosen by this file, never input.
	if err := r.st.DB().QueryRowContext(r.ctx, `SELECT `+column+` FROM situations WHERE id = ?`, r.sitID).Scan(&raw); err != nil {
		r.t.Fatalf("read %s: %v", column, err)
	}
	if raw == nil {
		return time.Time{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, *raw)
	if err != nil {
		r.t.Fatalf("parse %s %q: %v", column, *raw, err)
	}
	return at, true
}

func (r *s5rFixture) mustSituationTime(column string) time.Time {
	r.t.Helper()
	at, ok := r.situationTime(column)
	if !ok {
		r.t.Fatalf("%s is NULL; the replay needs the persisted value", column)
	}
	return at
}

// transitionCount is how much durable history this Situation has recorded.
func (r *s5rFixture) transitionCount() int {
	return r.scalarInt(`SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ?`, r.sitID)
}

// deliveredReplies counts every thread_append/broadcast_handoff intent this
// Situation has ever actually delivered.
func (r *s5rFixture) deliveredReplies() int {
	return r.scalarInt(`
		SELECT COUNT(*) FROM notification_intents
		WHERE situation_id = ? AND effect_class IN ('thread_append','broadcast_handoff') AND status = 'delivered'`, r.sitID)
}

// ----------------------------------------------------------------------
// One event's actual operator-visible outcome.
// ----------------------------------------------------------------------

// s5rOutcome is everything one replay event actually produced on the wire.
type s5rOutcome struct {
	rootPosts  []e2eSlackCall
	rootEdits  []e2eSlackCall
	replies    []e2eSlackCall
	modelCalls int // model calls consumed by the controller cycle
	deliverAdd int // model calls consumed by delivery (must always be 0)
}

func (o s5rOutcome) rootWrites() int { return len(o.rootPosts) + len(o.rootEdits) }

// all is every payload the segment actually put on the wire.
func (o s5rOutcome) all() []e2eSlackCall {
	out := make([]e2eSlackCall, 0, o.rootWrites()+len(o.replies))
	out = append(out, o.rootPosts...)
	out = append(out, o.rootEdits...)
	return append(out, o.replies...)
}

// currentRoot is the last root write of the event: what the operator's one
// main message now says.
func (o s5rOutcome) currentRoot() (e2eSlackCall, bool) {
	if n := len(o.rootEdits); n > 0 {
		return o.rootEdits[n-1], true
	}
	if n := len(o.rootPosts); n > 0 {
		return o.rootPosts[n-1], true
	}
	return e2eSlackCall{}, false
}

// runEvent runs one controller cycle plus its delivery at the current clock
// and reports exactly what reached the fake provider. wantCycleCalls is the
// model calls the controller half must consume, stated per event and
// asserted rather than merely logged (lead review round 2, 2026-09-10,
// finding 2). The delivery half must always consume none.
func (r *s5rFixture) runEvent(label string, wantCycleCalls int) s5rOutcome {
	r.t.Helper()
	beforeCalls := r.l2.callCount()
	r.drainController()
	cycleCalls := r.l2.callCount() - beforeCalls

	out := r.deliverSegment(label)
	out.modelCalls = cycleCalls
	if cycleCalls != wantCycleCalls {
		r.t.Fatalf("%s: the controller cycle consumed %d model call(s), want exactly %d", label, cycleCalls, wantCycleCalls)
	}
	r.logOutcome(label, out)
	return out
}

// deliverSegment runs delivery alone at the current clock and classifies
// every payload that reached the provider since the last look. EVERY
// delivery in this file goes through it, so no payload escapes the shared
// per-payload checks and no delivery segment escapes its own zero-model-call
// assertion — including the overtaken case's manual recovery segment, which
// asserts its own event shape instead of calling assertEvent.
func (r *s5rFixture) deliverSegment(label string) s5rOutcome {
	r.t.Helper()
	beforeCalls := r.l2.callCount()
	r.deliverNow()
	out := s5rOutcome{deliverAdd: r.l2.callCount() - beforeCalls}

	all := r.slack.accepted()
	for _, c := range all[r.seen:] {
		switch {
		case c.Method == "chat.update":
			out.rootEdits = append(out.rootEdits, c)
		case c.Method == "chat.postMessage" && c.ThreadTS == "":
			out.rootPosts = append(out.rootPosts, c)
		default:
			out.replies = append(out.replies, c)
		}
	}
	r.seen = len(all)

	// Delivery must never consult a model: rendering reads recorded facts.
	if out.deliverAdd != 0 {
		r.t.Fatalf("%s: delivery consumed %d model call(s); rendering a recorded Transition must consult no model", label, out.deliverAdd)
	}
	r.assertPayloads(label, out.all())
	return out
}

// drainCycle runs a controller cycle with no delivery behind it — the
// segments that commit while the provider is unreachable — and asserts the
// model calls it consumed.
func (r *s5rFixture) drainCycle(label string, wantCycleCalls int) {
	r.t.Helper()
	beforeCalls := r.l2.callCount()
	r.drainController()
	if got := r.l2.callCount() - beforeCalls; got != wantCycleCalls {
		r.t.Fatalf("%s: the controller cycle consumed %d model call(s), want exactly %d", label, got, wantCycleCalls)
	}
}

// failedDeliveryRound runs one delivery round against an unreachable
// provider. Nothing is accepted, so there is no payload to classify — but
// the round must still consult no model.
func (r *s5rFixture) failedDeliveryRound(label string) {
	r.t.Helper()
	beforeCalls := r.l2.callCount()
	r.deliverRound()
	if got := r.l2.callCount() - beforeCalls; got != 0 {
		r.t.Fatalf("%s: a failed delivery round consumed %d model call(s), want none", label, got)
	}
	if accepted := r.slack.accepted(); len(accepted) != r.seen {
		r.t.Fatalf("%s: the unreachable provider accepted %d call(s)", label, len(accepted)-r.seen)
	}
}

// logOutcome prints the event's actual root and reply payloads. The B6
// handoff asks for readable root and reply payloads in the return; running
// this file with -v is where they come from.
func (r *s5rFixture) logOutcome(label string, out s5rOutcome) {
	r.t.Helper()
	r.t.Logf("=== %s @ %s · lifecycle=%s · model calls: cycle=%d delivery=%d",
		label, r.clock.Now().Format(time.RFC3339), r.lifecycle(), out.modelCalls, out.deliverAdd)
	for _, c := range append(append([]e2eSlackCall{}, out.rootPosts...), out.rootEdits...) {
		r.t.Logf("--- root (%s)\n%s", c.Method, c.Text)
	}
	for _, c := range out.replies {
		r.t.Logf("--- thread reply\n%s", c.Text)
	}
	if len(out.replies) == 0 {
		r.t.Logf("--- thread reply: none")
	}
}

// s5rExpect is one canonical replayTargets row, expressed as what must be
// observable on the wire.
type s5rExpect struct {
	lifecycle   string
	orientation string   // the neutral ▸ marker slide 4 reserves for orientation
	rootMust    []string // facts the refreshed root must state
	rootMustNot []string
	replies     int
	replyMust   []string
	// transitions is the total durable Transition count after this event;
	// a quiet checkpoint refreshes the root without recording history.
	transitions int
}

func (r *s5rFixture) assertEvent(label string, out s5rOutcome, want s5rExpect) {
	r.t.Helper()
	if got := r.lifecycle(); got != want.lifecycle {
		r.t.Fatalf("%s: lifecycle = %s, want %s", label, got, want.lifecycle)
	}
	if got := r.transitionCount(); got != want.transitions {
		r.t.Fatalf("%s: recorded transitions = %d, want %d", label, got, want.transitions)
	}
	if got := len(out.replies); got != want.replies {
		r.t.Fatalf("%s: thread replies = %d, want %d", label, got, want.replies)
	}
	if out.rootWrites() != 1 {
		r.t.Fatalf("%s: root writes = %d, want exactly 1 (the one main message, updated in place)", label, out.rootWrites())
	}
	root, ok := out.currentRoot()
	if !ok {
		r.t.Fatalf("%s: no root write at all", label)
	}
	// Blocks are what an operator's client actually renders; the fallback
	// Text is a courtesy field. Every meaningful fact below is therefore
	// asserted in BOTH (lead review round 2, 2026-09-10, finding 2).
	rootBlocks := r.blockText(label+" root", root.Blocks)
	if want.orientation != "" {
		marker := "*▸ " + want.orientation + "*"
		r.mustSay(label, "root", root, rootBlocks, marker)
	}
	for _, must := range want.rootMust {
		r.mustSay(label, "root", root, rootBlocks, must)
	}
	for _, never := range want.rootMustNot {
		r.mustNotSay(label, "root", root, rootBlocks, never)
	}
	if want.replies == 1 {
		reply := out.replies[0]
		if reply.ThreadTS != r.rootTS {
			r.t.Fatalf("%s: reply thread_ts = %q, want the Situation's own root %q", label, reply.ThreadTS, r.rootTS)
		}
		replyBlocks := r.blockText(label+" reply", reply.Blocks)
		for _, must := range want.replyMust {
			r.mustSay(label, "reply", reply, replyBlocks, must)
		}
	}
}

// mustSay requires want in the delivered fallback text AND in the decoded
// Block Kit text of the same message.
func (r *s5rFixture) mustSay(label, role string, c e2eSlackCall, blocks, want string) {
	r.t.Helper()
	if !strings.Contains(c.Text, want) {
		r.t.Fatalf("%s: %s fallback text is missing %q:\n%s", label, role, want, c.Text)
	}
	if !strings.Contains(blocks, want) {
		r.t.Fatalf("%s: %s renders without %q; the operator reads the blocks, not the fallback:\n%s", label, role, want, blocks)
	}
}

// mustNotSay requires never in neither the fallback text nor the blocks.
func (r *s5rFixture) mustNotSay(label, role string, c e2eSlackCall, blocks, never string) {
	r.t.Helper()
	if strings.Contains(c.Text, never) {
		r.t.Fatalf("%s: %s fallback text must not contain %q:\n%s", label, role, never, c.Text)
	}
	if strings.Contains(blocks, never) {
		r.t.Fatalf("%s: %s renders %q, which it must not:\n%s", label, role, never, blocks)
	}
}

// assertPayloads applies the checks EVERY delivered message must pass,
// whatever produced it: a real Block Kit payload; §7's rule that this
// release renders the status-check fallback and never an unenforceable
// visible-reply promise; and S5-03's rule that every bracketed placeholder
// in the illustrative target copy was replaced with recorded data rather
// than shipped as copy. deliverSegment runs it for every segment, so the
// redundant and overtaken variants are covered as fully as the delivered
// one even though they assert their own event shape.
//
// Absence of a placeholder is a negative control only. It shows no
// illustrative token shipped; it is never evidence that the fact the token
// stood for was populated. That is what the per-event rootMust/replyMust
// assertions above, and the audit's own row-by-row map, are for.
func (r *s5rFixture) assertPayloads(label string, calls []e2eSlackCall) {
	r.t.Helper()
	for _, c := range calls {
		if strings.TrimSpace(c.Blocks) == "" || c.Blocks == "null" {
			r.t.Fatalf("%s: a delivered %s carried no blocks payload", label, c.Method)
		}
		for _, bad := range []string{"update by", "Update by"} {
			if strings.Contains(c.Text, bad) || strings.Contains(c.Blocks, bad) {
				r.t.Fatalf("%s: delivered %s contains the unsupported promise %q:\n%s", label, c.Method, bad, c.Text)
			}
		}
		r.assertNoPlaceholders(label, c)
	}
}

// rendered is everything an operator could see on one message: the
// fallback text and the decoded Block Kit text together. A must-NOT
// assertion reads this, so unwanted copy is caught wherever it hides.
func (r *s5rFixture) rendered(label string, c e2eSlackCall) string {
	r.t.Helper()
	return c.Text + "\n" + r.blockText(label, c.Blocks)
}

// blockText decodes one captured Block Kit payload into every text string
// it carries, joined in a deterministic order. This is the operator-visible
// rendering; assertions run against it, not only the fallback field.
func (r *s5rFixture) blockText(label, blocks string) string {
	r.t.Helper()
	var decoded any
	if err := json.Unmarshal([]byte(blocks), &decoded); err != nil {
		r.t.Fatalf("%s: blocks payload is not valid JSON (%v):\n%s", label, err, blocks)
	}
	var b strings.Builder
	s5rWalkText(decoded, &b)
	return b.String()
}

// s5rWalkText collects every "text" string in a decoded Block Kit tree.
// Object keys are visited in sorted order so the joined result never
// depends on Go's map iteration order.
func s5rWalkText(v any, b *strings.Builder) {
	switch node := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(node))
		for k := range node {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "text" {
				if s, ok := node[k].(string); ok {
					b.WriteString(s)
					b.WriteString("\n")
					continue
				}
			}
			s5rWalkText(node[k], b)
		}
	case []any:
		for _, child := range node {
			s5rWalkText(child, b)
		}
	}
}

// s5rPlaceholders is every bracketed token the frozen canonical HTML's 32
// slackExamples use in their status/activity/finding/thread/action copy.
// The list is the audit's own input, transcribed from the HTML; nothing
// rendered from recorded data may contain any of them (S5-03: "Replace
// bracketed placeholders only with recorded data").
var s5rPlaceholders = []string{
	"[Decision consequence]", "[Names of the alerts in this investigation]", "[accepted finding]",
	"[accepted result]", "[actual observation]", "[affected alert]", "[affected monitoring source]",
	"[affected scope]", "[affected source]", "[alert names]", "[new recorded update deadline]",
	"[observations]", "[recorded checkpoint]", "[recorded count]", "[recorded grace deadline]",
	"[recorded readiness/due condition]", "[recorded retry time]", "[recorded scope]",
	"[recorded update deadline]", "[relevant fact]", "[retained finding]", "[specific check]",
	"[specific decision-relevant fact]", "[specific fact]", "[supporting observation]",
	"[supporting observations]", "[useful observations]",
}

// s5rUnfilledBracket catches a placeholder shape this list has not seen yet,
// so a new illustrative token cannot slip into a rendered payload unnoticed.
var s5rUnfilledBracket = regexp.MustCompile(`\[[A-Za-z][^\]]{3,}\]`)

func (r *s5rFixture) assertNoPlaceholders(label string, c e2eSlackCall) {
	r.t.Helper()
	for _, field := range []string{c.Text, c.Blocks} {
		for _, token := range s5rPlaceholders {
			if strings.Contains(field, token) {
				r.t.Fatalf("%s: delivered %s ships the illustrative placeholder %q:\n%s", label, c.Method, token, c.Text)
			}
		}
		if m := s5rUnfilledBracket.FindString(field); m != "" {
			r.t.Fatalf("%s: delivered %s contains an unfilled bracketed token %q:\n%s", label, c.Method, m, c.Text)
		}
	}
}

// slackDateToken is the exact <!date^…> token the renderer emits for at, so
// a timing assertion names the persisted instant rather than a substring of
// prose.
func slackDateToken(at time.Time) string { return fmt.Sprintf("<!date^%d^", at.UTC().Unix()) }

// ----------------------------------------------------------------------
// Fixture construction.
// ----------------------------------------------------------------------

// newS5RFixture seeds the canonical four-alert R3 Situation: five prior
// closed Situations for the group (so a duration_outlier Sufficient reason
// is reachable at all), one Incident carrying four firing alerts, and the
// production ready transition that seeds its awaiting_decision Acute Triage
// schedule.
func newS5RFixture(t *testing.T, groupKey string) *s5rFixture {
	t.Helper()
	f := newE2EFixture(t)
	f.slack.setScript(alwaysOK)
	r := &s5rFixture{e2eFixture: f, groupKey: groupKey, incidentID: "inc-" + groupKey}

	f.seedPriorTerminalLineage(groupKey, 5)

	r.episode = f.clock.Now()
	if err := f.st.InsertIncident(f.ctx, store.Incident{
		ID: r.incidentID, GroupKey: groupKey,
		FirstAlertAt: r.episode, LastAlertAt: r.episode, ReadyAt: r.episode.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	for _, a := range s5rAlerts() {
		r.accept(a, "firing", r.episode)
	}
	if err := f.st.MarkIncidentReadyWithSituationInput(f.ctx, r.incidentID, f.clock.Now()); err != nil {
		t.Fatalf("mark incident ready: %v", err)
	}
	r.enqueueInput("incident_created", "created")
	r.sitID = f.situationIDForIncident(r.incidentID)
	// 45 minutes: the live Situation's elapsed duration becomes an outlier
	// against its minutes-long priors, which is what makes publication
	// authority reachable.
	f.clock.advance(45 * time.Minute)
	f.l2.steer(model.AttentionObserve, true)
	return r
}

// startInvestigation claims the Incident's decided Acute Triage attempt —
// the real writer that records an actual execution start.
func (r *s5rFixture) startInvestigation() store.ClaimedTriageAttempt {
	r.t.Helper()
	claim, err := r.st.ClaimIncidentTriageAttempt(r.ctx, r.incidentID, "s5r-triage", r.clock.Now(), 10*time.Minute)
	if err != nil {
		r.t.Fatalf("claim triage attempt: %v", err)
	}
	if len(claim.MemberDeliveryIDs) != len(s5rAlerts()) {
		r.t.Fatalf("frozen investigation inputs = %d, want the %d recorded alerts", len(claim.MemberDeliveryIDs), len(s5rAlerts()))
	}
	r.applyPendingInputs()
	return claim
}

// publishFinding persists the canonical R3 hypothesis through the real
// completion writer.
func (r *s5rFixture) publishFinding(attemptID string) {
	r.t.Helper()
	res, err := r.st.CompleteIncidentTriageAttempt(r.ctx, attemptID, r.incidentID, store.TriageFinding{
		OutputJSON: `{"correlation_findings":["Pod restarts precede the error-rate spike",` +
			`"Queue backlog follows the error spike"]}`,
		Summary:    "pod crash to error spike to queue backlog",
		RootCause:  "Pod restarts in checkout drove the error spike and the queue backlog",
		Confidence: 0.7, EvidencePackDigest: "sha256:s5r-evidence-1",
	}, r.clock.Now())
	if err != nil {
		r.t.Fatalf("complete triage attempt: %v", err)
	}
	if res.Outcome != store.TriageCompletionSuccess {
		r.t.Fatalf("completion outcome = %q, want success", res.Outcome)
	}
	r.applyPendingInputs()
}

// ----------------------------------------------------------------------
// S5-01: the seven-event replay, rendered.
// ----------------------------------------------------------------------

func TestS5ReplayDeliveredSequenceRendersEveryCanonicalEvent(t *testing.T) {
	r := newS5RFixture(t, "group=s5r-delivered")

	// Event 1 — 15:09:09 the first root arrives. No work has started.
	ev1 := r.runEvent("event 1 · first root arrives", 1)
	if len(ev1.rootPosts) != 1 {
		t.Fatalf("event 1 posted %d root message(s), want exactly the initial overview", len(ev1.rootPosts))
	}
	r.rootTS = ev1.rootPosts[0].TS
	if _, ts := r.rootCoordinates(r.sitID); ts != r.rootTS {
		t.Fatalf("durable root ts = %q, want the posted %q", ts, r.rootTS)
	}
	r.assertEvent("event 1", ev1, s5rExpect{
		lifecycle: "active", orientation: "Observed", transitions: 1, replies: 0,
		rootMust:    []string{"4/4 alerts firing", "Next status check:", "has not started yet"},
		rootMustNot: []string{"Investigating 4 alerts"},
	})

	// Event 2 — 15:10:33 the bounded investigation actually claims and starts.
	// From here to event 4 the controller re-decides on already-assessed
	// facts, so the expected model-call count for each is zero: the second
	// argument to runEvent is that expectation, asserted for every event.
	r.clock.advance(84 * time.Second)
	claim := r.startInvestigation()
	ev2 := r.runEvent("event 2 · investigation starts", 0)
	r.assertEvent("event 2", ev2, s5rExpect{
		lifecycle: "active", orientation: "Investigating", transitions: 2, replies: 1,
		rootMust: []string{"Investigating 4 alerts for " + s5rScope, "Next status check:"},
		// The one initial execution assurance: actual investigated count
		// and names, never a Situation total (slide 4 · running).
		replyMust: []string{"Investigating 4 alerts for " + s5rScope,
			"PodCrashLooping", "LatencyP99", "HighErrorRate", s5rQueueBacklog},
	})

	// Event 3 — 15:10:58 the finding is persisted and earns its reply.
	r.clock.advance(25 * time.Second)
	r.publishFinding(claim.AttemptID)
	ev3 := r.runEvent("event 3 · finding published", 0)
	r.assertEvent("event 3", ev3, s5rExpect{
		lifecycle: "active", orientation: "Monitoring", transitions: 3, replies: 1,
		rootMust: []string{"pod crash to error spike to queue backlog", "Next status check:"},
		replyMust: []string{"Pod restarts precede the error-rate spike",
			"Queue backlog follows the error spike", "Still unknown:", "Next status check:"},
	})

	// Event 4 — 15:11:29 QueueBacklog clears; three remain firing.
	r.clock.advance(31 * time.Second)
	r.accept(s5rAlerts()[3], "resolved", r.clock.Now())
	r.enqueueInput("membership_changed", "queue-clear")
	ev4 := r.runEvent("event 4 · one of four clears", 0)
	r.assertEvent("event 4", ev4, s5rExpect{
		lifecycle: "active", orientation: "Monitoring", transitions: 4, replies: 1,
		rootMust: []string{"3/4 alerts firing", "Next status check:"},
		replyMust: []string{s5rQueueBacklog + " cleared", "*Cleared:* " + s5rQueueBacklog,
			"*Still firing:* HighErrorRate, LatencyP99, PodCrashLooping"},
	})

	// Event 5 — 15:13:29 the recorded status checkpoint itself comes due,
	// with nothing else changed. The canonical target: "Root deadlines
	// refreshed; no thread spam", postReply false.
	checkpoint := r.mustSituationTime("next_assessment_at")
	if !checkpoint.After(r.clock.Now()) {
		t.Fatalf("recorded checkpoint %s is not in the future; event 5 would not be a checkpoint tick", checkpoint)
	}
	r.advanceTo(checkpoint)
	ev5 := r.runEvent("event 5 · quiet status checkpoint", 1)
	r.assertEvent("event 5", ev5, s5rExpect{
		// No new Transition: nothing material changed. The root is still
		// refreshed in place, which is exactly what the slide claims.
		lifecycle: "active", orientation: "Monitoring", transitions: 4, replies: 0,
		rootMust: []string{"3/4 alerts firing", "Next status check:"},
	})
	refreshed := r.mustSituationTime("next_assessment_at")
	if !refreshed.After(checkpoint) {
		t.Fatalf("event 5 left the checkpoint at %s; the quiet tick must move the root's own deadline forward", refreshed)
	}
	root5, _ := ev5.currentRoot()
	if !strings.Contains(root5.Text, slackDateToken(refreshed)) {
		t.Fatalf("event 5 root does not carry the refreshed checkpoint %s:\n%s", refreshed, root5.Text)
	}
	// The one model call runEvent asserted above IS the scheduled
	// assessment this checkpoint exists to make; nothing more. No second
	// call is made to advance a clock or rewrite a qualifier, and the
	// delivery that follows makes none at all.

	// Event 6 — 15:13:58 every monitored alert clears.
	r.clock.advance(29 * time.Second)
	for _, a := range s5rAlerts()[:3] {
		r.accept(a, "resolved", r.clock.Now())
	}
	r.enqueueInput("membership_changed", "all-clear")
	ev6 := r.runEvent("event 6 · all four clear", 1)
	grace := r.mustSituationTime("grace_until")
	observed := r.mustSituationTime("recovery_observed_at")
	if got := grace.Sub(observed); got != 2*time.Minute {
		t.Fatalf("derived recovery grace = %s, want the configured 2m webhook grace", got)
	}
	r.assertEvent("event 6", ev6, s5rExpect{
		lifecycle: "recovery_pending", orientation: "Confirming recovery", transitions: 5, replies: 1,
		rootMust:  []string{"4 alerts resolved", slackDateToken(grace)},
		replyMust: []string{"Cleared:", slackDateToken(grace)},
	})

	// Event 7 — 15:15:59 the persisted grace deadline expires. Nothing is
	// forced: one cycle a second before expiry must still be confirming.
	r.advanceTo(grace.Add(-time.Second))
	pre := r.runEvent("event 7a · one second before the grace deadline", 1)
	r.assertEvent("event 7a", pre, s5rExpect{
		lifecycle: "recovery_pending", orientation: "Confirming recovery", transitions: 5, replies: 0,
		rootMust: []string{slackDateToken(grace)},
	})

	r.advanceTo(grace.Add(3 * time.Second))
	ev7 := r.runEvent("event 7 · recovery confirmed", 0)
	terminal := r.mustSituationTime("terminal_at")
	if terminal.Before(grace) {
		t.Fatalf("terminal_at %s precedes the persisted grace deadline %s", terminal, grace)
	}
	r.assertEvent("event 7", ev7, s5rExpect{
		lifecycle: "recovered", orientation: "Recovered", transitions: 6, replies: 1,
		rootMust: []string{"Recovery confirmed after the observation period",
			"monitoring for this episode has ended"},
		// Tracking ended: no further automatic check is promised.
		rootMustNot: []string{"Next status check:"},
		replyMust: []string{"Recovery confirmed after the observation period",
			"monitoring for this episode has ended"},
	})
	if seen := r.rendered("event 7 reply", ev7.replies[0]); strings.Contains(seen, "Next status check:") {
		t.Fatalf("the terminal reply promises another automatic check:\n%s", seen)
	}

	// S5-02, delivered case: five earned replies — the four R3 recorded
	// (finding, partial recovery, all-clear, recovered) plus the assurance
	// the illustrative target adds when it is delivered before the finding.
	if got := r.deliveredReplies(); got != 5 {
		t.Fatalf("delivered replies = %d, want 5 (assurance, finding, partial recovery, all-clear, recovered)%s",
			got, r.intentSummary())
	}
	if got := r.scalarInt(
		`SELECT COUNT(*) FROM notification_intents WHERE situation_id = ? AND status NOT IN ('delivered','superseded')`,
		r.sitID); got != 0 {
		t.Fatalf("%d intent(s) never settled%s", got, r.intentSummary())
	}
}

// ----------------------------------------------------------------------
// S5-02, redundant case: the awaiting root is authorized but the provider
// is unreachable, so the first main message that actually posts is the one
// the running investigation earned. It conveys execution itself, and no
// separate assurance reply is ever delivered — the "first-root-running"
// Slack example ("Initial publication occurs after actual execution
// started. This main message serves as the one initial assurance").
// ----------------------------------------------------------------------

func TestS5ReplayRedundantFirstRootPostsNoAssurance(t *testing.T) {
	r := newS5RFixture(t, "group=s5r-redundant")
	// Publication is authorized but the provider is unreachable, so the
	// awaiting root never actually posts.
	r.slack.setScript(alwaysStatus(http.StatusServiceUnavailable, 0))
	r.drainCycle("publication cycle · provider unreachable", 1)
	r.failedDeliveryRound("publication delivery · provider unreachable")

	r.clock.advance(84 * time.Second)
	claim := r.startInvestigation()
	r.drainCycle("execution start cycle · provider unreachable", 0)
	r.slack.setScript(alwaysOK)
	first := r.runEvent("first root · execution already running", 0)
	if len(first.rootPosts) != 1 {
		t.Fatalf("first publication posted %d root message(s), want exactly 1%s", len(first.rootPosts), r.intentSummary())
	}
	r.rootTS = first.rootPosts[0].TS
	if len(first.replies) != 0 {
		t.Fatalf("first publication also posted %d thread repl(y/ies); the initial root conveys execution itself:\n%s",
			len(first.replies), first.replies[0].Text)
	}
	firstRoot := first.rootPosts[0]
	r.mustSay("first root", "root", firstRoot, r.blockText("first root", firstRoot.Blocks),
		"Investigating 4 alerts for "+s5rScope)
	r.mustSay("first root", "root", firstRoot, r.blockText("first root", firstRoot.Blocks), "*\u25b8 Investigating*")

	r.clock.advance(25 * time.Second)
	r.publishFinding(claim.AttemptID)
	r.runEvent("finding published", 0)

	r.clock.advance(31 * time.Second)
	r.accept(s5rAlerts()[3], "resolved", r.clock.Now())
	r.enqueueInput("membership_changed", "queue-clear")
	r.runEvent("one of four clears", 0)

	r.clock.advance(29 * time.Second)
	for _, a := range s5rAlerts()[:3] {
		r.accept(a, "resolved", r.clock.Now())
	}
	r.enqueueInput("membership_changed", "all-clear")
	r.runEvent("all four clear", 1)

	grace := r.mustSituationTime("grace_until")
	r.advanceTo(grace.Add(3 * time.Second))
	r.runEvent("recovery confirmed", 1)

	if got := r.lifecycle(); got != "recovered" {
		t.Fatalf("lifecycle = %s, want recovered", got)
	}
	if got := r.deliveredReplies(); got != 4 {
		t.Fatalf("delivered replies = %d, want 4: no assurance, because the first root already conveyed it%s",
			got, r.intentSummary())
	}
}

// ----------------------------------------------------------------------
// S5-02, overtaken case: the finding is ready while the start assurance is
// still queued behind an unavailable provider. The "finding-supersedes-
// start" Slack example.
//
// REPORTED DISCREPANCY D1 (product, not repaired here — B6 is an evaluator
// and the owning chunk is B5/§5.3). On this real sequence the commit-time
// obsolete-start supersession never fires, because it filters on
// journal_kind = 'investigation_started' (migration 0022,
// liveTransientAssuranceIntentIDsTx) while the controller records the
// actual execution start as operator_contract_changed: selectControllerReason
// only reaches ReasonInvestigationStarted when the PRIOR contract was not
// already an investigation, and investigationCurrent treats
// run_acute_triage/planned exactly like run_acute_triage/running. The
// canonical R3 order requests triage in the publishing cycle ("analysis was
// still pending/collecting") and starts it in the next one, so the guard's
// own precondition is never met.
//
// What the operator actually sees is still safe, and this test pins that:
// the stale ROOT edit is superseded normally (newer_root_projection), so
// only the finding's root lands, and B5's delivery-time narrowing strips
// the superseded start from the reply that does go out. The cost is one
// extra content-free reply, so the illustrative "stays at four" count is
// five here. The store-level regression that DOES reach the commit-time
// path (internal/store/situation_s5_replay_test.go) keeps that mechanism
// covered; it starts from a monitor_situation contract, which the canonical
// event 1 does not.
// ----------------------------------------------------------------------

func TestS5ReplayFindingOvertakesAnUndeliveredStart(t *testing.T) {
	r := newS5RFixture(t, "group=s5r-overtaken")

	ev1 := r.runEvent("event 1 · first root arrives", 1)
	if len(ev1.rootPosts) != 1 {
		t.Fatalf("event 1 posted %d root message(s), want 1", len(ev1.rootPosts))
	}
	r.rootTS = ev1.rootPosts[0].TS

	// Slack goes away exactly while the assurance is earned, so event 2's
	// root edit and reply are both still owed when the finding lands.
	r.slack.setScript(alwaysStatus(http.StatusServiceUnavailable, 0))
	r.clock.advance(84 * time.Second)
	claim := r.startInvestigation()
	r.drainCycle("execution start cycle · provider unreachable", 0)
	r.failedDeliveryRound("execution start delivery · provider unreachable")
	assuranceSeq := r.scalarInt(`SELECT MAX(sequence) FROM situation_transitions WHERE situation_id = ?`, r.sitID)
	if got := r.intentStatus(assuranceSeq, "thread_append"); got != "pending" {
		t.Fatalf("assurance reply status = %s before the finding, want pending", got)
	}

	// The finding commits while both are still owed.
	r.clock.advance(25 * time.Second)
	r.publishFinding(claim.AttemptID)
	r.drainCycle("finding cycle · provider unreachable", 0)
	findingSeq := r.scalarInt(`SELECT MAX(sequence) FROM situation_transitions WHERE situation_id = ?`, r.sitID)
	if findingSeq <= assuranceSeq {
		t.Fatalf("the finding did not commit its own Transition (sequences %d then %d)", assuranceSeq, findingSeq)
	}

	// The undelivered ROOT edit is superseded and names its replacement.
	// This is queried BY EFFECT CLASS: the first B6 candidate read the
	// thread_append row twice and so never asserted the root at all (lead
	// review 2026-09-10, additional precision).
	reply := r.intentRow(assuranceSeq, "thread_append")
	staleRoot := r.intentRow(assuranceSeq, "root_sync")
	freshRoot := r.intentRow(findingSeq, "root_sync")
	if staleRoot.ID == reply.ID {
		t.Fatalf("the root and reply assertions read the same intent row %q", staleRoot.ID)
	}
	if staleRoot.Status != "superseded" {
		t.Fatalf("the undelivered root edit status = %s, want superseded%s", staleRoot.Status, r.intentSummary())
	}
	if staleRoot.Reason != "newer_root_projection" {
		t.Fatalf("the superseded root's reason = %q, want newer_root_projection", staleRoot.Reason)
	}
	if staleRoot.Replacement != freshRoot.ID {
		t.Fatalf("the superseded root names replacement %q, want the finding's own root intent %q",
			staleRoot.Replacement, freshRoot.ID)
	}
	// D1 above: this row is still live at commit time. Asserted so the
	// discrepancy is visible here and fails loudly the day it is repaired.
	if reply.Status != "pending" {
		t.Fatalf("assurance reply status = %s; §5.3 commit-time supersession now reaches the canonical order — "+
			"reported discrepancy D1 is fixed, so update this expectation and the S5-02 self-check row", reply.Status)
	}

	// Slack returns. Only ONE root edit lands, and no stale start claim
	// ever reaches the operator.
	r.slack.setScript(alwaysOK)
	const settle = "provider returns · both owed messages settle"
	out := r.deliverSegment(settle)
	r.logOutcome(settle, out)
	replies := out.replies
	if len(out.rootEdits) != 1 || len(out.rootPosts) != 0 {
		t.Fatalf("recovery delivered %d root edit(s) and %d root post(s), want exactly the finding's own edit",
			len(out.rootEdits), len(out.rootPosts))
	}
	for _, c := range replies {
		if c.ThreadTS != r.rootTS {
			t.Fatalf("a settled reply landed on thread %q, not this Situation's root %q", c.ThreadTS, r.rootTS)
		}
	}
	for _, c := range replies {
		if seen := r.rendered(settle, c); strings.Contains(seen, "Investigating 4 alerts") {
			t.Fatalf("a stale start claim reached the operator after the finding:\n%s", seen)
		}
	}
	// The narrowed survivor states the supersession without claiming the
	// root was refreshed (B5 round 6, contract §46/3).
	var narrowed bool
	for _, c := range replies {
		seen := r.rendered(settle, c)
		if strings.Contains(c.Text, "have been superseded; they are not current") {
			narrowed = true
			r.mustSay(settle, "narrowed reply", c, r.blockText(settle, c.Blocks),
				"have been superseded; they are not current")
			if strings.Contains(seen, "main message") {
				t.Fatalf("the narrowed reply claims the main message is current:\n%s", seen)
			}
		}
	}
	if !narrowed {
		t.Fatalf("the overtaken assurance was delivered without the supersession statement: %d repl(y/ies)", len(replies))
	}

	r.clock.advance(31 * time.Second)
	r.accept(s5rAlerts()[3], "resolved", r.clock.Now())
	r.enqueueInput("membership_changed", "queue-clear")
	r.runEvent("one of four clears", 0)

	r.clock.advance(29 * time.Second)
	for _, a := range s5rAlerts()[:3] {
		r.accept(a, "resolved", r.clock.Now())
	}
	r.enqueueInput("membership_changed", "all-clear")
	r.runEvent("all four clear", 1)

	grace := r.mustSituationTime("grace_until")
	r.advanceTo(grace.Add(3 * time.Second))
	r.runEvent("recovery confirmed", 1)

	if got := r.lifecycle(); got != "recovered" {
		t.Fatalf("lifecycle = %s, want recovered", got)
	}
	// Five, not the illustrative four: D1 leaves the overtaken assurance
	// deliverable, narrowed. The safety property (no stale start on screen)
	// is asserted above; this count is the reported gap, not an expectation
	// the slide endorses.
	if got := r.deliveredReplies(); got != 5 {
		t.Fatalf("delivered replies = %d, want the 5 this build actually posts "+
			"(4 earned plus the narrowed overtaken assurance; the canonical target is 4 — see discrepancy D1)%s",
			got, r.intentSummary())
	}
}

// s5rIntent is one durable notification intent's supersession bookkeeping.
type s5rIntent struct {
	ID          string
	Status      string
	Reason      string
	Replacement string
}

// intentRow reads one intent of class belonging to the Transition at
// sequence — by effect class, so a root and a reply are never confused.
func (r *s5rFixture) intentRow(sequence int, class string) s5rIntent {
	r.t.Helper()
	var i s5rIntent
	var reason, replacement *string
	if err := r.st.DB().QueryRowContext(r.ctx, `
		SELECT i.id, i.status, i.supersession_reason, i.replacement_intent_id
		  FROM notification_intents i
		  JOIN situation_transitions t ON t.id = i.transition_id
		 WHERE i.situation_id = ? AND t.sequence = ? AND i.effect_class = ?`,
		r.sitID, sequence, class).Scan(&i.ID, &i.Status, &reason, &replacement); err != nil {
		r.t.Fatalf("read %s intent at sequence %d: %v", class, sequence, err)
	}
	if reason != nil {
		i.Reason = *reason
	}
	if replacement != nil {
		i.Replacement = *replacement
	}
	return i
}

func (r *s5rFixture) intentStatus(sequence int, class string) string {
	r.t.Helper()
	return r.intentRow(sequence, class).Status
}
