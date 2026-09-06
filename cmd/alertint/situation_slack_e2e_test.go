// SPDX-License-Identifier: FSL-1.1-ALv2

package main

// Plan 3 Task 10, Step 2: the deterministic fake-Slack end-to-end test.
//
// Everything in the delivery path below is the real, unmodified production
// component: a real *store.Store on disk, the real situation.Controller
// committing real Transitions/Episode summaries/notification intents, the
// real situation.NotificationWorker claiming and acknowledging them, the
// real cmd/alertint SituationDeliverer rendering them, and the real
// internal/notify/slack.Client putting them on the wire. The ONLY fake is
// the Slack Web API itself: an httptest server this file scripts response
// by response, so every failure mode the spec names — an uncertain post
// whose response is lost, a failing root edit, a rate limit, an invalid
// token, a lost channel, a multi-minute outage, recovery, replay, and a
// second outage during that replay — is reproduced deterministically
// against a fake clock, with no live workspace and no network.
//
// The L2 (Situation Assessment) boundary is faked the same way every other
// controller test in this repo fakes it, because this file's subject is
// delivery, not assessment.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	notifyslack "github.com/alertint/alertint-agent/internal/notify/slack"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ----------------------------------------------------------------------
// Scripted fake Slack Web API.
// ----------------------------------------------------------------------

// e2eSlackCall is one request the fake provider actually accepted, in
// arrival order. It records exactly the fields the at-least-once and
// ordering assertions need — never a token.
type e2eSlackCall struct {
	Method      string
	ClientMsgID string
	Channel     string
	ThreadTS    string
	Broadcast   bool
	TS          string
	Text        string
	// Accepted is false when the fake decided to reject or drop this call;
	// a dropped call still counts as one the PROVIDER saw, which is the
	// whole point of the uncertain-response case.
	Accepted bool
}

// e2eSlackReply is what the fake does with one request.
type e2eSlackReply struct {
	// Drop makes the handler hijack and close the connection after
	// recording the call: Slack accepted the message, the client never
	// learned the outcome.
	Drop bool
	// ErrorCode returns {"ok":false,"error":code} with HTTP 200, the shape
	// Slack itself uses for application-level rejections.
	ErrorCode string
	// HTTPStatus, when non-zero, returns that status instead of a JSON
	// envelope — 429 for a rate limit, 503 for an outage.
	HTTPStatus int
	// RetryAfterSeconds sets the Retry-After header.
	RetryAfterSeconds int
}

type fakeSlackServer struct {
	t   *testing.T
	mu  sync.Mutex
	srv *httptest.Server

	// script decides each call's reply. Replaced under the lock by the
	// test as it moves the fake provider between health states.
	script func(method string, call *e2eSlackCall) e2eSlackReply
	calls  []e2eSlackCall
	nextTS int
}

func newFakeSlackServer(t *testing.T) *fakeSlackServer {
	t.Helper()
	f := &fakeSlackServer{t: t, script: func(string, *e2eSlackCall) e2eSlackReply { return e2eSlackReply{} }}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlackServer) url() string { return f.srv.URL }

// setScript replaces the fake provider's behavior. Every test moves the
// provider between health states through this one seam.
func (f *fakeSlackServer) setScript(script func(method string, call *e2eSlackCall) e2eSlackReply) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.script = script
}

// alwaysOK is the healthy provider.
func alwaysOK(string, *e2eSlackCall) e2eSlackReply { return e2eSlackReply{} }

// alwaysStatus is a provider that answers every call with one HTTP status —
// 503 models a total outage, 429 a rate limit.
func alwaysStatus(status, retryAfter int) func(string, *e2eSlackCall) e2eSlackReply {
	return func(string, *e2eSlackCall) e2eSlackReply {
		return e2eSlackReply{HTTPStatus: status, RetryAfterSeconds: retryAfter}
	}
}

// alwaysError is a provider that rejects every call with one Slack error
// code (invalid_auth, channel_not_found, ...).
func alwaysError(code string) func(string, *e2eSlackCall) e2eSlackReply {
	return func(string, *e2eSlackCall) e2eSlackReply { return e2eSlackReply{ErrorCode: code} }
}

func (f *fakeSlackServer) handle(w http.ResponseWriter, r *http.Request) {
	method := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	call := e2eSlackCall{Method: method, ClientMsgID: r.Header.Get("X-Alertint-Client-Message-Id")}

	if method != "auth.test" {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err == nil {
			call.Channel, _ = payload["channel"].(string)
			call.ThreadTS, _ = payload["thread_ts"].(string)
			call.Broadcast, _ = payload["reply_broadcast"].(bool)
			call.TS, _ = payload["ts"].(string)
			call.Text, _ = payload["text"].(string)
		}
	}

	f.mu.Lock()
	reply := f.script(method, &call)
	f.nextTS++
	// chat.update answers with the timestamp of the message it edited, not
	// a new one — exactly as Slack does. Getting this wrong would let every
	// root edit silently rewrite the Situation's own durable root
	// coordinates, which is precisely the corruption these tests exist to
	// rule out.
	ts := fmt.Sprintf("1700000%03d.000100", f.nextTS)
	if method == "chat.update" && call.TS != "" {
		ts = call.TS
	}
	call.Accepted = !reply.Drop && reply.ErrorCode == "" && reply.HTTPStatus == 0
	if call.Accepted && method == "chat.postMessage" {
		call.TS = ts
	}
	f.calls = append(f.calls, call)
	f.mu.Unlock()

	switch {
	case reply.Drop:
		// The provider accepted the message; the connection dies before the
		// client can read the answer. This is the "uncertain success" the
		// spec's at-least-once boundary is about.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			f.t.Errorf("httptest ResponseWriter does not support Hijack; cannot model a lost response")
			return
		}
		conn, _, err := hijacker.Hijack()
		if err != nil {
			f.t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
		return
	case reply.HTTPStatus != 0:
		if reply.RetryAfterSeconds > 0 {
			w.Header().Set("Retry-After", fmt.Sprint(reply.RetryAfterSeconds))
		}
		w.WriteHeader(reply.HTTPStatus)
		return
	case reply.ErrorCode != "":
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"ok":false,"error":%q}`, reply.ErrorCode)
		return
	default:
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"ok":true,"channel":%q,"ts":%q}`, e2eChannel, ts)
	}
}

func (f *fakeSlackServer) snapshot() []e2eSlackCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]e2eSlackCall(nil), f.calls...)
}

// accepted returns only the calls the provider actually accepted, i.e. the
// messages that really exist in the channel.
func (f *fakeSlackServer) accepted() []e2eSlackCall {
	var out []e2eSlackCall
	for _, c := range f.snapshot() {
		if c.Accepted && c.Method != "auth.test" {
			out = append(out, c)
		}
	}
	return out
}

// ----------------------------------------------------------------------
// Fixture: real store, real controller, real worker, real deliverer.
// ----------------------------------------------------------------------

const (
	e2eChannel = "C-E2E"
	e2eOwner   = "e2e"
)

type e2eClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *e2eClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *e2eClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type e2eFixture struct {
	t     *testing.T
	ctx   context.Context //nolint:containedctx // test fixture only: always context.Background(), threaded through the helpers rather than repeated on each.
	st    *store.Store
	clock *e2eClock
	slack *fakeSlackServer

	// slackFloor is the operator's notify.slack.min_severity floor every
	// controller cycle runs under. Empty (the default) is "no floor".
	slackFloor model.InterruptionPriority

	worker *situation.NotificationWorker
	l2     *e2eAssessmentClient
}

func newE2EFixture(t *testing.T) *e2eFixture {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "e2e.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	clock := &e2eClock{now: time.Date(2026, 9, 6, 10, 0, 0, 0, time.UTC)}
	fake := newFakeSlackServer(t)
	client := notifyslack.NewClient(notifyslack.Config{
		BotToken: "xoxb-e2e-test-token", BaseURL: fake.url(), TimeoutSeconds: 2,
	})
	deliverer := NewSituationDeliverer(st, client, e2eChannel, clock.Now)

	f := &e2eFixture{t: t, ctx: ctx, st: st, clock: clock, slack: fake, l2: &e2eAssessmentClient{}}
	f.worker = situation.NewNotificationWorker(st, deliverer,
		situation.NotificationWorkerConfig{Owner: e2eOwner + ":notify"}, clock.Now,
		slog.New(slog.DiscardHandler))
	return f
}

// e2eAssessmentClient answers every L2 dispatch with one accepted, schema-
// valid proposal. attention/claimReason steer the derived Operator contract
// exactly the way internal/situation's own replay fixture does.
type e2eAssessmentClient struct {
	mu          sync.Mutex
	attention   model.Attention
	claimReason bool
}

func (c *e2eAssessmentClient) steer(attention model.Attention, claimReason bool) {
	c.mu.Lock()
	c.attention, c.claimReason = attention, claimReason
	c.mu.Unlock()
}

func (c *e2eAssessmentClient) CompleteOnce(_ context.Context, _ string, prompt llm.Prompt, _ []string) (llm.OneShotCompletion, error) {
	c.mu.Lock()
	attention, claimReason := c.attention, c.claimReason
	c.mu.Unlock()

	proposal := model.AssessmentProposal{
		SchemaVersion: model.AssessmentSchemaVersion,
		Persistence:   model.PersistenceSustained,
		Impact:        model.ImpactSuspected,
		Novelty:       model.NoveltyFamiliar,
		Causality:     model.CausalityCorrelated,
		Attention:     model.AttentionObserve,
	}
	if attention != "" {
		proposal.Attention = attention
	}
	if claimReason {
		if cand, ok := e2eFirstNonFloorCandidate(prompt); ok {
			proposal.SufficientReason = &model.SufficientReason{
				Code: cand.Code, CandidateID: cand.ID, Summary: "Elapsed duration is an outlier for this group.",
			}
		}
	}
	raw, err := json.Marshal(proposal)
	if err != nil {
		return llm.OneShotCompletion{}, err
	}
	return llm.OneShotCompletion{
		Completion:     llm.Completion{Raw: raw, Model: "e2e-model"},
		RequestStarted: llm.RequestStartStatusTrue,
	}, nil
}

// e2eFirstNonFloorCandidate reads the eligible Sufficient-reason candidates
// back out of the prompt the controller actually rendered — the only way a
// proposal can name a candidate that validation will accept.
func e2eFirstNonFloorCandidate(prompt llm.Prompt) (model.ReasonCandidate, bool) {
	const marker = "Situation snapshot:\n"
	idx := strings.Index(prompt.Prefix, marker)
	if idx < 0 {
		return model.ReasonCandidate{}, false
	}
	var dto struct {
		EligibleReasons []model.ReasonCandidate `json:"eligible_reasons"`
	}
	if err := json.NewDecoder(strings.NewReader(prompt.Prefix[idx+len(marker):])).Decode(&dto); err != nil {
		return model.ReasonCandidate{}, false
	}
	for _, c := range dto.EligibleReasons {
		if !c.DeterministicFloor {
			return c, true
		}
	}
	return model.ReasonCandidate{}, false
}

// seed creates one Situation for groupKey through the real Incident +
// situation-input round trip, then runs one controller cycle so it has a
// first authoritative Transition, an Episode summary, and its publication
// intents. Returns the Situation ID.
func (f *e2eFixture) seed(groupKey string) string {
	f.t.Helper()
	seedControllerRuntimeSituation(f.t, f.st, groupKey, f.clock.Now())
	// Resolve by INCIDENT, not by group key: a group may already carry
	// several terminal Situations (seedPriorTerminalLineage), and
	// seedControllerRuntimeSituation's own group-key lookup would then
	// return an arbitrary one of them.
	sitID := f.situationIDForIncident("inc-" + groupKey)
	f.controllerCycle()
	return sitID
}

// controllerCycle drains every due Situation through the real controller
// worker at the current clock.
func (f *e2eFixture) controllerCycle() int {
	f.t.Helper()
	f.clock.advance(time.Minute)
	cw := situation.NewControllerWorker(f.st, f.st, f.l2, situation.ControllerConfig{SlackFloor: f.slackFloor},
		situation.ControllerWorkerConfig{Owner: e2eOwner + ":controller", Now: f.clock.Now},
		f.clock.Now, audit.New(f.st.DB()), slog.New(slog.DiscardHandler))
	n, err := cw.Drain(f.ctx)
	if err != nil {
		f.t.Fatalf("controller drain: %v", err)
	}
	return n
}

// deliverRound runs exactly one real notification-worker round.
func (f *e2eFixture) deliverRound() int {
	f.t.Helper()
	n, err := f.worker.RunOnce(f.ctx)
	if err != nil {
		f.t.Fatalf("notification worker round: %v", err)
	}
	return n
}

// deliverUntilQuiet runs delivery rounds, advancing the clock past each
// retry backoff, until a round handles nothing.
// It requires TWO consecutive empty rounds with a clock advance between
// them: one empty round only proves nothing is claimable at this instant,
// which is also exactly what a pending retry backoff looks like.
func (f *e2eFixture) deliverUntilQuiet(maxRounds int) {
	f.t.Helper()
	empty := 0
	for i := 0; i < maxRounds; i++ {
		if f.deliverRound() == 0 {
			empty++
			if empty >= 2 {
				return
			}
		} else {
			empty = 0
		}
		f.clock.advance(6 * time.Minute) // past the 5m retry ceiling
	}
	f.t.Fatalf("delivery did not reach quiescence within %d rounds: %s", maxRounds, f.intentSummary())
}

// ----------------------------------------------------------------------
// Durable-state readers.
// ----------------------------------------------------------------------

type e2eIntent struct {
	ID              string
	Class           string
	Status          string
	ClientMessageID string
	AttemptCount    int
	ErrorClass      string
	RetryAt         string
	DeliveredAs     string
	MessageTS       string
	Sequence        int
}

func (f *e2eFixture) intents() []e2eIntent {
	f.t.Helper()
	rows, err := f.st.DB().QueryContext(f.ctx, `
		SELECT i.id, i.effect_class, i.status, i.client_message_id, i.attempt_count,
		       COALESCE(i.last_error_class,''), COALESCE(i.retry_at,''),
		       COALESCE(i.delivered_as,''), COALESCE(i.message_ts,''),
		       COALESCE(t.sequence, 0)
		  FROM notification_intents i
		  LEFT JOIN situation_transitions t ON t.id = i.transition_id
		 ORDER BY i.created_at ASC, COALESCE(t.sequence,0) ASC, i.effect_class ASC`)
	if err != nil {
		f.t.Fatalf("read intents: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []e2eIntent
	for rows.Next() {
		var i e2eIntent
		if err := rows.Scan(&i.ID, &i.Class, &i.Status, &i.ClientMessageID, &i.AttemptCount,
			&i.ErrorClass, &i.RetryAt, &i.DeliveredAs, &i.MessageTS, &i.Sequence); err != nil {
			f.t.Fatalf("scan intent: %v", err)
		}
		out = append(out, i)
	}
	if err := rows.Err(); err != nil {
		f.t.Fatalf("iterate intents: %v", err)
	}
	return out
}

func (f *e2eFixture) intentSummary() string {
	var b strings.Builder
	for _, i := range f.intents() {
		fmt.Fprintf(&b, "\n  %s status=%s attempts=%d err=%s delivered_as=%s seq=%d",
			i.Class, i.Status, i.AttemptCount, i.ErrorClass, i.DeliveredAs, i.Sequence)
	}
	return b.String()
}

func (f *e2eFixture) intentsOfClass(class string) []e2eIntent {
	var out []e2eIntent
	for _, i := range f.intents() {
		if i.Class == class {
			out = append(out, i)
		}
	}
	return out
}

func (f *e2eFixture) scalarInt(query string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.st.DB().QueryRowContext(f.ctx, query, args...).Scan(&n); err != nil {
		f.t.Fatalf("query %q: %v", query, err)
	}
	return n
}

func (f *e2eFixture) rootCoordinates(situationID string) (string, string) {
	f.t.Helper()
	var channel, ts *string
	if err := f.st.DB().QueryRowContext(f.ctx,
		`SELECT slack_channel, slack_root_ts FROM situations WHERE id = ?`, situationID).Scan(&channel, &ts); err != nil {
		f.t.Fatalf("read root coordinates: %v", err)
	}
	if channel == nil || ts == nil {
		return "", ""
	}
	return *channel, *ts
}

// ----------------------------------------------------------------------
// 1. Uncertain success: the response is lost after Slack accepted the post.
// ----------------------------------------------------------------------

func TestSituationSlackE2EUncertainPostReusesClientIdentityAndAcceptsADuplicate(t *testing.T) {
	f := newE2EFixture(t)

	// The provider accepts the first post and then loses the connection, so
	// the client can never learn the outcome. Every later call succeeds.
	var dropped bool
	f.slack.setScript(func(method string, _ *e2eSlackCall) e2eSlackReply {
		if method == "chat.postMessage" && !dropped {
			dropped = true
			return e2eSlackReply{Drop: true}
		}
		return e2eSlackReply{}
	})

	sitID := f.seed("group=e2e-uncertain")
	f.deliverUntilQuiet(12)

	roots := f.intentsOfClass("root_sync")
	if len(roots) != 1 {
		t.Fatalf("root_sync intents = %d, want exactly 1: an uncertain response must never create a second local intent%s", len(roots), f.intentSummary())
	}
	if roots[0].Status != "delivered" {
		t.Fatalf("root_sync status = %s, want delivered%s", roots[0].Status, f.intentSummary())
	}

	// The provider saw the root post TWICE, with the SAME client message id
	// both times — the at-least-once external boundary ADR-0049 makes
	// explicit, with a stable retry identity a deduplicating provider could
	// use.
	var rootPosts []e2eSlackCall
	for _, c := range f.slack.snapshot() {
		if c.Method == "chat.postMessage" && c.ThreadTS == "" {
			rootPosts = append(rootPosts, c)
		}
	}
	if len(rootPosts) != 2 {
		t.Fatalf("root posts reaching the provider = %d, want 2 (one lost response, one retry)", len(rootPosts))
	}
	if rootPosts[0].ClientMsgID == "" || rootPosts[0].ClientMsgID != rootPosts[1].ClientMsgID {
		t.Fatalf("client message ids = %q and %q, want one identical non-empty id across the retry",
			rootPosts[0].ClientMsgID, rootPosts[1].ClientMsgID)
	}
	if rootPosts[1].ClientMsgID != roots[0].ClientMessageID {
		t.Fatalf("wire client message id %q != durable intent client_message_id %q",
			rootPosts[1].ClientMsgID, roots[0].ClientMessageID)
	}

	// The authoritative coordinates are the ones the SECOND (acknowledged)
	// call returned; the lost first post never corrupted them.
	channel, ts := f.rootCoordinates(sitID)
	if channel != e2eChannel || ts != roots[0].MessageTS {
		t.Fatalf("root coordinates = (%q,%q), want (%q,%q)", channel, ts, e2eChannel, roots[0].MessageTS)
	}
}

// ----------------------------------------------------------------------
// 2. A failing root edit, a rate limit, and an hour of outage all retry
//    indefinitely — a valid effect never exhausts.
// ----------------------------------------------------------------------

func TestSituationSlackE2ERetriesIndefinitelyAndHonorsRetryAfter(t *testing.T) {
	f := newE2EFixture(t)
	f.slack.setScript(alwaysOK)
	sitID := f.seed("group=e2e-retry")
	f.deliverUntilQuiet(12)
	if _, ts := f.rootCoordinates(sitID); ts == "" {
		t.Fatal("the first root never published; the rest of this test has no root to edit")
	}

	// Make the next controller cycle material, so it produces a root EDIT
	// (chat.update against the published coordinates) plus a journal entry.
	f.l2.steer(model.AttentionInvestigate, false)
	f.clock.advance(20 * time.Minute)
	if n := f.controllerCycle(); n == 0 {
		t.Fatal("no controller work was due; the scenario needs a second material cycle")
	}

	// Slack is rate limiting with an explicit Retry-After.
	f.slack.setScript(alwaysStatus(http.StatusTooManyRequests, 45))
	f.deliverRound()

	pending := f.pendingBesidesDelivered()
	if len(pending) == 0 {
		t.Fatalf("nothing is pending after a rate limit; a rate-limited effect must stay claimable%s", f.intentSummary())
	}
	rateLimited := 0
	for _, i := range pending {
		if i.Status != "pending" {
			t.Fatalf("%s intent status = %s after a rate limit, want pending%s", i.Class, i.Status, f.intentSummary())
		}
		if i.ErrorClass != "ratelimited" {
			// A dependent journal entry that was never claimable this round
			// (its root is still owed) has nothing to honor yet — that is
			// the ordering rule working, not a missing backoff.
			continue
		}
		rateLimited++
		if i.RetryAt == "" {
			t.Fatalf("%s intent has no retry_at after a rate limit%s", i.Class, f.intentSummary())
		}
		retryAt, err := time.Parse(time.RFC3339Nano, i.RetryAt)
		if err != nil {
			t.Fatalf("parse retry_at %q: %v", i.RetryAt, err)
		}
		if earliest := f.clock.Now().Add(45 * time.Second); retryAt.Before(earliest) {
			t.Fatalf("%s retry_at = %s, want at or after the honored Retry-After %s", i.Class, retryAt, earliest)
		}
	}
	if rateLimited == 0 {
		t.Fatalf("no intent recorded the rate limit%s", f.intentSummary())
	}

	// A full hour of hard outage. Nothing may ever fail or block.
	f.slack.setScript(alwaysStatus(http.StatusServiceUnavailable, 0))
	for elapsed := time.Duration(0); elapsed < time.Hour; elapsed += 5 * time.Minute {
		f.deliverRound()
		f.clock.advance(5 * time.Minute)
	}
	for _, i := range f.intents() {
		if i.Status == "failed" || i.Status == "blocked_configuration" {
			t.Fatalf("%s intent reached %s after an hour of outage; a valid effect must retry indefinitely%s",
				i.Class, i.Status, f.intentSummary())
		}
	}
	attempts := 0
	for _, i := range f.intents() {
		attempts += i.AttemptCount
	}
	if attempts == 0 {
		t.Fatal("no delivery attempt was ever recorded during the outage")
	}

	// Slack comes back: everything converges with no operator action.
	f.slack.setScript(alwaysOK)
	f.deliverUntilQuiet(20)
	for _, i := range f.intents() {
		if i.Status != "delivered" && i.Status != "superseded" && i.Status != "withheld_by_operator_slack_floor" {
			t.Fatalf("%s intent status = %s after recovery, want delivered/superseded/withheld%s", i.Class, i.Status, f.intentSummary())
		}
	}
}

// pendingBesidesDelivered returns every intent not already delivered,
// superseded, or withheld — i.e. the durable work still owed to Slack.
func (f *e2eFixture) pendingBesidesDelivered() []e2eIntent {
	var out []e2eIntent
	for _, i := range f.intents() {
		switch i.Status {
		case "delivered", "superseded", "withheld_by_operator_slack_floor":
		default:
			out = append(out, i)
		}
	}
	return out
}

// ----------------------------------------------------------------------
// 3. Definite configuration rejections block rather than exhaust.
// ----------------------------------------------------------------------

func TestSituationSlackE2EConfigurationRejectionsBlockAndNeverDiscard(t *testing.T) {
	for _, tc := range []struct {
		name string
		code string
	}{
		{"invalid_token", "invalid_auth"},
		{"channel_loss", "channel_not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newE2EFixture(t)
			f.slack.setScript(alwaysError(tc.code))
			f.seed("group=e2e-" + tc.name)

			for i := 0; i < 4; i++ {
				f.deliverRound()
				f.clock.advance(6 * time.Minute)
			}

			blocked := f.scalarInt(`SELECT COUNT(*) FROM notification_intents WHERE status = 'blocked_configuration'`)
			if blocked == 0 {
				t.Fatalf("no intent reached blocked_configuration after %q%s", tc.code, f.intentSummary())
			}
			if failed := f.scalarInt(`SELECT COUNT(*) FROM notification_intents WHERE status = 'failed'`); failed != 0 {
				t.Fatalf("%d intent(s) reached failed; a configuration rejection must block, never exhaust%s", failed, f.intentSummary())
			}
			// The durable obligation survives: correcting configuration
			// returns the blocked work to pending and it delivers.
			f.slack.setScript(alwaysOK)
			if _, err := f.worker.ReactivateConfiguration(f.ctx); err != nil {
				t.Fatalf("reactivate configuration: %v", err)
			}
			f.deliverUntilQuiet(12)
			if remaining := len(f.pendingBesidesDelivered()); remaining != 0 {
				t.Fatalf("%d intent(s) still owed after corrected configuration%s", remaining, f.intentSummary())
			}
		})
	}
}

// ----------------------------------------------------------------------
// 4. A six-minute outage opens one gap generation; recovery emits exactly
//    one System notice ahead of a complete, ordered replay; a second
//    outage during that replay opens a second generation.
// ----------------------------------------------------------------------

func TestSituationSlackE2EOutageOpensGapRecoversAndReplaysInOrder(t *testing.T) {
	f := newE2EFixture(t)
	f.slack.setScript(alwaysStatus(http.StatusServiceUnavailable, 0))

	// Two Situations accumulate distinct journal entries while Slack is
	// unavailable, so the replay has real per-episode history to order.
	a := f.seed("group=e2e-gap-a")
	b := f.seed("group=e2e-gap-b")
	f.deliverRound()

	// Hold the outage past the five-minute threshold.
	for elapsed := time.Duration(0); elapsed < 6*time.Minute; elapsed += time.Minute {
		f.clock.advance(time.Minute)
		f.deliverRound()
	}
	f.l2.steer(model.AttentionInvestigate, false)
	f.clock.advance(20 * time.Minute)
	f.controllerCycle()
	f.deliverRound()

	if gaps := f.scalarInt(`SELECT COUNT(*) FROM slack_delivery_gaps`); gaps != 1 {
		t.Fatalf("delivery gap generations = %d, want exactly 1 after one continuous outage%s", gaps, f.intentSummary())
	}
	if open := f.scalarInt(`SELECT COUNT(*) FROM slack_delivery_state WHERE open_gap_generation IS NOT NULL`); open != 1 {
		t.Fatal("the open gap generation is not recorded on the installation delivery state")
	}
	if notices := f.scalarInt(`SELECT COUNT(*) FROM notification_intents WHERE effect_class = 'installation_gap_recovery'`); notices != 0 {
		t.Fatalf("%d recovery notice(s) exist while the gap is still open; the notice is created on recovery only", notices)
	}

	// Slack comes back. The next probe recovers the generation and the
	// bounded System notice becomes claimable ahead of the backlog.
	f.slack.setScript(alwaysOK)
	f.clock.advance(6 * time.Minute)
	f.deliverUntilQuiet(40)

	notices := f.intentsOfClass("installation_gap_recovery")
	if len(notices) != 1 {
		t.Fatalf("installation_gap_recovery intents = %d, want exactly one bounded notice per generation%s", len(notices), f.intentSummary())
	}
	if notices[0].Status != "delivered" {
		t.Fatalf("the recovery notice status = %s, want delivered", notices[0].Status)
	}

	calls := f.slack.accepted()
	noticeIdx := -1
	for i, c := range calls {
		if strings.Contains(c.Text, "AlertINT's Slack delivery was interrupted") {
			noticeIdx = i
			break
		}
	}
	if noticeIdx < 0 {
		t.Fatalf("no System recovery notice reached the channel; accepted calls = %d", len(calls))
	}
	if noticeIdx != 0 {
		t.Fatalf("the System recovery notice is accepted call #%d, want the first message of the replay", noticeIdx+1)
	}

	// Every affected Situation's root published, and its journal entries
	// replayed under that root in Transition-sequence order.
	for _, sit := range []string{a, b} {
		channel, ts := f.rootCoordinates(sit)
		if channel == "" || ts == "" {
			t.Fatalf("situation %s has no published root after replay", sit)
		}
		assertJournalRepliesInSequenceOrder(t, f, sit, ts)
	}

	// A second outage during ongoing delivery opens a SECOND generation —
	// generations are per continuous outage, never reused.
	f.l2.steer(model.AttentionObserve, false)
	f.slack.setScript(alwaysStatus(http.StatusServiceUnavailable, 0))
	f.clock.advance(20 * time.Minute)
	f.controllerCycle()
	for elapsed := time.Duration(0); elapsed < 7*time.Minute; elapsed += time.Minute {
		f.clock.advance(time.Minute)
		f.deliverRound()
	}
	if gaps := f.scalarInt(`SELECT COUNT(*) FROM slack_delivery_gaps`); gaps != 2 {
		t.Fatalf("delivery gap generations = %d after a second outage, want 2%s", gaps, f.intentSummary())
	}

	f.slack.setScript(alwaysOK)
	f.clock.advance(6 * time.Minute)
	f.deliverUntilQuiet(40)
	if notices := f.scalarInt(
		`SELECT COUNT(*) FROM notification_intents WHERE effect_class = 'installation_gap_recovery'`); notices != 2 {
		t.Fatalf("recovery notices = %d after two generations, want exactly one per generation%s", notices, f.intentSummary())
	}
}

// assertJournalRepliesInSequenceOrder proves every delivered journal entry
// for situationID reached the provider under that Situation's own root, in
// Transition-sequence order: a later entry can never pass an earlier one.
func assertJournalRepliesInSequenceOrder(t *testing.T, f *e2eFixture, situationID, rootTS string) {
	t.Helper()
	rows, err := f.st.DB().QueryContext(f.ctx, `
		SELECT t.sequence, i.message_ts
		  FROM notification_intents i
		  JOIN situation_transitions t ON t.id = i.transition_id
		 WHERE i.situation_id = ? AND i.status = 'delivered'
		   AND i.effect_class IN ('thread_append','broadcast_handoff')
		 ORDER BY t.sequence ASC`, situationID)
	if err != nil {
		t.Fatalf("read delivered journal intents: %v", err)
	}
	defer func() { _ = rows.Close() }()
	type entry struct {
		sequence int
		ts       string
	}
	var entries []entry
	for rows.Next() {
		var e entry
		if err := rows.Scan(&e.sequence, &e.ts); err != nil {
			t.Fatalf("scan journal intent: %v", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate journal intents: %v", err)
	}
	if len(entries) == 0 {
		return
	}

	arrival := map[string]int{}
	for i, c := range f.slack.accepted() {
		if c.Method == "chat.postMessage" && c.ThreadTS == rootTS {
			arrival[c.TS] = i
		}
	}
	last := -1
	for _, e := range entries {
		idx, ok := arrival[e.ts]
		if !ok {
			t.Fatalf("journal entry for transition #%d (ts %s) never arrived under root %s", e.sequence, e.ts, rootTS)
		}
		if idx < last {
			t.Fatalf("journal entry for transition #%d arrived before an earlier entry; replay must preserve Transition-sequence order", e.sequence)
		}
		last = idx
	}
}

// ----------------------------------------------------------------------
// 5. A publication that was only ever queued, followed by terminal state,
//    posts ONE latest-informative terminal root plus its ordered journal —
//    outside any recorded gap.
// ----------------------------------------------------------------------

func TestSituationSlackE2EQueuedPublicationTerminalBeforeFirstSlackCall(t *testing.T) {
	f := newE2EFixture(t)
	// The provider is unreachable only long enough to keep the first root
	// queued; it never fails long enough to open a gap generation.
	f.slack.setScript(alwaysStatus(http.StatusServiceUnavailable, 0))

	sitID := f.seed("group=e2e-queued-terminal")
	f.deliverRound()
	if _, ts := f.rootCoordinates(sitID); ts != "" {
		t.Fatal("the root published despite an unreachable provider; this scenario needs it queued")
	}

	// Terminalize the Situation before any Slack call succeeded.
	f.terminalize(sitID)

	f.slack.setScript(alwaysOK)
	f.clock.advance(time.Minute)
	f.deliverUntilQuiet(40)

	if gaps := f.scalarInt(`SELECT COUNT(*) FROM slack_delivery_gaps`); gaps != 0 {
		t.Fatalf("delivery gap generations = %d, want 0: a delay under five minutes is an ordinary delay, not a gap", gaps)
	}

	channel, rootTS := f.rootCoordinates(sitID)
	if channel != e2eChannel || rootTS == "" {
		t.Fatalf("root coordinates = (%q,%q); a queued publication must still publish its latest informative root", channel, rootTS)
	}

	// Exactly one root message exists in the channel — the terminal one —
	// and it is the LATEST informative projection, not the original
	// pre-terminal card replayed as though current.
	var rootPosts, edits int
	for _, c := range f.slack.accepted() {
		switch {
		case c.Method == "chat.postMessage" && c.ThreadTS == "":
			rootPosts++
		case c.Method == "chat.update":
			edits++
		}
	}
	if rootPosts != 1 {
		t.Fatalf("root posts = %d, want exactly 1: a delayed publication posts one root, never two", rootPosts)
	}
	liveRoots := 0
	for _, i := range f.intentsOfClass("root_sync") {
		if i.Status == "delivered" {
			liveRoots++
		}
	}
	if liveRoots == 0 {
		t.Fatalf("no root_sync intent delivered%s", f.intentSummary())
	}
	assertJournalRepliesInSequenceOrder(t, f, sitID, rootTS)

	terminal := f.scalarInt(
		`SELECT COUNT(*) FROM situation_transitions WHERE situation_id = ? AND lifecycle IN ('recovered','closed_unknown')`, sitID)
	if terminal == 0 {
		t.Fatal("the Situation never reached a terminal Transition")
	}
}

// terminalize drives situationID to closed_unknown through the real
// controller: its symptoms stop reporting and its source-aware
// lifecycle-observation deadline then expires. Nothing is hand-written.
func (f *e2eFixture) terminalize(situationID string) {
	f.t.Helper()
	// The seeded Incident carries no firing delivery of its own, so the
	// only thing standing between it and closed_unknown is the
	// observation deadline. The long duration class's deadline is 7 days.
	f.clock.advance(8 * 24 * time.Hour)
	if _, err := f.st.DB().ExecContext(f.ctx,
		`UPDATE situations SET next_assessment_at = ? WHERE id = ?`,
		f.clock.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano), situationID); err != nil {
		f.t.Fatalf("make situation due: %v", err)
	}
	if n := f.controllerCycle(); n == 0 {
		f.t.Fatal("no controller work was due; the Situation cannot terminalize")
	}
	var lifecycle string
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT lifecycle FROM situations WHERE id = ?`, situationID).Scan(&lifecycle); err != nil {
		f.t.Fatalf("read lifecycle: %v", err)
	}
	if lifecycle != "closed_unknown" && lifecycle != "recovered" {
		f.t.Fatalf("situation lifecycle = %q, want a terminal one", lifecycle)
	}
}

// ----------------------------------------------------------------------
// 6. A stale handoff is never broadcast as current: its immutable history
//    still delivers, demoted to a delayed non-current thread entry.
// ----------------------------------------------------------------------

func TestSituationSlackE2EStaleHandoffIsDemotedToADelayedThreadEntry(t *testing.T) {
	f := newE2EFixture(t)
	f.slack.setScript(alwaysOK)
	// Five completed Situations for this group first: duration_outlier —
	// the only non-floor Sufficient-reason candidate this build can reach,
	// and therefore the only path to an operator handoff — needs at least
	// five comparable prior durations.
	f.seedPriorTerminalLineage("group=e2e-stale-handoff", 5)
	sitID := f.seed("group=e2e-stale-handoff")
	f.deliverUntilQuiet(12)

	// Hand off to the operator: this creates the one broadcast_handoff
	// effect the spec allows.
	f.l2.steer(model.AttentionInvestigate, true)
	f.clock.advance(3 * time.Hour)
	f.controllerCycle()

	if handoffs := f.intentsOfClass("broadcast_handoff"); len(handoffs) == 0 {
		t.Fatalf("no broadcast_handoff intent was created; the operator handoff never happened%s", f.intentSummary())
	}

	// Before it can be delivered, the required action stops being current.
	f.l2.steer(model.AttentionObserve, false)
	f.clock.advance(20 * time.Minute)
	f.controllerCycle()

	f.deliverUntilQuiet(20)

	delivered := f.intentsOfClass("broadcast_handoff")
	if len(delivered) == 0 {
		t.Fatal("the broadcast handoff intent disappeared")
	}
	for _, i := range delivered {
		if i.Status != "delivered" {
			t.Fatalf("broadcast_handoff status = %s, want delivered: immutable history is never dropped%s", i.Status, f.intentSummary())
		}
		if i.DeliveredAs != "delayed_thread" {
			t.Fatalf("broadcast_handoff delivered_as = %q, want delayed_thread: a stale handoff must never broadcast as current", i.DeliveredAs)
		}
	}
	_, rootTS := f.rootCoordinates(sitID)
	if rootTS == "" {
		t.Fatal("the Situation has no published root; its demoted history has nothing to hang under")
	}
	for _, c := range f.slack.accepted() {
		if c.Broadcast {
			t.Fatal("a reply reached the main channel as a broadcast after its requested action stopped being current")
		}
		if c.Method == "chat.postMessage" && c.ThreadTS != "" && c.ThreadTS != rootTS {
			t.Fatalf("a journal reply was threaded under %q, not this Situation's own root %q", c.ThreadTS, rootTS)
		}
	}
}

// seedPriorTerminalLineage records n completed Situations for groupKey so
// the live one's duration_outlier candidate — this build's only reachable
// non-floor Sufficient reason — becomes admissible. They are written
// directly because they are HISTORY, not the subject under test: what this
// file exercises is delivery, and internal/situation's own
// history_replay_test.go already drives the identical lineage end to end
// through real HTTP ingestion.
func (f *e2eFixture) seedPriorTerminalLineage(groupKey string, n int) {
	f.t.Helper()
	for i := 0; i < n; i++ {
		// One at a time: migration 0014 allows exactly one nonterminal
		// Situation per group, so each prior is created through the same
		// production Incident + situation-input path every other Situation
		// in this file uses, then closed before the next one starts.
		f.closeSituation(f.seedRawSituation(groupKey, fmt.Sprintf("prior-%d", i)))
	}
}

// seedRawSituation creates one additional Situation for groupKey through
// the real Incident + situation-input round trip, distinguished by suffix.
func (f *e2eFixture) seedRawSituation(groupKey, suffix string) string {
	f.t.Helper()
	incID := "inc-" + groupKey + "-" + suffix
	now := f.clock.Now()
	if err := f.st.InsertIncident(f.ctx, store.Incident{
		ID: incID, GroupKey: groupKey, FirstAlertAt: now, LastAlertAt: now, ReadyAt: now.Add(time.Minute),
	}); err != nil {
		f.t.Fatalf("insert prior incident: %v", err)
	}
	// Close its collecting window immediately: incidents carry a partial
	// UNIQUE index on group_key while collecting, so the next prior cannot
	// open until this one is ready.
	if err := f.st.MarkIncidentReady(f.ctx, incID); err != nil {
		f.t.Fatalf("mark prior incident ready: %v", err)
	}
	inputID := "input-" + groupKey + "-" + suffix
	if _, err := f.st.DB().ExecContext(f.ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, 'incident_created', ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incID, groupKey, now.UTC().Format(time.RFC3339Nano)); err != nil {
		f.t.Fatalf("insert prior situation input: %v", err)
	}
	claims, err := f.st.ClaimSituationInputs(f.ctx, "e2e-prior:"+suffix, now, time.Minute, 1)
	if err != nil || len(claims) != 1 {
		f.t.Fatalf("claim prior situation input: claims=%d err=%v", len(claims), err)
	}
	if err := f.st.ApplySituationInput(f.ctx, claims[0]); err != nil {
		f.t.Fatalf("apply prior situation input: %v", err)
	}
	return f.situationIDForIncident(incID)
}

// closeSituation closes one Situation as closed_unknown — the one terminal
// lifecycle reachable directly from active, so migration 0014's own
// transition trigger accepts it. This is fixture bookkeeping for HISTORY
// rows only: the Situation under test in every assertion below reaches
// every lifecycle it visits through the real controller, and
// internal/situation/history_replay_test.go drives the same lineage end to
// end through real HTTP ingestion.
func (f *e2eFixture) closeSituation(situationID string) {
	f.t.Helper()
	if _, err := f.st.DB().ExecContext(f.ctx,
		`UPDATE situations SET lifecycle = 'closed_unknown', terminal_at = ?,
		        terminal_reason = 'observation_deadline' WHERE id = ?`,
		f.clock.Now().Add(2*time.Minute).UTC().Format(time.RFC3339Nano), situationID); err != nil {
		f.t.Fatalf("close situation: %v", err)
	}
}

func (f *e2eFixture) situationIDForIncident(incidentID string) string {
	f.t.Helper()
	var id string
	if err := f.st.DB().QueryRowContext(f.ctx,
		`SELECT situation_id FROM situation_incidents WHERE incident_id = ?`, incidentID).Scan(&id); err != nil {
		f.t.Fatalf("find situation for incident %s: %v", incidentID, err)
	}
	return id
}

// ----------------------------------------------------------------------
// 7. A failing root EDIT never corrupts the published root coordinates and
//    never blocks the Situation's later history from delivering once the
//    edit finally lands.
// ----------------------------------------------------------------------

func TestSituationSlackE2EFailingRootUpdateKeepsCoordinatesAndRecovers(t *testing.T) {
	f := newE2EFixture(t)
	f.slack.setScript(alwaysOK)
	sitID := f.seed("group=e2e-root-update")
	f.deliverUntilQuiet(12)

	_, publishedTS := f.rootCoordinates(sitID)
	if publishedTS == "" {
		t.Fatal("the first root never published")
	}

	// Posts keep working; only the root EDIT fails, with a retryable
	// Slack-side error.
	var updateFailures int
	f.slack.setScript(func(method string, _ *e2eSlackCall) e2eSlackReply {
		if method == "chat.update" && updateFailures < 3 {
			updateFailures++
			return e2eSlackReply{ErrorCode: "internal_error"}
		}
		return e2eSlackReply{}
	})

	f.l2.steer(model.AttentionInvestigate, false)
	f.clock.advance(20 * time.Minute)
	if n := f.controllerCycle(); n == 0 {
		t.Fatal("no controller work was due; the scenario needs a second material cycle")
	}

	f.deliverRound()
	if _, ts := f.rootCoordinates(sitID); ts != publishedTS {
		t.Fatalf("root coordinates moved to %q while the edit was failing, want the original %q", ts, publishedTS)
	}
	for _, i := range f.intentsOfClass("root_sync") {
		if i.Status == "failed" || i.Status == "blocked_configuration" {
			t.Fatalf("a retryable root edit reached %s%s", i.Status, f.intentSummary())
		}
	}

	f.deliverUntilQuiet(20)
	if updateFailures != 3 {
		t.Fatalf("the fake provider rejected %d edits, want 3 — the scenario never exercised the failure", updateFailures)
	}
	if _, ts := f.rootCoordinates(sitID); ts != publishedTS {
		t.Fatalf("root coordinates = %q after recovery, want the original %q: an edit never re-anchors a root", ts, publishedTS)
	}
	if remaining := len(f.pendingBesidesDelivered()); remaining != 0 {
		t.Fatalf("%d effect(s) still owed after the edit recovered%s", remaining, f.intentSummary())
	}
	assertJournalRepliesInSequenceOrder(t, f, sitID, publishedTS)
}

// ----------------------------------------------------------------------
// 8. A root the operator's Slack floor withholds never strands the earlier
//    root projection it replaces — and a purely local data-state mismatch
//    is never reported as a Slack dependency failure.
// ----------------------------------------------------------------------

func TestSituationSlackE2EBelowFloorRootNeverStrandsTheQueuedRootItReplaces(t *testing.T) {
	f := newE2EFixture(t)
	f.slackFloor = model.InterruptionMedium
	f.slack.setScript(alwaysOK)

	// The Situation opens below the operator's floor, so its first root is a
	// durably withheld decision and nothing is on screen.
	sitID := f.seed("group=e2e-floor-strand")

	// It then escalates above the floor and earns publication. Nothing is
	// delivered yet: that root projection is committed and merely queued.
	f.l2.steer(model.AttentionInvestigate, false)
	f.clock.advance(20 * time.Minute)
	if n := f.controllerCycle(); n == 0 {
		t.Fatal("no controller work was due; the scenario needs an above-floor escalation")
	}
	queued := ""
	for _, i := range f.intentsOfClass("root_sync") {
		if i.Status == "pending" {
			if queued != "" {
				t.Fatalf("two root projections are pending at once%s", f.intentSummary())
			}
			queued = i.ID
		}
	}
	if queued == "" {
		t.Fatalf("the escalation above the floor earned no pending root projection%s", f.intentSummary())
	}

	// Cycle two calms the Situation below the floor while that earned root
	// is still queued.
	f.l2.steer(model.AttentionObserve, false)
	f.clock.advance(20 * time.Minute)
	if n := f.controllerCycle(); n == 0 {
		t.Fatal("no controller work was due; the scenario needs a second material cycle")
	}
	for _, i := range f.intentsOfClass("root_sync") {
		if i.ID == queued && i.Status == "pending" {
			t.Fatalf("the earlier root projection is still pending after a newer one replaced it%s", f.intentSummary())
		}
	}

	f.deliverUntilQuiet(30)

	// The publication the floor already permitted is not erased by a later
	// below-floor commit: spec.md's ordinary-delay rule publishes the
	// LATEST informative root rather than dropping an earned, queued one.
	if _, ts := f.rootCoordinates(sitID); ts == "" {
		t.Fatalf("the Situation never published despite earning publication before the floor engaged%s", f.intentSummary())
	}
	if remaining := len(f.pendingBesidesDelivered()); remaining != 0 {
		t.Fatalf("%d effect(s) still owed once the queue drained%s", remaining, f.intentSummary())
	}

	// A local data-state mismatch is not a Slack outcome: nothing here may
	// register as a Slack dependency failure or open a Delivery gap.
	if gaps := f.scalarInt(`SELECT COUNT(*) FROM slack_delivery_gaps`); gaps != 0 {
		t.Fatalf("delivery gap generations = %d, want 0: Slack answered every call in this scenario", gaps)
	}
	if failing := f.scalarInt(`SELECT COUNT(*) FROM slack_delivery_state WHERE first_failure_at IS NOT NULL`); failing != 0 {
		t.Fatal("a Slack-dependency failure window opened although Slack never failed")
	}
}
