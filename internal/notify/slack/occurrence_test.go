// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// fakeSlack captures posts/updates by fronting a real slacklib.Client with a
// local httptest.Server: slack-go only serializes Block Kit blocks into the
// outgoing form inside its private BuildRequestContext step, which
// UnsafeApplyMsgOptions (the library's documented test/debug helper) never
// reaches — a real round trip through a stub server is the only way to
// observe the posted "blocks" field from outside the package.
type postCapture struct {
	channel   string
	text      string
	threadTS  string
	broadcast bool
	blocks    string
}

type fakeSlack struct {
	mu        sync.Mutex
	posts     []postCapture
	updates   []string
	updateErr error

	srv    *httptest.Server
	client *slacklib.Client
}

func newFakeSlack(t *testing.T) *fakeSlack {
	t.Helper()
	f := &fakeSlack{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	f.client = slacklib.New("xoxb-test", slacklib.OptionAPIURL(f.srv.URL+"/"))
	return f
}

func (f *fakeSlack) handle(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	f.mu.Lock()
	if strings.HasSuffix(r.URL.Path, "chat.update") {
		if f.updateErr != nil {
			f.mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprint(w, `{"ok":false,"error":"update_failed"}`)
			return
		}
		f.updates = append(f.updates, r.FormValue("text"))
	} else {
		f.posts = append(f.posts, postCapture{
			channel:   r.FormValue("channel"),
			text:      r.FormValue("text"),
			threadTS:  r.FormValue("thread_ts"),
			broadcast: r.FormValue("reply_broadcast") == "true",
			blocks:    r.FormValue("blocks"),
		})
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprint(w, `{"ok":true,"channel":"chan","ts":"ts-1"}`)
}

func (f *fakeSlack) PostMessageContext(ctx context.Context, channelID string, options ...slacklib.MsgOption) (string, string, error) {
	return f.client.PostMessageContext(ctx, channelID, options...)
}

func (f *fakeSlack) postCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.posts) }
func (f *fakeSlack) lastPost() postCapture {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.posts) == 0 {
		return postCapture{}
	}
	return f.posts[len(f.posts)-1]
}

func (f *fakeSlack) UpdateMessageContext(ctx context.Context, channelID, timestamp string, options ...slacklib.MsgOption) (string, string, string, error) {
	ch, ts, txt, err := f.client.UpdateMessageContext(ctx, channelID, timestamp, options...)
	if err != nil {
		return "", "", "", err
	}
	return ch, ts, txt, nil
}

func (f *fakeSlack) updateCount() int { f.mu.Lock(); defer f.mu.Unlock(); return len(f.updates) }
func (f *fakeSlack) lastUpdate() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.updates) == 0 {
		return ""
	}
	return f.updates[len(f.updates)-1]
}

type fakeThreadStore struct {
	missing bool
}

func (f *fakeThreadStore) GetIncidentSlackThread(_ context.Context, _ string) (ts, channel string, err error) {
	if f.missing {
		return "", "", store.ErrNotFound
	}
	return "ts-1", "chan", nil
}
func (f *fakeThreadStore) SetIncidentSlackThread(_ context.Context, _, _, _ string) error { return nil }

type noopTimer struct{}

func (noopTimer) Stop() bool { return true }

// occNotifier builds a Slack notifier wired with the fake client/store and a
// controllable clock + captured trailing-flush timer.
func occNotifier(t *testing.T, client *fakeSlack, ts *fakeThreadStore) (*Notifier, *time.Time, *func()) {
	t.Helper()
	n := NewWithClient(client, "chan", "", "change-gated", ts, nil)
	clockNow := time.Unix(1_000_000, 0).UTC()
	var flush func()
	n.now = func() time.Time { return clockNow }
	n.after = func(_ time.Duration, fn func()) stopper { flush = fn; return noopTimer{} }
	return n, &clockNow, &flush
}

func attach(n *Notifier, count int, at time.Time) error {
	return n.OnOccurrenceAttached(context.Background(), notify.RecurrenceEvent{
		Incident: store.Incident{ID: "inc1", GroupKey: "k", Summary: "DiskFull"},
		Stats:    store.OccurrenceStats{Count: count, LastSeen: at},
	})
}

func TestOccurrence_FirstAttachEditsImmediately(t *testing.T) {
	client := newFakeSlack(t)
	n, now, _ := occNotifier(t, client, &fakeThreadStore{})
	if err := attach(n, 1, *now); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if client.updateCount() != 1 {
		t.Errorf("updates = %d, want 1 (first attach edits immediately)", client.updateCount())
	}
	if !strings.Contains(client.lastUpdate(), "×2") {
		t.Errorf("edit text = %q, want recurred ×2 (count 1 + 1)", client.lastUpdate())
	}
}

// TestOccurrence_ThrottleCoalescesWithTrailingFlush covers AE1's Slack half: a
// burst of attaches yields exactly one immediate edit plus one trailing flush
// carrying the final count.
func TestOccurrence_ThrottleCoalescesWithTrailingFlush(t *testing.T) {
	client := newFakeSlack(t)
	n, now, flush := occNotifier(t, client, &fakeThreadStore{})

	for i := 1; i <= 8; i++ {
		if err := attach(n, i, *now); err != nil {
			t.Fatalf("attach %d: %v", i, err)
		}
	}
	if client.updateCount() != 1 {
		t.Fatalf("immediate edits = %d, want 1 (rest coalesced)", client.updateCount())
	}
	if *flush == nil {
		t.Fatal("no trailing flush armed")
	}

	*now = now.Add(occEditThrottle)
	(*flush)()
	if client.updateCount() != 2 {
		t.Fatalf("edits after flush = %d, want 2", client.updateCount())
	}
	if !strings.Contains(client.lastUpdate(), "×9") {
		t.Errorf("trailing flush text = %q, want the final count ×9 (count 8 + 1)", client.lastUpdate())
	}
}

// TestOccurrence_NoThreadIsNoOp covers AE4: an incident whose card was
// gate-suppressed (no thread row) gets zero Slack calls.
func TestOccurrence_NoThreadIsNoOp(t *testing.T) {
	client := newFakeSlack(t)
	n, now, flush := occNotifier(t, client, &fakeThreadStore{missing: true})
	if err := attach(n, 3, *now); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if client.updateCount() != 0 {
		t.Errorf("updates = %d, want 0 (no card to edit)", client.updateCount())
	}
	if *flush != nil {
		t.Error("a trailing flush was armed for a card-less incident")
	}
}

func TestOccurrence_SecondWindowEditsAgain(t *testing.T) {
	client := newFakeSlack(t)
	n, now, _ := occNotifier(t, client, &fakeThreadStore{})
	if err := attach(n, 1, *now); err != nil {
		t.Fatalf("attach 1: %v", err)
	}
	// Advance past the throttle window: the next attach edits immediately, no flush.
	*now = now.Add(occEditThrottle + time.Second)
	if err := attach(n, 2, *now); err != nil {
		t.Fatalf("attach 2: %v", err)
	}
	if client.updateCount() != 2 {
		t.Errorf("updates = %d, want 2 (each in its own window)", client.updateCount())
	}
}

func TestOccurrence_UpdateErrorNotRetried(t *testing.T) {
	client := newFakeSlack(t)
	client.updateErr = errors.New("slack 500")
	n, now, _ := occNotifier(t, client, &fakeThreadStore{})
	err := attach(n, 1, *now)
	if err == nil {
		t.Fatal("OnOccurrenceAttached returned nil on a Slack error, want the error surfaced")
	}
	// One attempt, no retry loop, no fallback post.
	if posts := client.postCount(); posts != 0 {
		t.Errorf("posts = %d, want 0 (no fallback post on an update error)", posts)
	}
}

func TestOccurrenceEditBlocks_RenderCountAndDrill(t *testing.T) {
	inc := store.Incident{ID: "inc1", GroupKey: "k", Summary: "DiskFull", RootCause: "disk 95%"}
	blocks := occurrenceEditBlocks(inc, 14, time.Date(2026, 7, 8, 2, 15, 0, 0, time.UTC), true)
	js := blocksJSON(t, blocks)
	if !strings.Contains(js, "recurred ×14") {
		t.Errorf("blocks missing recurred ×14:\n%s", js)
	}
	if !strings.Contains(js, "DRILL") {
		t.Errorf("drill occurrence card missing DRILL marker:\n%s", js)
	}
	if !strings.Contains(js, "DiskFull") {
		t.Errorf("occurrence card dropped the finding name:\n%s", js)
	}
}

func TestMilestoneHit_Schedule(t *testing.T) {
	yes := map[int]bool{5: true, 10: true, 25: true, 50: true, 100: true, 200: true, 300: true, 1000: true}
	for _, ep := range []int{1, 2, 3, 4, 5, 6, 9, 10, 11, 24, 25, 26, 49, 50, 51, 99, 100, 101, 150, 200, 250, 300, 1000} {
		want := yes[ep]
		if got := milestoneHit(ep); got != want {
			t.Errorf("milestoneHit(%d) = %v, want %v", ep, got, want)
		}
	}
}

// recurEvent builds a RecurrenceEvent for the slack broadcast tests.
// recurEvent's Incident.FirstAlertAt (5h before at) predates Stats.FirstOccurredAt
// (3h before at) — the incident fired once, then went quiet before recurring —
// so any span computed off the wrong anchor is caught by an exact assertion.
func recurEvent(trigger string, count int, at time.Time) notify.RecurrenceEvent {
	return notify.RecurrenceEvent{
		Incident: store.Incident{ID: "inc12345678", GroupKey: "k", Summary: "DiskFull", RootCause: "disk 95%", FirstAlertAt: at.Add(-5 * time.Hour)},
		Stats:    store.OccurrenceStats{Count: count, FirstOccurredAt: at.Add(-3 * time.Hour), LastSeen: at},
		Trigger:  trigger,
	}
}

func TestRecurrence_SeverityBroadcasts(t *testing.T) {
	client := newFakeSlack(t)
	n, _, _ := occNotifier(t, client, &fakeThreadStore{})
	ev := recurEvent("severity", 4, time.Unix(1_000_000, 0).UTC())
	ev.PriorSeverity, ev.NewSeverity = "warning", "critical"
	if err := n.OnOccurrenceAttached(context.Background(), ev); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if client.updateCount() != 0 {
		t.Errorf("card updates = %d, want 0 (re-judgment Notify writes the card)", client.updateCount())
	}
	if client.postCount() != 1 {
		t.Fatalf("posts = %d, want 1 (one broadcast)", client.postCount())
	}
	p := client.lastPost()
	if !p.broadcast || p.threadTS != "ts-1" {
		t.Errorf("post = {broadcast:%v thread_ts:%q}, want {true ts-1}", p.broadcast, p.threadTS)
	}
	if !strings.Contains(p.blocks, "Escalated") || !strings.Contains(p.blocks, "CRITICAL") || !strings.Contains(p.blocks, "why: severity") {
		t.Errorf("severity broadcast blocks missing rung text:\n%s", p.blocks)
	}
}

// TestRecurrence_SeverityBroadcastNoPriorLabel covers a baseline where every
// current member's severity is off the ladder (empty/unrecognized), so
// memberBaselines never records a prior label: the broadcast must drop the
// "(was ...)" clause instead of rendering a blank prior severity.
func TestRecurrence_SeverityBroadcastNoPriorLabel(t *testing.T) {
	client := newFakeSlack(t)
	n, _, _ := occNotifier(t, client, &fakeThreadStore{})
	ev := recurEvent("severity", 1, time.Unix(1_000_000, 0).UTC())
	ev.PriorSeverity, ev.NewSeverity = "", "critical"
	if err := n.OnOccurrenceAttached(context.Background(), ev); err != nil {
		t.Fatalf("attach: %v", err)
	}
	p := client.lastPost()
	if strings.Contains(p.blocks, "(was )") {
		t.Errorf("severity broadcast rendered a blank prior severity:\n%s", p.blocks)
	}
	if !strings.Contains(p.blocks, "Escalated") || !strings.Contains(p.blocks, "CRITICAL") {
		t.Errorf("severity broadcast missing escalation text:\n%s", p.blocks)
	}
}

func TestRecurrence_NewAlertnameBroadcasts(t *testing.T) {
	client := newFakeSlack(t)
	n, _, _ := occNotifier(t, client, &fakeThreadStore{})
	ev := recurEvent("new_alertname", 6, time.Unix(1_000_000, 0).UTC())
	ev.NewAlertname = "HighErrorRate"
	if err := n.OnOccurrenceAttached(context.Background(), ev); err != nil {
		t.Fatalf("attach: %v", err)
	}
	p := client.lastPost()
	if client.postCount() != 1 || !p.broadcast {
		t.Fatalf("want one broadcast, got posts=%d broadcast=%v", client.postCount(), p.broadcast)
	}
	if !strings.Contains(p.blocks, "New symptom") || !strings.Contains(p.blocks, "HighErrorRate") || !strings.Contains(p.blocks, "why: new_alertname") {
		t.Errorf("new_alertname broadcast missing text:\n%s", p.blocks)
	}
}

func TestRecurrence_CadenceBroadcasts(t *testing.T) {
	client := newFakeSlack(t)
	n, _, _ := occNotifier(t, client, &fakeThreadStore{})
	ev := recurEvent("cadence", 9, time.Unix(1_000_000, 0).UTC())
	ev.NewInterval, ev.PriorMedian = 5*time.Minute, 40*time.Minute
	if err := n.OnOccurrenceAttached(context.Background(), ev); err != nil {
		t.Fatalf("attach: %v", err)
	}
	p := client.lastPost()
	if !strings.Contains(p.blocks, "Firing faster") || !strings.Contains(p.blocks, "why: cadence") {
		t.Errorf("cadence broadcast missing text:\n%s", p.blocks)
	}
}

func TestRecurrence_BackstopsSilent(t *testing.T) {
	for _, trig := range []string{"cap", "ceiling"} {
		client := newFakeSlack(t)
		n, _, _ := occNotifier(t, client, &fakeThreadStore{})
		if err := n.OnOccurrenceAttached(context.Background(), recurEvent(trig, 3, time.Unix(1_000_000, 0).UTC())); err != nil {
			t.Fatalf("%s attach: %v", trig, err)
		}
		if client.postCount() != 0 || client.updateCount() != 0 {
			t.Errorf("%s: posts/updates = %d/%d, want 0/0 (silent backstop)", trig, client.postCount(), client.updateCount())
		}
	}
}

func TestRecurrence_MilestoneBroadcasts(t *testing.T) {
	client := newFakeSlack(t)
	n, now, _ := occNotifier(t, client, &fakeThreadStore{})
	// Count 4 -> Episodes 5 -> milestone. First attach edits card immediately.
	if err := n.OnOccurrenceAttached(context.Background(), recurEvent("none", 4, *now)); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if client.updateCount() != 1 {
		t.Errorf("card updates = %d, want 1 (plain attach edits card)", client.updateCount())
	}
	if client.postCount() != 1 {
		t.Fatalf("posts = %d, want 1 (milestone broadcast)", client.postCount())
	}
	p := client.lastPost()
	if !p.broadcast || !strings.Contains(p.blocks, "Still recurring") || !strings.Contains(p.blocks, "why: milestone") {
		t.Errorf("milestone broadcast wrong: broadcast=%v\n%s", p.broadcast, p.blocks)
	}
	// Span must anchor on the incident's true start (FirstAlertAt, 5h before
	// now per recurEvent), not the first occurrence row (FirstOccurredAt, only
	// 3h before now) — the latter would understate the incident's real age.
	if !strings.Contains(p.blocks, "over 5h") {
		t.Errorf("milestone broadcast span anchored on the wrong start time, want \"over 5h\":\n%s", p.blocks)
	}
}

func TestRecurrence_NonMilestonePlainAttachSilent(t *testing.T) {
	client := newFakeSlack(t)
	n, now, _ := occNotifier(t, client, &fakeThreadStore{})
	// Count 5 -> Episodes 6 -> not a milestone.
	if err := n.OnOccurrenceAttached(context.Background(), recurEvent("none", 5, *now)); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if client.updateCount() != 1 || client.postCount() != 0 {
		t.Errorf("updates/posts = %d/%d, want 1/0 (card edit only, no broadcast)", client.updateCount(), client.postCount())
	}
}

func TestRecurrence_ModeOffSilencesBroadcastsButKeepsCardEdit(t *testing.T) {
	client := newFakeSlack(t)
	n, now, _ := occNotifier(t, client, &fakeThreadStore{})
	n.recurrenceMode = recurrenceOff
	// A milestone plain attach: card still edits, no broadcast.
	if err := n.OnOccurrenceAttached(context.Background(), recurEvent("none", 4, *now)); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if client.updateCount() != 1 || client.postCount() != 0 {
		t.Errorf("off milestone: updates/posts = %d/%d, want 1/0", client.updateCount(), client.postCount())
	}
	// A severity escalation: no broadcast, no card edit (Notify writes card).
	sev := recurEvent("severity", 5, now.Add(occEditThrottle+time.Second))
	sev.PriorSeverity, sev.NewSeverity = "warning", "critical"
	if err := n.OnOccurrenceAttached(context.Background(), sev); err != nil {
		t.Fatalf("attach sev: %v", err)
	}
	if client.postCount() != 0 {
		t.Errorf("off severity: posts = %d, want 0", client.postCount())
	}
}

func TestRecurrence_NoThreadSkipsBroadcast(t *testing.T) {
	client := newFakeSlack(t)
	n, _, _ := occNotifier(t, client, &fakeThreadStore{missing: true})
	ev := recurEvent("severity", 4, time.Unix(1_000_000, 0).UTC())
	ev.PriorSeverity, ev.NewSeverity = "warning", "critical"
	if err := n.OnOccurrenceAttached(context.Background(), ev); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if client.postCount() != 0 || client.updateCount() != 0 {
		t.Errorf("gate-suppressed: posts/updates = %d/%d, want 0/0", client.postCount(), client.updateCount())
	}
}

func TestRecurrence_DrillBannerOnBroadcast(t *testing.T) {
	client := newFakeSlack(t)
	n, _, _ := occNotifier(t, client, &fakeThreadStore{})
	ev := recurEvent("severity", 4, time.Unix(1_000_000, 0).UTC())
	ev.PriorSeverity, ev.NewSeverity, ev.Drill = "warning", "critical", true
	if err := n.OnOccurrenceAttached(context.Background(), ev); err != nil {
		t.Fatalf("attach: %v", err)
	}
	p := client.lastPost()
	if !strings.Contains(p.blocks, "DRILL") || !strings.Contains(p.text, "DRILL") {
		t.Errorf("drill broadcast missing DRILL banner: text=%q\n%s", p.text, p.blocks)
	}
}

func TestRecurrence_PendingFlushCanceledOnRejudge(t *testing.T) {
	client := newFakeSlack(t)
	n, now, _ := occNotifier(t, client, &fakeThreadStore{})
	stopped := false
	n.after = func(_ time.Duration, _ func()) stopper { return &recordingStopper{stopped: &stopped} }
	// First plain attach edits immediately and sets last.
	if err := n.OnOccurrenceAttached(context.Background(), recurEvent("none", 1, *now)); err != nil {
		t.Fatalf("attach 1: %v", err)
	}
	// Second plain attach within the window arms a trailing timer (pending edit).
	if err := n.OnOccurrenceAttached(context.Background(), recurEvent("none", 2, *now)); err != nil {
		t.Fatalf("attach 2: %v", err)
	}
	// A severity re-judge attach must cancel the pending count-edit.
	sev := recurEvent("severity", 3, *now)
	sev.PriorSeverity, sev.NewSeverity = "warning", "critical"
	if err := n.OnOccurrenceAttached(context.Background(), sev); err != nil {
		t.Fatalf("attach sev: %v", err)
	}
	if !stopped {
		t.Error("pending trailing count-edit timer was not stopped on a re-judging attach")
	}
}

type recordingStopper struct{ stopped *bool }

func (r *recordingStopper) Stop() bool { *r.stopped = true; return true }
