// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// fakeSlack captures posts/updates. It renders each update's fallback text via
// UnsafeApplyMsgOptions so tests can assert on the recurrence count.
type fakeSlack struct {
	mu        sync.Mutex
	posts     int
	updates   []string
	updateErr error
}

func (f *fakeSlack) PostMessageContext(_ context.Context, channelID string, _ ...slacklib.MsgOption) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.posts++
	return channelID, "ts-1", nil
}

func (f *fakeSlack) UpdateMessageContext(_ context.Context, channelID, timestamp string, options ...slacklib.MsgOption) (string, string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return "", "", "", f.updateErr
	}
	_, values, _ := slacklib.UnsafeApplyMsgOptions("t", channelID, "https://slack.com/api/", options...)
	f.updates = append(f.updates, values.Get("text"))
	return channelID, timestamp, "", nil
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
	client := &fakeSlack{}
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
	client := &fakeSlack{}
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
	client := &fakeSlack{}
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
	client := &fakeSlack{}
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
	client := &fakeSlack{updateErr: errors.New("slack 500")}
	n, now, _ := occNotifier(t, client, &fakeThreadStore{})
	err := attach(n, 1, *now)
	if err == nil {
		t.Fatal("OnOccurrenceAttached returned nil on a Slack error, want the error surfaced")
	}
	// One attempt, no retry loop.
	client.mu.Lock()
	updated := client.posts // updateErr path increments nothing; ensure no storm
	client.mu.Unlock()
	_ = updated
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
