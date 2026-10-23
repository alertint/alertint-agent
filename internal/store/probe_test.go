// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestConnectionWatchCongestedOnMeanWaitNotTotal is issue #99: a busy agent's
// thousands of short waits a minute add up past the total on their own, so
// congestion also needs a long average wait.
func TestConnectionWatchCongestedOnMeanWaitNotTotal(t *testing.T) {
	watch := ConnectionWatch{Interval: time.Minute, Waited: 10 * time.Second, MeanWait: time.Second}
	for _, tc := range []struct {
		name   string
		waited time.Duration
		waits  int64
		want   bool
	}{
		{"lab v0.15.5: many short waits", 11700 * time.Millisecond, 7858, false},
		{"lab v0.15.4: fewer, still short", 19400 * time.Millisecond, 1133, false},
		{"one long wait, below the total", 3 * time.Second, 1, false},
		{"long waits past the total", 200 * time.Second, 40, true},
		{"long waits counted the interval before", 200 * time.Second, 0, true},
		{"no waits", 0, 0, false},
	} {
		if got := watch.congested(tc.waited, tc.waits); got != tc.want {
			t.Errorf("%s: congested(%s, %d) = %v, want %v", tc.name, tc.waited, tc.waits, got, tc.want)
		}
	}
}

// TestWatchConnectionWaitNamesALongHold holds the store connection while two
// store calls wait for it: the hold is logged with its holder, the waits as
// congestion, and the waiting calls' own short holds not at all.
func TestWatchConnectionWaitNamesALongHold(t *testing.T) {
	st := newTestStore(t)
	logs := &lockedBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		st.WatchConnectionWait(ctx, slog.New(slog.NewJSONHandler(logs, nil)), ConnectionWatch{
			Interval: 100 * time.Millisecond, Waited: 500 * time.Millisecond, MeanWait: 200 * time.Millisecond, Hold: 500 * time.Millisecond,
		})
	}()
	t.Cleanup(func() { cancel(); <-done })
	for deadline := time.Now().Add(5 * time.Second); st.holds.logger.Load() == nil; {
		if time.Now().After(deadline) {
			t.Fatal("watch never started")
		}
		time.Sleep(time.Millisecond)
	}

	var waiters sync.WaitGroup
	holdStoreConnection(t, st, time.Second, func() {
		for range 2 {
			waiters.Go(func() {
				var one int
				if err := st.DB().QueryRowContext(ctx, `SELECT 1`).Scan(&one); err != nil {
					t.Error(err)
				}
			})
		}
	})
	waiters.Wait()

	var held, congested []watchLine
	for deadline := time.Now().Add(5 * time.Second); len(congested) == 0; {
		if time.Now().After(deadline) {
			t.Fatalf("no congested line; logs:\n%s", logs)
		}
		time.Sleep(50 * time.Millisecond)
		held, congested = logs.lines(t, "store: connection held"), logs.lines(t, "store: connection congested")
	}
	if len(held) != 1 || !strings.HasPrefix(held[0].Holder, "store.holdStoreConnection < store.TestWatchConnectionWaitNamesALongHold") ||
		held[0].Held < time.Second {
		t.Fatalf("held lines = %v, want one naming holdStoreConnection for at least 1s", held)
	}
	if congested[0].Waited < 500*time.Millisecond {
		t.Fatalf("congested line = %v, want the waiters' wait", congested[0])
	}
}

// holdStoreConnection holds the store connection in a transaction for d,
// starting the would-be waiters once it has it.
func holdStoreConnection(t *testing.T, st *Store, d time.Duration, whileHeld func()) {
	t.Helper()
	tx, err := st.DB().BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	whileHeld()
	time.Sleep(d)
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// lockedBuffer is a log destination safe to write from several goroutines.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// watchLine is the fields of WatchConnectionWait's log lines.
type watchLine struct {
	Msg    string        `json:"msg"`
	Holder string        `json:"holder"`
	Held   time.Duration `json:"held"`
	Waited time.Duration `json:"waited"`
}

// lines returns the JSON log lines with message msg.
func (b *lockedBuffer) lines(t *testing.T, msg string) []watchLine {
	t.Helper()
	var out []watchLine
	for line := range strings.Lines(b.String()) {
		var entry watchLine
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("log line %q: %v", line, err)
		}
		if entry.Msg == msg {
			out = append(out, entry)
		}
	}
	return out
}
