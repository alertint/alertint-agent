// SPDX-License-Identifier: FSL-1.1-ALv2

package health

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRegistry_ReportsProbeResults(t *testing.T) {
	r := NewRegistry(time.Minute,
		Check{Name: "good", Detail: "http://ok", Probe: func(context.Context) error { return nil }},
		Check{Name: "bad", Detail: "#chan", Probe: func(context.Context) error { return errors.New("auth failed") }},
	)
	statuses := r.Run(context.Background())
	if len(statuses) != 2 {
		t.Fatalf("want 2 statuses, got %d", len(statuses))
	}
	if !statuses[0].OK || statuses[0].Name != "good" {
		t.Errorf("good probe: %+v", statuses[0])
	}
	if statuses[1].OK || statuses[1].Error != "auth failed" {
		t.Errorf("bad probe: %+v", statuses[1])
	}
}

func TestRegistry_CachesWithinTTL(t *testing.T) {
	calls := 0
	r := NewRegistry(time.Hour, Check{
		Name:  "counted",
		Probe: func(context.Context) error { calls++; return nil },
	})
	r.Run(context.Background())
	r.Run(context.Background())
	if calls != 1 {
		t.Errorf("probe ran %d times within TTL, want 1", calls)
	}
}

func TestRegistry_ReprobesAfterTTL(t *testing.T) {
	calls := 0
	r := NewRegistry(time.Nanosecond, Check{
		Name:  "counted",
		Probe: func(context.Context) error { calls++; return nil },
	})
	r.Run(context.Background())
	time.Sleep(time.Millisecond)
	r.Run(context.Background())
	if calls != 2 {
		t.Errorf("probe ran %d times across TTL expiry, want 2", calls)
	}
}

func TestRegistry_NilSafe(t *testing.T) {
	var r *Registry
	if got := r.Run(context.Background()); got != nil {
		t.Errorf("nil registry must return nil, got %v", got)
	}
	r.Watch(context.Background(), nil) // must return immediately, not panic
}

// watchHarness runs Watch against a scripted probe sequence (the last
// result repeats once exhausted), cancels after the whole sequence has
// been consumed, and returns the captured log output.
func watchHarness(t *testing.T, r *Registry, results []error) string {
	t.Helper()
	var mu sync.Mutex
	call := 0
	consumed := make(chan struct{})
	r.checks[0].Probe = func(context.Context) error {
		mu.Lock()
		defer mu.Unlock()
		err := results[min(call, len(results)-1)]
		call++
		if call == len(results) {
			close(consumed)
		}
		return err
	}
	r.watchMin, r.watchSteady = time.Millisecond, 2*time.Millisecond

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		r.Watch(ctx, logger)
		close(done)
	}()

	select {
	case <-consumed:
	case <-time.After(5 * time.Second):
		t.Fatal("watch never consumed the scripted probe results")
	}
	cancel()
	<-done
	return buf.String()
}

func TestRegistry_WatchRetriesStartupFailure(t *testing.T) {
	r := NewRegistry(time.Hour, Check{Name: "prometheus", Detail: "http://prom:9090"})
	logs := watchHarness(t, r, []error{
		errors.New("connection refused"),
		errors.New("connection refused"),
		nil,
	})
	for _, want := range []string{
		"integration health: FAILED",
		"integration health: retry failed",
		"integration health: connection restored",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q:\n%s", want, logs)
		}
	}
	// The watcher must seed the cache so /health reflects the recovery.
	statuses := r.Run(context.Background())
	if len(statuses) != 1 || !statuses[0].OK {
		t.Errorf("cached status after recovery: %+v", statuses)
	}
}

func TestRegistry_WatchLogsConnectionLossAndRecovery(t *testing.T) {
	r := NewRegistry(time.Hour, Check{Name: "prometheus", Detail: "http://prom:9090"})
	logs := watchHarness(t, r, []error{
		nil,
		errors.New("connection refused"),
		nil,
	})
	for _, want := range []string{
		"integration health: OK",
		"integration health: connection lost; retrying",
		"integration health: connection restored",
	} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs missing %q:\n%s", want, logs)
		}
	}
}
