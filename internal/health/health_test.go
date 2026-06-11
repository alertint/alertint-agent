// SPDX-License-Identifier: FSL-1.1-ALv2

package health

import (
	"context"
	"errors"
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
}
