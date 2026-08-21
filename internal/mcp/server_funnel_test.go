// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
)

func TestHandlePokeFunnelGetReportsCounts(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{SituationCommands: &fakeSituationCommands{}}, st, audit.New(st.DB()))
	now := time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC)
	seedTestIncident(t, st, "inc-funnel-1", "host=funnel-1", now)
	seedTestDelivery(t, st, "del-funnel-1", "alert-funnel-1", "inc-funnel-1", "zabbix", map[string]string{}, now)

	res, err := s.handlePokeFunnelGet(context.Background(), reqWith(map[string]any{
		"since": "2026-08-01T00:00:00Z", "until": "2026-09-01T00:00:00Z",
	}))
	if err != nil || res.IsError {
		t.Fatalf("err=%v result=%s", err, resultText(t, res))
	}
	out := resultText(t, res)
	if !strings.Contains(out, `"accepted_deliveries":1`) {
		t.Fatalf("expected accepted_deliveries=1 in response: %s", out)
	}
}

func TestHandlePokeFunnelGetRequiresSinceAndUntil(t *testing.T) {
	s := newMCPServer(t)
	res, err := s.handlePokeFunnelGet(context.Background(), reqWith(map[string]any{"since": "2026-08-01T00:00:00Z"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for a missing until")
	}
}

func TestHandlePokeFunnelGetRejectsInvalidTime(t *testing.T) {
	s := newMCPServer(t)
	res, err := s.handlePokeFunnelGet(context.Background(), reqWith(map[string]any{"since": "not-a-time", "until": "2026-09-01T00:00:00Z"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected an error result for an invalid since")
	}
}
