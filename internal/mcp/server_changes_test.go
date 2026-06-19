// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestRecentChanges_ExactAndMatch(t *testing.T) {
	ctx := context.Background()
	st, _ := store.Open(ctx, ":memory:")
	defer func() { _ = st.Close() }()
	now := time.Now().UTC()
	ins := func(id string, labels map[string]string, mins int) {
		ts := now.Add(time.Duration(-mins) * time.Minute)
		_ = st.InsertChange(ctx, store.Change{ID: id, Source: "ci", Kind: "deploy", Title: id, Labels: labels, OccurredAt: ts, ReceivedAt: ts})
	}
	ins("match", map[string]string{"service": "checkout", "namespace": "prod"}, 5)
	ins("partial", map[string]string{"service": "checkout"}, 3) // missing namespace → excluded by AND-match
	ins("other", map[string]string{"service": "payments", "namespace": "prod"}, 1)

	s := &Server{cfg: Config{ChangesEnabled: true, ChangesWindowMinutes: 120}, st: st, auditor: audit.New(st.DB())}
	req := mcplib.CallToolRequest{}
	req.Params.Arguments = map[string]any{
		"selector": map[string]any{"service": "checkout", "namespace": "prod"},
		"limit":    float64(10),
	}
	res, err := s.handleRecentChanges(ctx, req)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	changes, _ := payload["changes"].([]any)
	if len(changes) != 1 {
		t.Fatalf("AND-match want 1 (only 'match'), got %d: %v", len(changes), changes)
	}
}

func TestRecentChanges_DisabledMessage(t *testing.T) {
	st, _ := store.Open(context.Background(), ":memory:")
	defer func() { _ = st.Close() }()
	s := &Server{cfg: Config{ChangesEnabled: false}, st: st, auditor: audit.New(st.DB())}
	res, _ := s.handleRecentChanges(context.Background(), mcplib.CallToolRequest{})
	if !res.IsError {
		t.Fatal("want error result when changes disabled")
	}
}
