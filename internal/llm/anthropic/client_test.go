package anthropic_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	llm "github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/internal/store"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// responseBody builds a minimal Anthropic Messages API success body.
func responseBody(text string, inputTok, outputTok int) string {
	payload := map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"usage": map[string]any{
			"input_tokens":  inputTok,
			"output_tokens": outputTok,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// newTestClient wires a Client against the given test server URL.
func newTestClient(t *testing.T, serverURL string, auditor *audit.Auditor) *llm.Client {
	t.Helper()
	cfg := llm.Config{
		APIKey:         "test-key",
		Model:          "claude-test",
		MaxTokens:      256,
		BaseRetryDelay: 5 * time.Millisecond,
	}
	c := llm.NewWithHTTPClient(cfg, auditor, nil, serverURL)
	return c
}

// newTestStore opens an in-memory store with applied migrations.
func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// --------------------------------------------------------------------------
// Tests
// --------------------------------------------------------------------------

// TestSuccess verifies a well-formed response is returned as-is.
func TestSuccess(t *testing.T) {
	want := `{"analysis_name":"test","confidence":0.9}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBody(want, 10, 20))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	raw, err := c.Complete(context.Background(), "sys", "user", []string{"analysis_name", "confidence"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["analysis_name"] != "test" {
		t.Errorf("analysis_name = %v, want test", got["analysis_name"])
	}
}

// TestMarkdownFenceStripped verifies ```json ... ``` wrappers are removed.
func TestMarkdownFenceStripped(t *testing.T) {
	want := "```json\n{\"key\":\"val\"}\n```"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBody(want, 5, 5))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	raw, err := c.Complete(context.Background(), "sys", "user", []string{"key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["key"] != "val" {
		t.Errorf("key = %v, want val", got["key"])
	}
}

// TestRetryOn429 verifies the client retries on HTTP 429 and eventually succeeds.
func TestRetryOn429(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n < 3 {
			// First two attempts return 429.
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBody(`{"result":"ok"}`, 1, 1))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	raw, err := c.Complete(context.Background(), "sys", "user", []string{"result"})
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 total calls (2 retries + 1 success), got %d", calls.Load())
	}
	var got map[string]any
	_ = json.Unmarshal(raw, &got)
	if got["result"] != "ok" {
		t.Errorf("result = %v, want ok", got["result"])
	}
}

// TestRetryExhausted verifies that after MaxRetries the last error is returned.
func TestRetryExhausted(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	_, err := c.Complete(context.Background(), "sys", "user", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	expectedCalls := int32(llm.MaxRetries + 1)
	if calls.Load() != expectedCalls {
		t.Errorf("expected %d calls, got %d", expectedCalls, calls.Load())
	}
}

// TestSchemaViolation verifies ErrSchemaViolation is returned when a
// required key is absent from the model response.
func TestSchemaViolation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBody(`{"only_key":"present"}`, 1, 1))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	_, err := c.Complete(context.Background(), "sys", "user", []string{"only_key", "missing_key"})
	if err == nil {
		t.Fatal("expected schema violation error, got nil")
	}
	if !errors.Is(err, llm.ErrSchemaViolation) {
		t.Errorf("expected ErrSchemaViolation, got: %v", err)
	}
}

// TestNon429ErrorNotRetried verifies that a 500 is returned immediately
// without retrying.
func TestNon429ErrorNotRetried(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	_, err := c.Complete(context.Background(), "sys", "user", nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if calls.Load() != 1 {
		t.Errorf("expected 1 call (no retry on 500), got %d", calls.Load())
	}
}

// TestAuditRowsWritten verifies that llm.request and llm.response rows
// are appended to the audit log on a successful call.
func TestAuditRowsWritten(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBody(`{"ok":true}`, 5, 8))
	}))
	defer srv.Close()

	st := newTestStore(t)
	auditor := audit.New(st.DB())
	c := newTestClient(t, srv.URL, auditor)

	ctx := context.Background()
	_, err := c.Complete(ctx, "sys", "user", []string{"ok"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rows, err := countAuditRows(st.DB(), "llm.request", "llm.response")
	if err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if rows["llm.request"] != 1 {
		t.Errorf("llm.request rows = %d, want 1", rows["llm.request"])
	}
	if rows["llm.response"] != 1 {
		t.Errorf("llm.response rows = %d, want 1", rows["llm.response"])
	}
}

func countAuditRows(db *sql.DB, kinds ...string) (map[string]int, error) {
	out := make(map[string]int)
	for _, k := range kinds {
		var n int
		if err := db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_log WHERE kind = ?`, k).Scan(&n); err != nil {
			return nil, err
		}
		out[k] = n
	}
	return out, nil
}
