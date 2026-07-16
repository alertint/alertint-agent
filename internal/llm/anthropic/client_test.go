// SPDX-License-Identifier: FSL-1.1-ALv2

package anthropic_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// responseBodyStop builds a success body carrying a stop_reason (e.g.
// "max_tokens" for an output-ceiling truncation).
func responseBodyStop(text, stopReason string, inputTok, outputTok int) string {
	payload := map[string]any{
		"content": []map[string]any{
			{"type": "text", "text": text},
		},
		"stop_reason": stopReason,
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
	comp, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, []string{"analysis_name", "confidence"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(comp.Raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["analysis_name"] != "test" {
		t.Errorf("analysis_name = %v, want test", got["analysis_name"])
	}
	// The Completion carries the usage the audit log uses, for the caller's
	// "llm responded" line.
	if comp.Model != "claude-test" {
		t.Errorf("Model = %q, want claude-test", comp.Model)
	}
	if comp.InputTokens != 10 || comp.OutputTokens != 20 {
		t.Errorf("tokens = (%d,%d), want (10,20)", comp.InputTokens, comp.OutputTokens)
	}
	if comp.Latency < 0 {
		t.Errorf("Latency should be non-negative, got %v", comp.Latency)
	}
}

// TestDefaultModelAndThinkingDisabled verifies (1) an empty Config.Model
// resolves to DefaultModel on the wire, and (2) every request explicitly
// disables extended thinking — on models that default thinking ON when the
// field is omitted (claude-sonnet-5+), thinking output would count against
// max_tokens and truncate the required-keys JSON reply.
func TestDefaultModelAndThinkingDisabled(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBody(`{"analysis_name":"t"}`, 1, 1))
	}))
	defer srv.Close()

	c := llm.NewWithHTTPClient(llm.Config{APIKey: "k"}, nil, nil, srv.URL)
	if _, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, []string{"analysis_name"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if body["model"] != llm.DefaultModel {
		t.Errorf("model on the wire = %v, want DefaultModel %q", body["model"], llm.DefaultModel)
	}
	thinking, ok := body["thinking"].(map[string]any)
	if !ok || thinking["type"] != "disabled" {
		t.Errorf("thinking on the wire = %v, want {type: disabled}", body["thinking"])
	}
}

// TestDefaultModelIsCurrentSonnet pins the default triage model: Sonnet for
// first-finding quality, with Haiku as the documented config opt-in.
func TestDefaultModelIsCurrentSonnet(t *testing.T) {
	if llm.DefaultModel != "claude-sonnet-5" {
		t.Errorf("DefaultModel = %q, want claude-sonnet-5", llm.DefaultModel)
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
	comp, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, []string{"key"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(comp.Raw, &got); err != nil {
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
	comp, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, []string{"result"})
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("expected 3 total calls (2 retries + 1 success), got %d", calls.Load())
	}
	var got map[string]any
	_ = json.Unmarshal(comp.Raw, &got)
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
	_, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, nil)
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
	_, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, []string{"only_key", "missing_key"})
	if err == nil {
		t.Fatal("expected schema violation error, got nil")
	}
	if !errors.Is(err, llm.ErrSchemaViolation) {
		t.Errorf("expected ErrSchemaViolation, got: %v", err)
	}
}

// TestMaxTokensTruncationError verifies that a reply cut off by the output
// ceiling (stop_reason=max_tokens) yields a clear, actionable
// ErrResponseTruncated — not the misleading "not valid JSON" the raw parse
// failure would produce — so the operator's fix (raise llm.max_tokens) is
// obvious from the log line.
func TestMaxTokensTruncationError(t *testing.T) {
	// A JSON object cut off mid-field, exactly what the model emits when it
	// exhausts the output budget partway through the required-keys reply.
	truncated := `{"analysis_name":"node OOM cascade","alerts":[{"alert_id":"a1","role_in`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, responseBodyStop(truncated, "max_tokens", 5000, 256))
	}))
	defer srv.Close()

	c := newTestClient(t, srv.URL, nil)
	_, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, []string{"analysis_name"})
	if err == nil {
		t.Fatal("expected truncation error, got nil")
	}
	if !errors.Is(err, llm.ErrResponseTruncated) {
		t.Errorf("expected ErrResponseTruncated, got: %v", err)
	}
	if strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("truncation must not surface as a JSON parse error: %v", err)
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
	_, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "user"}, nil)
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
	_, err := c.Complete(ctx, "sys", llm.Prompt{Prefix: "user"}, []string{"ok"})
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

// TestPromptSuffixConcatenated verifies a Prompt with prefix+suffix reaches
// the API as one user turn whose content is the exact concatenation (Task 2
// changes the encoding to blocks when marked; the text must survive either way).
func TestPromptSuffixConcatenated(t *testing.T) {
	var gotBody []byte
	srv := captureServer(t, &gotBody)

	c := llm.NewWithHTTPClient(llm.Config{APIKey: "k"}, nil, nil, srv.URL)
	if _, err := c.Complete(context.Background(), "sys",
		llm.Prompt{Prefix: "PREFIX-", Suffix: "SUFFIX"}, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// A suffixed prompt always serializes as block array (Task 2), so
	// reconstruct the text across blocks rather than substring-matching the
	// raw JSON.
	var blocks []requestBlock
	if err := json.Unmarshal(decodeUserContent(t, gotBody), &blocks); err != nil {
		t.Fatalf("content is not a block array: %v", err)
	}
	var got strings.Builder
	for _, b := range blocks {
		got.WriteString(b.Text)
	}
	if got.String() != "PREFIX-SUFFIX" {
		t.Errorf("user content lost the prefix+suffix concatenation: %q", got.String())
	}
}

// decodeUserContent pulls messages[0].content out of a captured request body.
func decodeUserContent(t *testing.T, body []byte) json.RawMessage {
	t.Helper()
	var req struct {
		Messages []struct {
			Content json.RawMessage `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		t.Fatalf("parse request: %v", err)
	}
	if len(req.Messages) != 1 {
		t.Fatalf("messages = %d, want 1", len(req.Messages))
	}
	return req.Messages[0].Content
}

// captureServer returns a test server that records the last request body.
func captureServer(t *testing.T, body *[]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*body, _ = io.ReadAll(r.Body)
		_, _ = fmt.Fprint(w, responseBody(`{"ok":true}`, 1, 1))
	}))
	t.Cleanup(srv.Close)
	return srv
}

type requestBlock struct {
	Type         string          `json:"type"`
	Text         string          `json:"text"`
	CacheControl json.RawMessage `json:"cache_control"`
}

// TestMarkedPromptEmitsBlocksWithBreakpoint: marked + suffix → two text
// blocks, cache_control {"type":"ephemeral"} on the prefix block ONLY, no ttl.
func TestMarkedPromptEmitsBlocksWithBreakpoint(t *testing.T) {
	var body []byte
	srv := captureServer(t, &body)
	c := llm.NewWithHTTPClient(llm.Config{APIKey: "k"}, nil, nil, srv.URL)
	if _, err := c.Complete(context.Background(), "sys",
		llm.Prompt{Prefix: "E", Suffix: "DV", CachePrefix: true}, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var blocks []requestBlock
	if err := json.Unmarshal(decodeUserContent(t, body), &blocks); err != nil {
		t.Fatalf("content is not a block array: %v", err)
	}
	if len(blocks) != 2 {
		t.Fatalf("blocks = %d, want 2", len(blocks))
	}
	if blocks[0].Text != "E" || blocks[1].Text != "DV" {
		t.Errorf("block texts = %q, %q", blocks[0].Text, blocks[1].Text)
	}
	if string(blocks[0].CacheControl) != `{"type":"ephemeral"}` {
		t.Errorf("prefix cache_control = %s, want {\"type\":\"ephemeral\"}", blocks[0].CacheControl)
	}
	if blocks[1].CacheControl != nil {
		t.Errorf("suffix block must not carry cache_control, got %s", blocks[1].CacheControl)
	}
}

// TestMarkedPromptNoSuffixSingleBlock: call-1 shape — one marked block.
func TestMarkedPromptNoSuffixSingleBlock(t *testing.T) {
	var body []byte
	srv := captureServer(t, &body)
	c := llm.NewWithHTTPClient(llm.Config{APIKey: "k"}, nil, nil, srv.URL)
	if _, err := c.Complete(context.Background(), "sys",
		llm.Prompt{Prefix: "E", CachePrefix: true}, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	var blocks []requestBlock
	if err := json.Unmarshal(decodeUserContent(t, body), &blocks); err != nil {
		t.Fatalf("content is not a block array: %v", err)
	}
	if len(blocks) != 1 || string(blocks[0].CacheControl) != `{"type":"ephemeral"}` {
		t.Errorf("want one marked block, got %+v", blocks)
	}
}

// TestUnmarkedPromptKeepsLegacyStringShape: the kill-switch guarantee — an
// unmarked, suffix-less prompt serializes content as a plain JSON string,
// byte-identical to the pre-caching client.
func TestUnmarkedPromptKeepsLegacyStringShape(t *testing.T) {
	var body []byte
	srv := captureServer(t, &body)
	c := llm.NewWithHTTPClient(llm.Config{APIKey: "k"}, nil, nil, srv.URL)
	if _, err := c.Complete(context.Background(), "sys",
		llm.Prompt{Prefix: "plain user prompt"}, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	content := decodeUserContent(t, body)
	var s string
	if err := json.Unmarshal(content, &s); err != nil {
		t.Fatalf("content is not a plain JSON string (legacy shape broken): %s", content)
	}
	if s != "plain user prompt" {
		t.Errorf("content = %q", s)
	}
}

// responseBodyCached builds a success body whose usage carries cache fields.
func responseBodyCached(text string, inputTok, outputTok, cacheW, cacheR int) string {
	payload := map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"usage": map[string]any{
			"input_tokens":                inputTok,
			"output_tokens":               outputTok,
			"cache_creation_input_tokens": cacheW,
			"cache_read_input_tokens":     cacheR,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// TestCacheUsageCaptured: the two cache usage fields reach Completion and the
// llm.response audit payload.
func TestCacheUsageCaptured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, responseBodyCached(`{"ok":true}`, 7, 3, 4200, 1100))
	}))
	defer srv.Close()

	st := newTestStore(t)
	auditor := audit.New(st.DB())
	c := llm.NewWithHTTPClient(llm.Config{APIKey: "k"}, auditor, nil, srv.URL)

	comp, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "E", CachePrefix: true}, nil)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if comp.CacheCreationInputTokens != 4200 || comp.CacheReadInputTokens != 1100 {
		t.Errorf("cache usage = %d/%d, want 4200/1100",
			comp.CacheCreationInputTokens, comp.CacheReadInputTokens)
	}

	var payloadJSON string
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT payload_json FROM audit_log WHERE kind = 'llm.response'`).Scan(&payloadJSON); err != nil {
		t.Fatalf("read llm.response payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(payloadJSON), &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	if payload["cache_creation_input_tokens"] != float64(4200) ||
		payload["cache_read_input_tokens"] != float64(1100) {
		t.Errorf("audit payload cache fields = %v/%v, want 4200/1100",
			payload["cache_creation_input_tokens"], payload["cache_read_input_tokens"])
	}
}
