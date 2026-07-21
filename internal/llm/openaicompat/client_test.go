// SPDX-License-Identifier: FSL-1.1-ALv2

package openaicompat_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/openaicompat"
	"github.com/alertint/alertint-agent/internal/store"
)

// chatBody builds a minimal OpenAI chat-completions success body.
func chatBody(content string, promptTok, completionTok int) string {
	payload := map[string]any{
		"choices": []map[string]any{
			{"message": map[string]any{"content": content}, "finish_reason": "stop"},
		},
		"usage": map[string]any{
			"prompt_tokens":     promptTok,
			"completion_tokens": completionTok,
		},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// newClient points a default-config client at srv. Overrides may tweak cfg.
func newClient(srv *httptest.Server, mut func(*openaicompat.Config)) *openaicompat.Client {
	cfg := openaicompat.Config{
		BaseURL:        srv.URL,
		Model:          "qwen3-32b",
		MaxTokens:      4096,
		ResponseFormat: "json_object",
		TimeoutSeconds: 5,
	}
	if mut != nil {
		mut(&cfg)
	}
	return openaicompat.New(cfg, nil, nil)
}

func TestCompleteHappyPath(t *testing.T) {
	var gotPath string
	var gotBody map[string]any
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(chatBody(`{"overall_issue":"disk full"}`, 100, 20)))
	}))
	defer srv.Close()

	c := newClient(srv, nil)
	comp, err := c.Complete(context.Background(), "sys", llm.Prompt{Prefix: "evidence"}, []string{"overall_issue"})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("path = %q, want /v1/chat/completions", gotPath)
	}
	if gotAuth != "" {
		t.Errorf("no APIKey set: Authorization header must be absent, got %q", gotAuth)
	}
	if gotBody["model"] != "qwen3-32b" {
		t.Errorf("model = %v", gotBody["model"])
	}
	if gotBody["max_tokens"] != float64(4096) {
		t.Errorf("max_tokens = %v", gotBody["max_tokens"])
	}
	msgs, ok := gotBody["messages"].([]any)
	if !ok || len(msgs) != 2 {
		t.Fatalf("want [system,user] messages, got %v", gotBody["messages"])
	}
	sys, ok := msgs[0].(map[string]any)
	if !ok {
		t.Fatalf("system message is not an object: %v", msgs[0])
	}
	usr, ok := msgs[1].(map[string]any)
	if !ok {
		t.Fatalf("user message is not an object: %v", msgs[1])
	}
	if sys["role"] != "system" || sys["content"] != "sys" {
		t.Errorf("system message = %v", sys)
	}
	if usr["role"] != "user" || usr["content"] != "evidence" {
		t.Errorf("user message = %v", usr)
	}
	rf, ok := gotBody["response_format"].(map[string]any)
	if !ok {
		t.Fatalf("response_format is not an object: %v", gotBody["response_format"])
	}
	if rf["type"] != "json_object" {
		t.Errorf("response_format = %v", rf)
	}
	kw, ok := gotBody["chat_template_kwargs"].(map[string]any)
	if !ok {
		t.Fatalf("chat_template_kwargs is not an object: %v", gotBody["chat_template_kwargs"])
	}
	if kw["enable_thinking"] != false {
		t.Errorf("enable_thinking = %v, want false", kw["enable_thinking"])
	}
	if string(comp.Raw) != `{"overall_issue":"disk full"}` {
		t.Errorf("Raw = %s", comp.Raw)
	}
	if comp.Model != "qwen3-32b" || comp.InputTokens != 100 || comp.OutputTokens != 20 {
		t.Errorf("usage mapping: %+v", comp)
	}
	if comp.CacheCreationInputTokens != 0 || comp.CacheReadInputTokens != 0 {
		t.Errorf("cache fields must be zero on this wire format: %+v", comp)
	}
}

func TestRequestShapeVariants(t *testing.T) {
	var gotBody map[string]any
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotBody = nil // reset: json.Decode into a map merges rather than replaces stale keys
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(chatBody(`{"k":1}`, 1, 1)))
	}))
	defer srv.Close()

	t.Run("bearer header when key set", func(t *testing.T) {
		c := newClient(srv, func(cfg *openaicompat.Config) { cfg.APIKey = "sk-local" })
		if _, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
			t.Fatal(err)
		}
		if gotAuth != "Bearer sk-local" {
			t.Errorf("Authorization = %q", gotAuth)
		}
	})

	t.Run("response_format off omits the field", func(t *testing.T) {
		c := newClient(srv, func(cfg *openaicompat.Config) { cfg.ResponseFormat = "off" })
		if _, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
			t.Fatal(err)
		}
		if _, present := gotBody["response_format"]; present {
			t.Error("response_format must be omitted when off")
		}
	})

	t.Run("thinking true is passed through", func(t *testing.T) {
		c := newClient(srv, func(cfg *openaicompat.Config) { cfg.Thinking = true })
		if _, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
			t.Fatal(err)
		}
		kw, ok := gotBody["chat_template_kwargs"].(map[string]any)
		if !ok {
			t.Fatalf("chat_template_kwargs is not an object: %v", gotBody["chat_template_kwargs"])
		}
		if kw["enable_thinking"] != true {
			t.Errorf("enable_thinking = %v, want true", kw["enable_thinking"])
		}
	})

	t.Run("prefix+suffix joined; CachePrefix changes nothing", func(t *testing.T) {
		c := newClient(srv, nil)
		p := llm.Prompt{Prefix: "call-1 prompt", Suffix: "\n\ncontinuation", CachePrefix: true}
		if _, err := c.Complete(context.Background(), "s", p, []string{"k"}); err != nil {
			t.Fatal(err)
		}
		msgs, ok := gotBody["messages"].([]any)
		if !ok || len(msgs) != 2 {
			t.Fatalf("want [system,user] messages, got %v", gotBody["messages"])
		}
		usr, ok := msgs[1].(map[string]any)
		if !ok {
			t.Fatalf("user message is not an object: %v", msgs[1])
		}
		if usr["content"] != "call-1 prompt\n\ncontinuation" {
			t.Errorf("user content = %q", usr["content"])
		}
	})
}

func TestMarkdownFenceStripped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBody("```json\n{\"k\":1}\n```", 1, 1)))
	}))
	defer srv.Close()
	comp, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err != nil {
		t.Fatal(err)
	}
	if string(comp.Raw) != `{"k":1}` {
		t.Errorf("Raw = %s", comp.Raw)
	}
}

// chatBodyFull builds a success body with reasoning_content and finish_reason
// under the caller's control.
func chatBodyFull(content, reasoning, finishReason string) string {
	msg := map[string]any{"content": content}
	if reasoning != "" {
		msg["reasoning_content"] = reasoning
	}
	payload := map[string]any{
		"choices": []map[string]any{
			{"message": msg, "finish_reason": finishReason},
		},
		"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5},
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return "{}"
	}
	return string(b)
}

func TestReasoningContentIgnored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBodyFull(`{"k":1}`, "long chain of thought that is not JSON", "stop")))
	}))
	defer srv.Close()
	comp, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err != nil {
		t.Fatalf("reasoning_content sibling must not interfere: %v", err)
	}
	if string(comp.Raw) != `{"k":1}` {
		t.Errorf("Raw = %s", comp.Raw)
	}
}

func TestLeadingThinkBlockStripped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBodyFull("  <think>hmm, disk\nor network?</think>\n{\"k\":1}", "", "stop")))
	}))
	defer srv.Close()
	comp, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err != nil {
		t.Fatalf("leading think block must be stripped: %v", err)
	}
	if string(comp.Raw) != `{"k":1}` {
		t.Errorf("Raw = %s", comp.Raw)
	}
}

func TestStackedThinkBlocksStripped(t *testing.T) {
	// Sequential and nested leading blocks are still reasoning leakage — a
	// single-block strip would leave debris that fails the JSON parse outright
	// instead of degrading to the reply.
	for name, content := range map[string]string{
		"sequential": "<think>plan a</think>\n<think>plan b</think>\n{\"k\":1}",
		"nested":     "<think>compare <think>host overlap?</think> no</think>{\"k\":1}",
		"both":       " <think>a<think>b</think>c</think> <think>d</think>\n{\"k\":1}",
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(chatBodyFull(content, "", "stop")))
			}))
			defer srv.Close()
			comp, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
			if err != nil {
				t.Fatalf("stacked think blocks must be stripped: %v", err)
			}
			if string(comp.Raw) != `{"k":1}` {
				t.Errorf("Raw = %s", comp.Raw)
			}
		})
	}
}

func TestUnclosedThinkBlockLeftAlone(t *testing.T) {
	// An unclosed leading <think> means the reply is unusable either way; the
	// stripper leaves it untouched and the JSON parse reports it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBodyFull(`<think>never closed {"k":1}`, "", "stop")))
	}))
	defer srv.Close()
	_, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err == nil || !strings.Contains(err.Error(), "not valid JSON") {
		t.Fatalf("want not-valid-JSON error, got %v", err)
	}
}

func TestNonLeadingThinkLeftAlone(t *testing.T) {
	// A <think> inside a JSON string value is model output, not leakage —
	// the strip must not touch it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBodyFull(`{"k":"the tag <think>x</think> appears in a log line"}`, "", "stop")))
	}))
	defer srv.Close()
	comp, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(comp.Raw), "<think>x</think>") {
		t.Errorf("non-leading think must survive: %s", comp.Raw)
	}
}

func TestFinishReasonLengthIsTruncationError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBodyFull(`{"k":"cut of`, "", "length")))
	}))
	defer srv.Close()
	_, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if !errors.Is(err, llm.ErrResponseTruncated) {
		t.Fatalf("want ErrResponseTruncated, got %v", err)
	}
	if !strings.Contains(err.Error(), "raise llm.max_tokens") {
		t.Errorf("truncation error must be actionable: %v", err)
	}
}

func TestRequiredKeyMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBody(`{"other":1}`, 1, 1)))
	}))
	defer srv.Close()
	_, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"overall_issue"})
	if !errors.Is(err, llm.ErrSchemaViolation) {
		t.Fatalf("want ErrSchemaViolation, got %v", err)
	}
}

func TestRetryOn429ThenSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = w.Write([]byte(chatBody(`{"k":1}`, 1, 1)))
	}))
	defer srv.Close()
	c := newClient(srv, func(cfg *openaicompat.Config) { cfg.BaseRetryDelay = time.Millisecond })
	if _, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatalf("429 then success must succeed: %v", err)
	}
	if calls.Load() != 2 {
		t.Errorf("calls = %d, want 2", calls.Load())
	}
}

func TestRetryOn503ThenSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable) // vLLM/SGLang queue full
			return
		}
		_, _ = w.Write([]byte(chatBody(`{"k":1}`, 1, 1)))
	}))
	defer srv.Close()
	c := newClient(srv, func(cfg *openaicompat.Config) { cfg.BaseRetryDelay = time.Millisecond })
	if _, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatalf("503 then success must succeed: %v", err)
	}
}

func TestRetriesExhaustedOnPersistent500(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	c := newClient(srv, func(cfg *openaicompat.Config) { cfg.BaseRetryDelay = time.Millisecond })
	_, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	var retryErr *llm.RetryableError
	if !errors.As(err, &retryErr) || retryErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("want RetryableError{500} after exhaustion, got %v", err)
	}
	if calls.Load() != 3 { // initial + MaxRetries(2)
		t.Errorf("calls = %d, want 3", calls.Load())
	}
}

func TestBadRequestImmediateWithExcerpt(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"unknown model qwen99"}}`))
	}))
	defer srv.Close()
	_, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400") || !strings.Contains(err.Error(), "unknown model qwen99") {
		t.Fatalf("400 must surface immediately with body excerpt, got: %v", err)
	}
	if calls.Load() != 1 {
		t.Errorf("400 must not be retried, calls = %d", calls.Load())
	}
}

func TestResponseFormat400CarriesHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"response_format is not supported"}}`))
	}))
	defer srv.Close()
	_, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err == nil || !strings.Contains(err.Error(), `set llm.response_format: "off"`) {
		t.Fatalf("400 mentioning response_format must carry the config hint, got: %v", err)
	}
}

// TestNonJSON200CarriesResponseFormatHint: a runtime that silently ignores
// response_format and returns 200 with plain prose must surface the same
// actionable hint as the 400 path -- not just a bare "not valid JSON".
func TestNonJSON200CarriesResponseFormatHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBody("sure, here is the disk usage summary you asked for", 5, 5)))
	}))
	defer srv.Close()
	_, err := newClient(srv, nil).Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err == nil || !strings.Contains(err.Error(), `set llm.response_format: "off"`) {
		t.Fatalf("200 with non-JSON content and response_format!=off must carry the config hint, got: %v", err)
	}
}

// TestNonJSON200OmitsHintWhenResponseFormatOff: with response_format already
// off, the hint would be nonsensical (it points at the very knob already set) --
// omit it.
func TestNonJSON200OmitsHintWhenResponseFormatOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBody("not json at all", 5, 5)))
	}))
	defer srv.Close()
	c := newClient(srv, func(cfg *openaicompat.Config) { cfg.ResponseFormat = "off" })
	_, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err == nil {
		t.Fatal("want error for non-JSON content")
	}
	if strings.Contains(err.Error(), "response_format") {
		t.Errorf("response_format already off: hint must not be appended, got: %v", err)
	}
}

func TestTimeoutHonored(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		_, _ = w.Write([]byte(chatBody(`{"k":1}`, 1, 1)))
	}))
	defer srv.Close()
	c := newClient(srv, func(cfg *openaicompat.Config) { cfg.TimeoutSeconds = 1 })
	start := time.Now()
	_, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"})
	if err == nil {
		t.Fatal("want timeout error")
	}
	if elapsed := time.Since(start); elapsed > 1900*time.Millisecond {
		t.Errorf("timeout not honored, took %v", elapsed)
	}
}

// TestConfigDefaultsApplied locks the fallback branches in Config.defaults():
// a Config that leaves MaxTokens/TimeoutSeconds unset (the zero value) must
// still get the documented 1024/120 defaults. cmd/alertint's
// buildClassifierClient deliberately passes MaxTokens: 0 on the
// openai-compatible path to trigger this exact fallback.
func TestConfigDefaultsApplied(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = w.Write([]byte(chatBody(`{"k":1}`, 1, 1)))
	}))
	defer srv.Close()

	c := openaicompat.New(openaicompat.Config{BaseURL: srv.URL, Model: "m"}, nil, nil)
	if _, err := c.Complete(context.Background(), "s", llm.Prompt{Prefix: "p"}, []string{"k"}); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if gotBody["max_tokens"] != float64(1024) {
		t.Errorf("max_tokens = %v, want default 1024", gotBody["max_tokens"])
	}
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

// countAuditRows counts audit_log rows by kind.
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

// TestAuditRowsWritten mirrors internal/llm/anthropic's test of the same
// name: llm.request and llm.response rows must be appended to the audit log
// on a successful call, under the "llm.openaicompat" actor.
func TestAuditRowsWritten(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(chatBody(`{"ok":true}`, 5, 8)))
	}))
	defer srv.Close()

	st := newTestStore(t)
	auditor := audit.New(st.DB())
	c := openaicompat.New(openaicompat.Config{
		BaseURL:        srv.URL,
		Model:          "qwen3-32b",
		MaxTokens:      4096,
		ResponseFormat: "json_object",
		TimeoutSeconds: 5,
	}, auditor, nil)

	ctx := context.Background()
	if _, err := c.Complete(ctx, "sys", llm.Prompt{Prefix: "user"}, []string{"ok"}); err != nil {
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
