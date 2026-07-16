// SPDX-License-Identifier: FSL-1.1-ALv2

// Package anthropic provides a minimal client for the Anthropic Messages
// API (https://docs.anthropic.com/en/api/messages).
//
// Design constraints (Slice 06):
//   - Single-shot, non-streaming: one request → one structured JSON response.
//   - Caller supplies a system prompt, a user prompt, and a list of required
//     top-level JSON keys that must appear in the model's reply. The client
//     enforces this contract so callers never get silently partial output.
//   - Exponential-backoff retry on 429/529 (rate-limit / overloaded) up to
//     MaxRetries attempts. Any other 4xx or 5xx is returned immediately.
//   - Audit: two rows appended per successful call:
//     kind=llm.request  – prompt hash (SHA-256), model, no prompt body
//     kind=llm.response – token counts, latency_ms
//   - The API key is passed in at construction time; callers read it from
//     the environment (config.LLMConfig.APIKeyEnv).
package anthropic

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
)

const (
	// DefaultModel is used when Config.Model is empty. Sonnet is the default
	// so the first finding is built by the strongest reasoning tier the price
	// class allows; claude-haiku-4-5 remains a one-line config opt-in for cost.
	DefaultModel = "claude-sonnet-5"

	// messagesEndpoint is the Anthropic Messages API URL.
	messagesEndpoint = "https://api.anthropic.com/v1/messages"

	// anthropicVersion is the API version header value required by Anthropic.
	anthropicVersion = "2023-06-01"

	// MaxRetries is the maximum number of retry attempts on 429/529.
	MaxRetries = 2

	// maxResponseBytes caps the response body read to avoid runaway reads.
	maxResponseBytes = 512 * 1024 // 512 KiB
)

// Config holds tunables for the Anthropic client.
type Config struct {
	// APIKey is the Anthropic API key. Required.
	APIKey string
	// Model defaults to DefaultModel when empty.
	Model string
	// MaxTokens is the ceiling passed to the API. Defaults to 1024.
	MaxTokens int
	// BaseRetryDelay is the initial backoff before the first retry.
	// Defaults to 1 second. Tests may set this much smaller.
	BaseRetryDelay time.Duration
	// TimeoutSeconds is the whole-request HTTP timeout. Defaults to 120 (the
	// value the triage client hardcoded before the shadow classifier needed a
	// seconds-scale budget on a second client — see ADR-0018).
	TimeoutSeconds int
}

func (c *Config) defaults() {
	if c.Model == "" {
		c.Model = DefaultModel
	}
	if c.MaxTokens <= 0 {
		c.MaxTokens = 1024
	}
	if c.BaseRetryDelay <= 0 {
		c.BaseRetryDelay = time.Second
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = 120
	}
}

// Client calls the Anthropic Messages API.
type Client struct {
	cfg      Config
	http     *http.Client
	auditor  *audit.Auditor
	logger   *slog.Logger
	now      func() time.Time
	endpoint string // overridden in tests via NewWithHTTPClient
}

// New constructs a Client. auditor and logger may be nil (no-ops).
func New(cfg Config, auditor *audit.Auditor, logger *slog.Logger) *Client {
	return NewWithHTTPClient(cfg, auditor, logger, "")
}

// NewWithHTTPClient constructs a Client with a custom base URL. When
// baseURL is non-empty it overrides messagesEndpoint; this is used in
// tests to point at an httptest.Server.
func NewWithHTTPClient(cfg Config, auditor *audit.Auditor, logger *slog.Logger, baseURL string) *Client {
	cfg.defaults()
	if logger == nil {
		logger = slog.Default()
	}
	endpoint := messagesEndpoint
	if baseURL != "" {
		endpoint = baseURL + "/v1/messages"
	}
	return &Client{
		cfg:      cfg,
		http:     &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
		auditor:  auditor,
		logger:   logger,
		now:      func() time.Time { return time.Now().UTC() },
		endpoint: endpoint,
	}
}

// Completion is the result of a Complete call: the validated raw JSON plus the
// usage figures the client already computes for the audit log. Returning them
// (rather than discarding them) lets the incident-aware caller emit an "llm
// responded" action-trail line without re-deriving anything — see ADR 0004.
type Completion struct {
	Raw          json.RawMessage // validated model JSON (nil on error)
	Model        string          // the model that served the request
	InputTokens  int
	OutputTokens int
	Latency      time.Duration
}

// Prompt is the user-turn payload of a Complete call. Prefix is always set;
// Suffix is the verification round's call-2 continuation (empty on a
// single-call prompt). CachePrefix marks the end of Prefix as a prompt-cache
// breakpoint — set it only when a follow-up call reusing Prefix verbatim is
// guaranteed (the verification pair), otherwise the cache write premium is
// paid with no matching read.
type Prompt struct {
	Prefix      string
	Suffix      string
	CachePrefix bool
}

// text is the full user-turn text, prefix and suffix joined.
func (p Prompt) text() string { return p.Prefix + p.Suffix }

// Complete sends systemPrompt + prompt to the model and returns a
// Completion whose Raw is the JSON extracted from the assistant's first text
// content block, alongside the model, token usage, and latency.
//
// requiredKeys is a list of top-level JSON keys that must be present in
// the parsed response object. If any key is missing, ErrSchemaViolation
// is returned along with the raw response for debugging.
//
// The caller is responsible for unmarshaling Completion.Raw into their target
// type.
func (c *Client) Complete(
	ctx context.Context,
	systemPrompt string, prompt Prompt,
	requiredKeys []string,
) (Completion, error) {
	start := c.now()

	reqHash := promptHash(systemPrompt, prompt.text())
	if c.auditor != nil {
		_ = c.auditor.Append(ctx, "llm.anthropic", "llm.request", map[string]any{
			"model":       c.cfg.Model,
			"prompt_hash": reqHash,
		})
	}

	raw, inputTokens, outputTokens, err := c.callWithRetry(ctx, systemPrompt, prompt)
	latency := c.now().Sub(start)

	if c.auditor != nil {
		payload := map[string]any{
			"model":         c.cfg.Model,
			"prompt_hash":   reqHash,
			"latency_ms":    latency.Milliseconds(),
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		_ = c.auditor.Append(ctx, "llm.anthropic", "llm.response", payload)
	}

	comp := Completion{
		Raw:          raw,
		Model:        c.cfg.Model,
		InputTokens:  inputTokens,
		OutputTokens: outputTokens,
		Latency:      latency,
	}
	if err != nil {
		return comp, err
	}
	if err := validateKeys(raw, requiredKeys); err != nil {
		return comp, err
	}
	return comp, nil
}

// ----------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------

// messagesRequest is the body sent to POST /v1/messages.
type messagesRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  []message       `json:"messages"`
	Thinking  *thinkingConfig `json:"thinking,omitempty"`
}

// thinkingConfig is the extended-thinking selector on the Messages API.
// Triage is a single-shot JSON extraction, so thinking is always disabled
// explicitly: on models where an omitted thinking field means "adaptive
// thinking on" (claude-sonnet-5 and newer), thinking output would count
// against MaxTokens and truncate the required-keys JSON reply.
type thinkingConfig struct {
	Type string `json:"type"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// messagesResponse is the relevant subset of the Anthropic response.
type messagesResponse struct {
	Content    []contentBlock `json:"content"`
	StopReason string         `json:"stop_reason"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
	Error *apiError `json:"error,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type apiError struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// callWithRetry executes the HTTP request, retrying on 429/529 with
// exponential backoff up to MaxRetries times.
func (c *Client) callWithRetry(ctx context.Context, system string, prompt Prompt) (raw json.RawMessage, inputTok, outputTok int, err error) {
	delay := c.cfg.BaseRetryDelay
	for attempt := 0; attempt <= MaxRetries; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, 0, 0, ctx.Err()
			}
			delay *= 2
		}
		raw, inputTok, outputTok, err = c.doRequest(ctx, system, prompt)
		if err == nil {
			return raw, inputTok, outputTok, nil
		}
		var retryErr *RetryableError
		if errors.As(err, &retryErr) && attempt < MaxRetries {
			c.logger.Warn("llm: retryable error, backing off",
				"attempt", attempt+1,
				"status", retryErr.StatusCode,
				"delay", delay,
			)
			continue
		}
		return nil, 0, 0, err
	}
	return nil, 0, 0, err
}

// doRequest performs a single HTTP call to the Messages API.
func (c *Client) doRequest(ctx context.Context, system string, prompt Prompt) (json.RawMessage, int, int, error) {
	body := messagesRequest{
		Model:     c.cfg.Model,
		MaxTokens: c.cfg.MaxTokens,
		System:    system,
		Messages:  []message{{Role: "user", Content: prompt.text()}},
		Thinking:  &thinkingConfig{Type: "disabled"},
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("llm: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Api-Key", c.cfg.APIKey)
	req.Header.Set("Anthropic-Version", anthropicVersion)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("llm: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("llm: read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == 529 {
		return nil, 0, 0, &RetryableError{StatusCode: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		var apiErr messagesResponse
		_ = json.Unmarshal(respBody, &apiErr)
		msg := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if apiErr.Error != nil {
			msg = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, apiErr.Error.Message)
		}
		return nil, 0, 0, fmt.Errorf("llm: api error: %s", msg)
	}

	var parsed messagesResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, 0, 0, fmt.Errorf("llm: parse response: %w", err)
	}

	// A max_tokens stop means the reply was cut off at the output ceiling: the
	// text is incomplete JSON. Surface it as an actionable truncation error
	// rather than the raw, misleading "not valid JSON" the parse below would
	// give — the fix is to raise llm.max_tokens, not to retry (which truncates
	// identically), so this is returned immediately, not as a RetryableError.
	if parsed.StopReason == "max_tokens" {
		return nil, parsed.Usage.InputTokens, parsed.Usage.OutputTokens,
			fmt.Errorf("%w=%d (raise llm.max_tokens)", ErrResponseTruncated, c.cfg.MaxTokens)
	}

	text := firstTextBlock(parsed.Content)
	if text == "" {
		return nil, parsed.Usage.InputTokens, parsed.Usage.OutputTokens,
			errors.New("llm: response contained no text content block")
	}

	// The model should return raw JSON. Trim any markdown fences.
	text = stripMarkdownFence(text)

	var raw json.RawMessage
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		return nil, parsed.Usage.InputTokens, parsed.Usage.OutputTokens,
			fmt.Errorf("llm: response is not valid JSON: %w", err)
	}
	return raw, parsed.Usage.InputTokens, parsed.Usage.OutputTokens, nil
}

// firstTextBlock returns the text of the first content block with type "text".
func firstTextBlock(blocks []contentBlock) string {
	for _, b := range blocks {
		if b.Type == "text" {
			return b.Text
		}
	}
	return ""
}

// stripMarkdownFence removes ```json ... ``` wrappers if present.
func stripMarkdownFence(s string) string {
	// Trim leading/trailing whitespace first.
	trimmed := bytes.TrimSpace([]byte(s))
	prefixes := [][]byte{[]byte("```json"), []byte("```")}
	suffix := []byte("```")
	for _, p := range prefixes {
		if bytes.HasPrefix(trimmed, p) {
			inner := bytes.TrimPrefix(trimmed, p)
			inner = bytes.TrimSuffix(bytes.TrimSpace(inner), suffix)
			return string(bytes.TrimSpace(inner))
		}
	}
	return string(trimmed)
}

// validateKeys checks that every key in required appears at the top level
// of the JSON object raw. Returns ErrSchemaViolation if any are missing.
func validateKeys(raw json.RawMessage, required []string) error {
	if len(required) == 0 {
		return nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("%w: response is not a JSON object", ErrSchemaViolation)
	}
	var missing []string
	for _, k := range required {
		if _, ok := obj[k]; !ok {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%w: missing keys %v", ErrSchemaViolation, missing)
	}
	return nil
}

// promptHash returns a hex-encoded SHA-256 of the concatenated prompts.
// Used in audit rows so the prompt content is never stored in the DB.
func promptHash(system, user string) string {
	h := sha256.New()
	h.Write([]byte(system))
	h.Write([]byte{0x1f}) // ASCII unit separator
	h.Write([]byte(user))
	return hex.EncodeToString(h.Sum(nil))
}

// ----------------------------------------------------------------------
// Sentinel errors
// ----------------------------------------------------------------------

// ErrSchemaViolation is returned when the model's JSON response is
// missing one or more required top-level keys.
var ErrSchemaViolation = errors.New("llm: schema violation")

// ErrResponseTruncated is returned when the model stopped at the output-token
// ceiling (stop_reason=max_tokens), leaving the JSON reply incomplete. The
// remedy is to raise llm.max_tokens; retrying reproduces the same truncation.
var ErrResponseTruncated = errors.New("llm: response truncated at max_tokens")

// RetryableError wraps an HTTP status code that warrants a retry.
type RetryableError struct {
	StatusCode int
}

func (e *RetryableError) Error() string {
	return fmt.Sprintf("llm: retryable HTTP %d", e.StatusCode)
}
