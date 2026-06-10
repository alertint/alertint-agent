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
	// DefaultModel is used when Config.Model is empty.
	DefaultModel = "claude-haiku-4-5-20251001"

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
		http:     &http.Client{Timeout: 120 * time.Second},
		auditor:  auditor,
		logger:   logger,
		now:      func() time.Time { return time.Now().UTC() },
		endpoint: endpoint,
	}
}

// Complete sends systemPrompt + userPrompt to the model and returns the
// raw JSON extracted from the assistant's first text content block.
//
// requiredKeys is a list of top-level JSON keys that must be present in
// the parsed response object. If any key is missing, ErrSchemaViolation
// is returned along with the raw response for debugging.
//
// The caller is responsible for unmarshaling the returned json.RawMessage
// into their target type.
func (c *Client) Complete(
	ctx context.Context,
	systemPrompt, userPrompt string,
	requiredKeys []string,
) (json.RawMessage, error) {
	start := c.now()

	reqHash := promptHash(systemPrompt, userPrompt)
	if c.auditor != nil {
		_ = c.auditor.Append(ctx, "llm.anthropic", "llm.request", map[string]any{
			"model":       c.cfg.Model,
			"prompt_hash": reqHash,
		})
	}

	raw, inputTokens, outputTokens, err := c.callWithRetry(ctx, systemPrompt, userPrompt)
	latencyMs := c.now().Sub(start).Milliseconds()

	if c.auditor != nil {
		payload := map[string]any{
			"model":         c.cfg.Model,
			"prompt_hash":   reqHash,
			"latency_ms":    latencyMs,
			"input_tokens":  inputTokens,
			"output_tokens": outputTokens,
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		_ = c.auditor.Append(ctx, "llm.anthropic", "llm.response", payload)
	}

	if err != nil {
		return nil, err
	}

	if err := validateKeys(raw, requiredKeys); err != nil {
		return raw, err
	}
	return raw, nil
}

// ----------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------

// messagesRequest is the body sent to POST /v1/messages.
type messagesRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []message `json:"messages"`
}

type message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// messagesResponse is the relevant subset of the Anthropic response.
type messagesResponse struct {
	Content []contentBlock `json:"content"`
	Usage   struct {
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
func (c *Client) callWithRetry(ctx context.Context, system, user string) (raw json.RawMessage, inputTok, outputTok int, err error) {
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
		raw, inputTok, outputTok, err = c.doRequest(ctx, system, user)
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
func (c *Client) doRequest(ctx context.Context, system, user string) (json.RawMessage, int, int, error) {
	body := messagesRequest{
		Model:     c.cfg.Model,
		MaxTokens: c.cfg.MaxTokens,
		System:    system,
		Messages:  []message{{Role: "user", Content: user}},
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

// RetryableError wraps an HTTP status code that warrants a retry.
type RetryableError struct {
	StatusCode int
}

func (e *RetryableError) Error() string {
	return fmt.Sprintf("llm: retryable HTTP %d", e.StatusCode)
}
