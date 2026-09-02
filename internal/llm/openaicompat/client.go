// SPDX-License-Identifier: FSL-1.1-ALv2

// Package openaicompat is a minimal client for self-hosted OpenAI-compatible
// chat-completions endpoints (SGLang, vLLM, Ollama, LM Studio) — see
// ADR-0026. It mirrors internal/llm/anthropic's surface and contract:
// single-shot, non-streaming, required-JSON-keys enforcement, two audit rows
// per call. Differences from the anthropic client, all deliberate:
//   - Wire format: POST {base_url}/v1/chat/completions, Bearer auth (only
//     when a key is configured — local endpoints are often unauthenticated).
//   - No client-side prompt caching: Prompt.CachePrefix is ignored; cache
//     usage fields are always zero (SGLang/vLLM prefix-cache server-side).
//   - Reasoning defense: a reasoning_content sibling field is never read,
//     one leading <think>…</think> block is stripped, and every request
//     pins chat_template_kwargs {"enable_thinking": <cfg.Thinking>} — except
//     against hosted OpenAI (api.openai.com), which rejects the field as an
//     unrecognized request argument; the leading-<think> strip still applies.
//   - Retries: 429 plus any 5xx (local runtimes signal transient overload /
//     loading / respawn with generic 500/503, unlike Anthropic's 529).
package openaicompat

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/llm"
)

const (
	// MaxRetries is the maximum number of retry attempts on 429/5xx.
	MaxRetries = 2

	// maxResponseBytes caps the response body read to avoid runaway reads.
	maxResponseBytes = 512 * 1024 // 512 KiB

	// maxErrorBodyExcerpt bounds how much of a non-2xx body lands in the
	// returned error text.
	maxErrorBodyExcerpt = 512
)

// responseFormatHint is appended to a 400 whose body mentions
// response_format — the actionable fix, not just the failure.
const responseFormatHint = `set llm.response_format: "off" if your runtime does not support enforced JSON output`

// Config holds tunables for the openai-compatible client.
type Config struct {
	// BaseURL is the endpoint root, already normalized by internal/config
	// (no trailing slash or /v1). Required.
	BaseURL string
	// APIKey is optional: empty means no Authorization header.
	APIKey string
	// Model is the model name the endpoint serves. Required (no default —
	// there is no universal local model name).
	Model string
	// MaxTokens is the completion-token ceiling. Defaults to 1024.
	MaxTokens int
	// ResponseFormat is "json_object" (send response_format) or "off" (omit).
	ResponseFormat string
	// Thinking is the value sent as chat_template_kwargs.enable_thinking.
	Thinking bool
	// ReasoningEffort, when non-empty, is sent as
	// chat_template_kwargs.reasoning_effort alongside enable_thinking.
	// Model-specific vocabulary (e.g. Qwen3.8: "xhigh", "medium", "low") —
	// passed through as-is, no value validation here.
	ReasoningEffort string
	// BaseRetryDelay is the initial backoff before the first retry.
	// Defaults to 1 second. Tests may set this much smaller.
	BaseRetryDelay time.Duration
	// TimeoutSeconds is the whole-request HTTP timeout. Defaults to 120.
	TimeoutSeconds int
}

func (c *Config) defaults() {
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

// Client calls an OpenAI-compatible chat-completions API.
type Client struct {
	cfg      Config
	http     *http.Client
	auditor  *audit.Auditor
	logger   *slog.Logger
	now      func() time.Time
	endpoint string
	// pinChatTemplateKwargs sends the enable_thinking pin. Off for hosted
	// OpenAI, which 400s on the unrecognized field; its models have no
	// chat-template thinking toggle to pin anyway.
	pinChatTemplateKwargs bool
	// hosted marks the endpoint as hosted OpenAI: Probe uses the model-
	// metadata route instead of the generic health/models routes.
	hosted bool
}

// New constructs a Client. auditor and logger may be nil (no-ops).
func New(cfg Config, auditor *audit.Auditor, logger *slog.Logger) *Client {
	cfg.defaults()
	if logger == nil {
		logger = slog.Default()
	}
	return &Client{
		cfg:      cfg,
		http:     &http.Client{Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second},
		auditor:  auditor,
		logger:   logger,
		now:      func() time.Time { return time.Now().UTC() },
		endpoint: cfg.BaseURL + "/v1/chat/completions",

		pinChatTemplateKwargs: !isHostedOpenAI(cfg.BaseURL),
		hosted:                isHostedOpenAI(cfg.BaseURL),
	}
}

// isHostedOpenAI reports whether baseURL points at the hosted OpenAI API.
// BaseURL arrives normalized by internal/config (scheme + host, no trailing
// slash or /v1), so a parse failure just means "not hosted OpenAI".
func isHostedOpenAI(baseURL string) bool {
	u, err := url.Parse(baseURL)
	if err != nil {
		return false
	}
	return strings.EqualFold(u.Hostname(), "api.openai.com")
}

// Complete sends systemPrompt + prompt and returns a llm.Completion whose Raw
// is the JSON extracted from choices[0].message.content. Prompt.CachePrefix
// is ignored on this wire format. requiredKeys works exactly as on the
// anthropic client (llm.ErrSchemaViolation on a miss).
func (c *Client) Complete(
	ctx context.Context,
	systemPrompt string, prompt llm.Prompt,
	requiredKeys []string,
) (llm.Completion, error) {
	start := c.now()

	reqHash := llm.PromptHash(systemPrompt, prompt.Text())
	if c.auditor != nil {
		_ = c.auditor.Append(ctx, "llm.openaicompat", "llm.request", map[string]any{
			"model":       c.cfg.Model,
			"prompt_hash": reqHash,
		})
	}

	raw, usage, err := c.callWithRetry(ctx, systemPrompt, prompt, MaxRetries)
	latency := c.now().Sub(start)

	if c.auditor != nil {
		payload := map[string]any{
			"model":         c.cfg.Model,
			"prompt_hash":   reqHash,
			"latency_ms":    latency.Milliseconds(),
			"input_tokens":  usage.input,
			"output_tokens": usage.output,
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		_ = c.auditor.Append(ctx, "llm.openaicompat", "llm.response", payload)
	}

	comp := llm.Completion{
		Raw:          raw,
		Model:        c.cfg.Model,
		InputTokens:  usage.input,
		OutputTokens: usage.output,
		Latency:      latency,
	}
	if err != nil {
		return comp, err
	}
	if err := llm.ValidateKeys(raw, requiredKeys); err != nil {
		return comp, err
	}
	return comp, nil
}

// CompleteOnce is Complete's one-shot counterpart, for callers that must
// bypass the client's hidden HTTP retry loop without changing Complete's own
// shipped retry behavior (Plan 2's Situation controller — see
// internal/llm/anthropic's CompleteOnce doc comment for the full rationale,
// identical here). It shares doRequest/callWithRetry with Complete, calling
// callWithRetry with maxRetries=0, and classifies the outcome into
// RequestStartStatus via llm.ClassifyRequestStart.
func (c *Client) CompleteOnce(
	ctx context.Context,
	systemPrompt string, prompt llm.Prompt,
	requiredKeys []string,
) (llm.OneShotCompletion, error) {
	start := c.now()

	reqHash := llm.PromptHash(systemPrompt, prompt.Text())
	if c.auditor != nil {
		_ = c.auditor.Append(ctx, "llm.openaicompat", "llm.request", map[string]any{
			"model":       c.cfg.Model,
			"prompt_hash": reqHash,
		})
	}

	raw, usage, err := c.callWithRetry(ctx, systemPrompt, prompt, 0)
	latency := c.now().Sub(start)

	if c.auditor != nil {
		payload := map[string]any{
			"model":         c.cfg.Model,
			"prompt_hash":   reqHash,
			"latency_ms":    latency.Milliseconds(),
			"input_tokens":  usage.input,
			"output_tokens": usage.output,
		}
		if err != nil {
			payload["error"] = err.Error()
		}
		_ = c.auditor.Append(ctx, "llm.openaicompat", "llm.response", payload)
	}

	comp := llm.OneShotCompletion{
		Completion: llm.Completion{
			Raw:          raw,
			Model:        c.cfg.Model,
			InputTokens:  usage.input,
			OutputTokens: usage.output,
			Latency:      latency,
		},
		RequestStarted: llm.ClassifyRequestStart(err),
	}
	if err != nil {
		return comp, err
	}
	if err := llm.ValidateKeys(raw, requiredKeys); err != nil {
		return comp, err
	}
	return comp, nil
}

// ----------------------------------------------------------------------
// Internal helpers
// ----------------------------------------------------------------------

// chatRequest is the body sent to POST /v1/chat/completions.
type chatRequest struct {
	Model              string          `json:"model"`
	MaxTokens          int             `json:"max_tokens"`
	Messages           []chatMessage   `json:"messages"`
	ResponseFormat     *responseFormat `json:"response_format,omitempty"`
	ChatTemplateKwargs map[string]any  `json:"chat_template_kwargs,omitempty"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type responseFormat struct {
	Type string `json:"type"` // always "json_object"
}

// chatResponse is the relevant subset of the OpenAI-format response.
// A reasoning_content sibling of content (SGLang/vLLM reasoning parsers) is
// deliberately not modeled: the payload is content, nothing else.
type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// tokenUsage is the per-call usage subset the client reports onward.
type tokenUsage struct {
	input, output int
}

// callWithRetry executes the HTTP request through the shared llm.CallWithRetry
// backoff loop, retrying on 429 and any 5xx (wrapped by doRequest as
// llm.RetryableError) up to maxRetries times. Complete calls this with
// MaxRetries; CompleteOnce calls it with 0 — see anthropic's callWithRetry
// doc comment for the shared rationale.
func (c *Client) callWithRetry(ctx context.Context, system string, prompt llm.Prompt, maxRetries int) (json.RawMessage, tokenUsage, error) {
	return llm.CallWithRetry(ctx, c.logger, maxRetries, c.cfg.BaseRetryDelay,
		func(ctx context.Context) (json.RawMessage, tokenUsage, error) {
			return c.doRequest(ctx, system, prompt)
		})
}

// doRequest performs a single HTTP call to the chat-completions API.
func (c *Client) doRequest(ctx context.Context, system string, prompt llm.Prompt) (json.RawMessage, tokenUsage, error) {
	maxTokens := prompt.OutputTokenLimit(c.cfg.MaxTokens)
	body := chatRequest{
		Model:     c.cfg.Model,
		MaxTokens: maxTokens,
		Messages: []chatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: prompt.Text()},
		},
	}
	if c.pinChatTemplateKwargs {
		body.ChatTemplateKwargs = map[string]any{"enable_thinking": c.cfg.Thinking}
		if c.cfg.ReasoningEffort != "" {
			body.ChatTemplateKwargs["reasoning_effort"] = c.cfg.ReasoningEffort
		}
	}
	if c.cfg.ResponseFormat != "off" {
		body.ResponseFormat = &responseFormat{Type: "json_object"}
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, tokenUsage{}, fmt.Errorf("%w: marshal request: %w", llm.ErrRequestNotSent, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(encoded))
	if err != nil {
		return nil, tokenUsage{}, fmt.Errorf("%w: build request: %w", llm.ErrRequestNotSent, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, tokenUsage{}, fmt.Errorf("llm: http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, tokenUsage{}, fmt.Errorf("llm: read response: %w", err)
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
		return nil, tokenUsage{}, &llm.RetryableError{StatusCode: resp.StatusCode}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, tokenUsage{}, apiError(resp.StatusCode, respBody)
	}

	var parsed chatResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, tokenUsage{}, fmt.Errorf("%w: parse response: %w", llm.ErrResponseInvalid, err)
	}
	usage := tokenUsage{
		input:  parsed.Usage.PromptTokens,
		output: parsed.Usage.CompletionTokens,
	}
	if len(parsed.Choices) == 0 {
		return nil, usage, fmt.Errorf("%w: response contained no choices", llm.ErrResponseInvalid)
	}
	choice := parsed.Choices[0]

	// A length finish means the reply was cut off at the completion-token
	// ceiling: the text is incomplete JSON. Surface it as an actionable
	// truncation error rather than the misleading "not valid JSON" — the fix
	// is to raise llm.max_tokens (or disable llm.thinking), not to retry. When
	// the ceiling came from an explicit per-call Prompt.MaxOutputTokens (e.g. a
	// deliberately bounded repair call), the operator's configured
	// llm.max_tokens is not the cause — report the per-call cap instead so the
	// truncation is not misdiagnosed as an operator misconfiguration.
	if choice.FinishReason == "length" {
		hint := "raise llm.max_tokens"
		if prompt.MaxOutputTokens != 0 {
			hint = "per-call max_output_tokens"
		}
		return nil, usage, fmt.Errorf("%w=%d (%s)", llm.ErrResponseTruncated, maxTokens, hint)
	}

	text := stripLeadingThink(choice.Message.Content)
	if text == "" {
		return nil, usage, fmt.Errorf("%w: response contained no text content", llm.ErrResponseInvalid)
	}
	text = llm.StripMarkdownFence(text)

	var raw json.RawMessage
	if err := json.Unmarshal([]byte(text), &raw); err != nil {
		if c.cfg.ResponseFormat != "off" {
			return nil, usage, fmt.Errorf("%w: response is not valid JSON: %w (%s)", llm.ErrResponseInvalid, err, responseFormatHint)
		}
		return nil, usage, fmt.Errorf("%w: response is not valid JSON: %w", llm.ErrResponseInvalid, err)
	}
	return raw, usage, nil
}

// apiError renders a non-2xx, non-retryable status as an error carrying a
// bounded body excerpt; a 400 that mentions response_format gains the
// actionable config hint.
func apiError(status int, body []byte) error {
	excerpt := strings.TrimSpace(string(body))
	if len(excerpt) > maxErrorBodyExcerpt {
		excerpt = excerpt[:maxErrorBodyExcerpt] + "…"
	}
	if status == http.StatusBadRequest && strings.Contains(excerpt, "response_format") {
		excerpt += " (" + responseFormatHint + ")"
	}
	return &llm.APIError{StatusCode: status, Message: excerpt}
}

const (
	thinkOpen  = "<think>"
	thinkClose = "</think>"
)

// stripLeadingThink removes leading <think>…</think> blocks (plus surrounding
// whitespace) — the shape hybrid-reasoning models leak when the serving
// runtime has no reasoning parser configured. Blocks may be stacked
// sequentially or nested, so each one is consumed depth-balanced and the scan
// repeats while another block immediately follows. A non-leading occurrence
// is left alone: only the leading position is reasoning leakage; anywhere
// else it is model output on its own head. An unclosed leading block leaves
// the content untouched for the JSON parse to report.
func stripLeadingThink(s string) string {
	cur, stripped := s, false
	for {
		trimmed := strings.TrimLeftFunc(cur, unicode.IsSpace)
		if !strings.HasPrefix(trimmed, thinkOpen) {
			if stripped {
				return trimmed
			}
			return s
		}
		rest, ok := skipThinkBlock(trimmed)
		if !ok {
			if stripped {
				return trimmed
			}
			return s
		}
		cur, stripped = rest, true
	}
}

// skipThinkBlock consumes one depth-balanced <think>…</think> block from the
// start of s and returns the remainder. ok is false when the block never
// closes at depth zero.
func skipThinkBlock(s string) (rest string, ok bool) {
	depth, i := 0, 0
	for i < len(s) {
		switch {
		case strings.HasPrefix(s[i:], thinkOpen):
			depth++
			i += len(thinkOpen)
		case strings.HasPrefix(s[i:], thinkClose):
			depth--
			i += len(thinkClose)
			if depth == 0 {
				return s[i:], true
			}
		default:
			i++
		}
	}
	return "", false
}
