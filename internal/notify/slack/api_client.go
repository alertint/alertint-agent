// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	slacklib "github.com/slack-go/slack"
)

// ----------------------------------------------------------------------
// Plan 3 Task 6: a narrow, hand-rolled Slack Web API client covering
// exactly chat.postMessage, chat.update, and auth.test — the three calls
// Situation delivery needs. It follows this codebase's existing narrow-
// client convention (internal/zabbix/client.go, internal/prometheus/
// client.go) rather than wrapping slack-go/slack's own HTTP client: this
// file needs precise, independently testable control over classifying a
// response as retryable, configuration-blocking, or invalid (spec.md
// "Notification intent contract"), which slack-go's client does not
// expose as typed errors. Block Kit body construction still reuses
// slack-go's own block/text-object structs (situation.go) — they are
// plain, well-tested wire-compatible data types, not the HTTP surface
// this file replaces.
//
// This client requests no Slack history-read scopes, never searches
// Slack, and performs no read-before-redrive reconciliation (spec.md
// "Local idempotency, external delivery, and ordering").
// ----------------------------------------------------------------------

const (
	defaultAPIBase       = "https://slack.com/api"
	defaultTimeout       = 10 * time.Second
	maxResponseBodyBytes = 1 << 20 // 1 MiB: generous for any chat.postMessage/update/auth.test reply, bounded against a misbehaving peer.
)

// ErrorClass is the closed classification api_client.go assigns to every
// failed Slack call (Task 6 brief Step 4/5): transport/5xx/rate-limit/
// uncertain responses are retryable; token/scope/channel rejections are
// configuration-blocking; a malformed durable payload this build sent is
// invalid.
type ErrorClass string

const (
	ErrorClassRetryable     ErrorClass = "retryable"
	ErrorClassConfiguration ErrorClass = "configuration_blocking"
	ErrorClassInvalid       ErrorClass = "invalid"
)

// APIError is the typed result of a failed Slack Web API call. It never
// carries the bot token or a raw response body — only a bounded class,
// a bounded Slack (or local transport) error code, and, for a retryable
// failure, how long to wait before trying again.
type APIError struct {
	Class      ErrorClass
	Code       string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("slack: %s: %s (retry after %s)", e.Class, e.Code, e.RetryAfter)
	}
	return fmt.Sprintf("slack: %s: %s", e.Class, e.Code)
}

// Config configures the narrow Slack Web API Client.
type Config struct {
	BotToken       string
	BaseURL        string // override for tests; defaults to defaultAPIBase.
	TimeoutSeconds int
}

// Client is a narrow Slack Web API client covering chat.postMessage,
// chat.update, and auth.test.
type Client struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

// NewClient constructs a Client from cfg.
func NewClient(cfg Config) *Client {
	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	base := cfg.BaseURL
	if base == "" {
		base = defaultAPIBase
	}
	return &Client{
		httpClient: &http.Client{Timeout: timeout},
		token:      cfg.BotToken,
		baseURL:    strings.TrimRight(base, "/"),
	}
}

// PostMessageRequest is one chat.postMessage call.
type PostMessageRequest struct {
	Channel  string
	Text     string
	Blocks   []slacklib.Block
	ThreadTS string // set for a thread reply; empty for a root.

	// ReplyBroadcast marks a thread reply as also shown in the channel
	// (Slack's reply_broadcast). Root posts must leave this false.
	ReplyBroadcast bool

	// ClientMsgID is this build's own deterministic local identity for one
	// durable delivery (Task 4's NotificationIntent.ClientMessageID). Slack's
	// chat.postMessage accepts no idempotency parameter (spec.md: "Plan 3
	// requests no Slack history-read scopes and performs no
	// read-before-redrive reconciliation" — an uncertain retry may rarely
	// create a provider-side duplicate, accepted). It is carried only as a
	// request header for local log/trace correlation, never sent as a body
	// field Slack would interpret, and never logged or returned inside an
	// error.
	ClientMsgID string
}

// UpdateMessageRequest is one chat.update call.
type UpdateMessageRequest struct {
	Channel     string
	TS          string
	Text        string
	Blocks      []slacklib.Block
	ClientMsgID string
}

// MessageResult is the durable Slack coordinate a successful post/update
// returns.
type MessageResult struct {
	Channel string
	TS      string
}

// clientMsgIDHeader carries PostMessageRequest/UpdateMessageRequest's own
// ClientMsgID for request/response log correlation only. Slack does not
// interpret it.
const clientMsgIDHeader = "X-Alertint-Client-Message-Id"

// PostMessage posts one new message (a root, a thread reply, or a
// broadcast reply per ThreadTS/ReplyBroadcast).
func (c *Client) PostMessage(ctx context.Context, req PostMessageRequest) (MessageResult, error) {
	if err := validatePostMessageRequest(req); err != nil {
		return MessageResult{}, err
	}
	payload := postMessagePayload{
		Channel:        req.Channel,
		Text:           req.Text,
		Blocks:         req.Blocks,
		ThreadTS:       req.ThreadTS,
		ReplyBroadcast: req.ReplyBroadcast,
	}
	env, err := c.call(ctx, "chat.postMessage", payload, req.ClientMsgID)
	if err != nil {
		return MessageResult{}, err
	}
	return MessageResult{Channel: env.Channel, TS: env.TS}, nil
}

// UpdateMessage edits a previously posted message in place (including the
// R4 deadline-refresh root edit, which is a plain chat.update).
func (c *Client) UpdateMessage(ctx context.Context, req UpdateMessageRequest) (MessageResult, error) {
	if err := validateUpdateMessageRequest(req); err != nil {
		return MessageResult{}, err
	}
	payload := updateMessagePayload{
		Channel: req.Channel,
		TS:      req.TS,
		Text:    req.Text,
		Blocks:  req.Blocks,
	}
	env, err := c.call(ctx, "chat.update", payload, req.ClientMsgID)
	if err != nil {
		return MessageResult{}, err
	}
	return MessageResult{Channel: env.Channel, TS: env.TS}, nil
}

// AuthTest verifies the configured bot token against auth.test — the
// startup/recovery readiness probe.
func (c *Client) AuthTest(ctx context.Context) error {
	_, err := c.call(ctx, "auth.test", struct{}{}, "")
	return err
}

// ----------------------------------------------------------------------
// Validation — malformed durable payloads this build would otherwise send.
// ----------------------------------------------------------------------

func validatePostMessageRequest(req PostMessageRequest) error {
	if strings.TrimSpace(req.Channel) == "" {
		return &APIError{Class: ErrorClassInvalid, Code: "missing_channel"}
	}
	if strings.TrimSpace(req.Text) == "" && len(req.Blocks) == 0 {
		return &APIError{Class: ErrorClassInvalid, Code: "missing_text"}
	}
	if req.ReplyBroadcast && strings.TrimSpace(req.ThreadTS) == "" {
		return &APIError{Class: ErrorClassInvalid, Code: "broadcast_without_thread"}
	}
	return nil
}

func validateUpdateMessageRequest(req UpdateMessageRequest) error {
	if strings.TrimSpace(req.Channel) == "" {
		return &APIError{Class: ErrorClassInvalid, Code: "missing_channel"}
	}
	if strings.TrimSpace(req.TS) == "" {
		return &APIError{Class: ErrorClassInvalid, Code: "missing_ts"}
	}
	if strings.TrimSpace(req.Text) == "" && len(req.Blocks) == 0 {
		return &APIError{Class: ErrorClassInvalid, Code: "missing_text"}
	}
	return nil
}

// ----------------------------------------------------------------------
// Transport
// ----------------------------------------------------------------------

type postMessagePayload struct {
	Channel        string           `json:"channel"`
	Text           string           `json:"text"`
	Blocks         []slacklib.Block `json:"blocks,omitempty"`
	ThreadTS       string           `json:"thread_ts,omitempty"`
	ReplyBroadcast bool             `json:"reply_broadcast,omitempty"`
}

type updateMessagePayload struct {
	Channel string           `json:"channel"`
	TS      string           `json:"ts"`
	Text    string           `json:"text"`
	Blocks  []slacklib.Block `json:"blocks,omitempty"`
}

// apiEnvelope is the common Slack Web API response shape this client
// needs: success/error plus the delivered coordinates chat.postMessage/
// chat.update return. auth.test's own extra fields (team, user, ...) are
// not read — a non-error response is success enough for a readiness
// probe.
type apiEnvelope struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error,omitempty"`
	Channel string `json:"channel,omitempty"`
	TS      string `json:"ts,omitempty"`
}

// call issues one Slack Web API method with a JSON body and classifies
// every failure mode: a transport error, a non-2xx HTTP status, an
// undecodable body, or a Slack-reported {"ok":false,"error":"..."} — never
// returning the raw response body or the bot token in the resulting error.
func (c *Client) call(ctx context.Context, method string, payload any, clientMsgID string) (apiEnvelope, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return apiEnvelope{}, &APIError{Class: ErrorClassInvalid, Code: "encode_request_failed"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/"+method, bytes.NewReader(body))
	if err != nil {
		return apiEnvelope{}, &APIError{Class: ErrorClassInvalid, Code: "build_request_failed"}
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Authorization", "Bearer "+c.token)
	if clientMsgID != "" {
		req.Header.Set(clientMsgIDHeader, clientMsgID)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return apiEnvelope{}, classifyTransportError(err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBodyBytes))
	if err != nil {
		return apiEnvelope{}, &APIError{Class: ErrorClassRetryable, Code: "read_response_failed"}
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		return apiEnvelope{}, &APIError{Class: ErrorClassRetryable, Code: "ratelimited", RetryAfter: retryAfterFrom(resp.Header)}
	case resp.StatusCode >= 500:
		return apiEnvelope{}, &APIError{Class: ErrorClassRetryable, Code: fmt.Sprintf("http_%d", resp.StatusCode)}
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return apiEnvelope{}, &APIError{Class: ErrorClassConfiguration, Code: fmt.Sprintf("http_%d", resp.StatusCode)}
	case resp.StatusCode >= 400:
		// An unexpected 4xx this build does not specifically classify below
		// (Slack's Web API normally answers 200 with ok:false instead): the
		// request itself may be malformed, but the outcome is not certain
		// enough to call configuration-blocking — treat it as invalid so
		// it surfaces rather than retries forever.
		return apiEnvelope{}, &APIError{Class: ErrorClassInvalid, Code: fmt.Sprintf("http_%d", resp.StatusCode)}
	}

	var envelope apiEnvelope
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		// Slack answered 2xx but not with a shape this client understands:
		// the outcome is uncertain, so treat it as retryable rather than
		// assume either success or failure.
		return apiEnvelope{}, &APIError{Class: ErrorClassRetryable, Code: "undecodable_response"}
	}
	if !envelope.OK {
		return apiEnvelope{}, classifySlackErrorCode(envelope.Error, resp.Header)
	}
	return envelope, nil
}

// classifyTransportError classifies a failure to even complete the HTTP
// round trip (DNS, connection refused, TLS, timeout, context
// cancellation) as retryable — the outcome of such a failure is always
// uncertain, never a confirmed rejection.
func classifyTransportError(err error) *APIError {
	code := "transport_error"
	if errors.Is(err, context.DeadlineExceeded) || isTimeoutErr(err) {
		code = "timeout"
	}
	return &APIError{Class: ErrorClassRetryable, Code: code}
}

func isTimeoutErr(err error) bool {
	var timeoutErr interface{ Timeout() bool }
	return errors.As(err, &timeoutErr) && timeoutErr.Timeout()
}

// configurationErrorCodes are Slack Web API error codes this build treats
// as blocked_configuration: missing/invalid token, scope, channel,
// authentication, or permission configuration (spec.md "Required fields
// and states": "blocked_configuration covers missing/invalid token,
// channel, authentication, or permission configuration").
var configurationErrorCodes = map[string]bool{
	"invalid_auth":      true,
	"not_authed":        true,
	"account_inactive":  true,
	"token_revoked":     true,
	"token_expired":     true,
	"no_permission":     true,
	"missing_scope":     true,
	"channel_not_found": true,
	"not_in_channel":    true,
	"is_archived":       true,
	"restricted_action": true,
	"restricted_action_non_threadable_channel": true,
	"restricted_action_read_only_channel":      true,
	"restricted_action_thread_only_channel":    true,
	"ekm_access_denied":                        true,
	"org_login_required":                       true,
	"not_allowed_token_type":                   true,
	"method_not_supported_for_channel_type":    true,
	"team_access_not_granted":                  true,
	"user_is_bot":                              true,
	"user_is_restricted":                       true,
}

// retryableErrorCodes are Slack Web API error codes this build treats as
// retryable: rate limiting and Slack-side transient failures.
var retryableErrorCodes = map[string]bool{
	"ratelimited":         true,
	"rate_limited":        true,
	"internal_error":      true,
	"fatal_error":         true,
	"request_timeout":     true,
	"service_unavailable": true,
}

// classifySlackErrorCode classifies one {"ok":false,"error":code} response.
// Any code this build does not specifically recognize as retryable or
// configuration-blocking is invalid — a malformed durable payload this
// build sent (e.g. invalid_blocks, msg_too_long, message_not_found), which
// stays operator-visible and redriveable rather than retried forever.
func classifySlackErrorCode(code string, header http.Header) *APIError {
	switch {
	case retryableErrorCodes[code]:
		return &APIError{Class: ErrorClassRetryable, Code: code, RetryAfter: retryAfterFrom(header)}
	case configurationErrorCodes[code]:
		return &APIError{Class: ErrorClassConfiguration, Code: code}
	case code == "":
		return &APIError{Class: ErrorClassInvalid, Code: "unknown_error"}
	default:
		return &APIError{Class: ErrorClassInvalid, Code: code}
	}
}

// retryAfterFrom parses the Retry-After header (seconds, per Slack's own
// rate-limit documentation) into a Duration. Zero when absent or
// unparsable — the caller applies its own backoff floor in that case.
func retryAfterFrom(header http.Header) time.Duration {
	v := header.Get("Retry-After")
	if v == "" {
		return 0
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil || seconds < 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}
