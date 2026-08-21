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
	"time"

	slacklib "github.com/slack-go/slack"
)

// APIClient is the narrow JSON Slack surface the Situation notifier needs.
// The existing slacklib.Client wrapper used by the legacy notifier does not
// expose client_msg_id, so idempotent Situation posting goes through this
// dedicated bearer-auth JSON client instead.
type APIClient interface {
	Post(ctx context.Context, req PostRequest) (channel, ts string, err error)
	Update(ctx context.Context, req UpdateRequest) error
}

// MessageMetadata names the Situation, transition, and intent kind a post
// carries — Slack message metadata, not a channel-visible field.
type MessageMetadata struct {
	EventType    string         `json:"event_type,omitempty"`
	EventPayload map[string]any `json:"event_payload,omitempty"`
}

// PostRequest is one chat.postMessage call.
type PostRequest struct {
	Channel        string           `json:"channel"`
	Text           string           `json:"text"`
	Blocks         []slacklib.Block `json:"blocks,omitempty"`
	ThreadTS       string           `json:"thread_ts,omitempty"`
	ReplyBroadcast bool             `json:"reply_broadcast,omitempty"`
	ClientMsgID    string           `json:"client_msg_id"`
	Metadata       MessageMetadata  `json:"metadata,omitempty"`
}

// UpdateRequest is one chat.update call — always targets the persisted
// channel/message timestamp, never re-derived.
type UpdateRequest struct {
	Channel  string           `json:"channel"`
	TS       string           `json:"ts"`
	Text     string           `json:"text"`
	Blocks   []slacklib.Block `json:"blocks,omitempty"`
	Metadata MessageMetadata  `json:"metadata,omitempty"`
}

// RateLimitError wraps a Slack 429 response, carrying the server's own
// Retry-After timing when present so a retry honors it rather than guessing.
type RateLimitError struct {
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string {
	return fmt.Sprintf("slack: rate limited, retry after %s", e.RetryAfter)
}

// HTTPAPIClient is the concrete narrow JSON Slack API client. It never logs
// the bot token: it appears nowhere but the one Authorization header set on
// each outbound request.
type HTTPAPIClient struct {
	httpClient *http.Client
	botToken   string
	baseURL    string
}

// NewHTTPAPIClient constructs an HTTPAPIClient using a bot token (xoxb-...).
func NewHTTPAPIClient(botToken string) *HTTPAPIClient {
	return &HTTPAPIClient{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		botToken:   botToken,
		baseURL:    "https://slack.com/api",
	}
}

type apiResponse struct {
	OK      bool   `json:"ok"`
	Error   string `json:"error"`
	Channel string `json:"channel"`
	TS      string `json:"ts"`
}

// Post sends one chat.postMessage call and returns the channel/ts Slack
// assigned the message.
func (c *HTTPAPIClient) Post(ctx context.Context, req PostRequest) (string, string, error) {
	resp, err := c.call(ctx, "chat.postMessage", req)
	if err != nil {
		return "", "", err
	}
	return resp.Channel, resp.TS, nil
}

// Update sends one chat.update call. It always targets req.Channel/req.TS —
// the persisted root coordinates — never a freshly derived channel/ts.
func (c *HTTPAPIClient) Update(ctx context.Context, req UpdateRequest) error {
	_, err := c.call(ctx, "chat.update", req)
	return err
}

func (c *HTTPAPIClient) call(ctx context.Context, method string, payload any) (apiResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return apiResponse{}, fmt.Errorf("slack: marshal %s request: %w", method, err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/"+method, bytes.NewReader(body))
	if err != nil {
		return apiResponse{}, fmt.Errorf("slack: build %s request: %w", method, err)
	}
	httpReq.Header.Set("Content-Type", "application/json; charset=utf-8")
	httpReq.Header.Set("Authorization", "Bearer "+c.botToken)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return apiResponse{}, fmt.Errorf("slack: %s: %w", method, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusTooManyRequests {
		return apiResponse{}, &RateLimitError{RetryAfter: retryAfter(resp.Header.Get("Retry-After"))}
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return apiResponse{}, fmt.Errorf("slack: read %s response: %w", method, err)
	}
	var parsed apiResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return apiResponse{}, fmt.Errorf("slack: decode %s response: %w", method, err)
	}
	if !parsed.OK {
		errCode := parsed.Error
		if errCode == "" {
			errCode = "unknown_error"
		}
		return apiResponse{}, errors.New("slack: " + method + ": " + errCode)
	}
	return parsed, nil
}

func retryAfter(header string) time.Duration {
	seconds, err := strconv.Atoi(header)
	if err != nil || seconds < 0 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}
