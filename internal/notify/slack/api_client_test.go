// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	slacklib "github.com/slack-go/slack"
)

func testClient(t *testing.T, handler http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return NewClient(Config{BotToken: "xoxb-test-token", BaseURL: srv.URL, TimeoutSeconds: 2})
}

func decodeBody(t *testing.T, r *http.Request) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	return m
}

// ----------------------------------------------------------------------
// chat.postMessage
// ----------------------------------------------------------------------

func TestSlackAPIPostMessageSuccess(t *testing.T) {
	var gotPath string
	var gotAuth string
	var gotBody map[string]any
	var gotClientMsgID string

	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotClientMsgID = r.Header.Get(clientMsgIDHeader)
		gotBody = decodeBody(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1700000000.000100"}`))
	})

	res, err := c.PostMessage(context.Background(), PostMessageRequest{
		Channel:     "C123",
		Text:        "hello",
		Blocks:      []slacklib.Block{slacklib.NewSectionBlock(slacklib.NewTextBlockObject(slacklib.MarkdownType, "hello", false, false), nil, nil)},
		ClientMsgID: "client-msg-1",
	})
	if err != nil {
		t.Fatalf("PostMessage() error = %v", err)
	}
	if res.Channel != "C123" || res.TS != "1700000000.000100" {
		t.Fatalf("PostMessage() = %+v, want channel C123 ts 1700000000.000100", res)
	}
	if !strings.HasSuffix(gotPath, "/chat.postMessage") {
		t.Fatalf("request path = %q, want chat.postMessage", gotPath)
	}
	if gotAuth != "Bearer xoxb-test-token" {
		t.Fatalf("Authorization header = %q, want Bearer xoxb-test-token", gotAuth)
	}
	if gotClientMsgID != "client-msg-1" {
		t.Fatalf("client message id header = %q, want client-msg-1", gotClientMsgID)
	}
	if gotBody["channel"] != "C123" || gotBody["text"] != "hello" {
		t.Fatalf("request body = %+v, want channel/text set", gotBody)
	}
	if _, ok := gotBody["thread_ts"]; ok {
		t.Fatalf("request body = %+v, a root post must not set thread_ts", gotBody)
	}
	if _, ok := gotBody["reply_broadcast"]; ok {
		t.Fatalf("request body = %+v, a root post must not set reply_broadcast", gotBody)
	}
	blocks, ok := gotBody["blocks"].([]any)
	if !ok || len(blocks) != 1 {
		t.Fatalf("request body blocks = %+v, want exactly one block", gotBody["blocks"])
	}
}

func TestSlackAPIPostMessageStableClientMsgID(t *testing.T) {
	// Two calls with identical input must send byte-identical request
	// bodies and the same client-message-id header — no randomness or
	// timestamps leak into the wire request.
	var bodies []string
	var headers []string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		body := decodeBody(t, r)
		encoded, _ := json.Marshal(body)
		bodies = append(bodies, string(encoded))
		headers = append(headers, r.Header.Get(clientMsgIDHeader))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1.1"}`))
	})

	req := PostMessageRequest{Channel: "C123", Text: "hello", ClientMsgID: "stable-id"}
	for i := 0; i < 2; i++ {
		if _, err := c.PostMessage(context.Background(), req); err != nil {
			t.Fatalf("PostMessage() [%d] error = %v", i, err)
		}
	}
	if bodies[0] != bodies[1] {
		t.Fatalf("request bodies differ across identical calls: %q vs %q", bodies[0], bodies[1])
	}
	if headers[0] != "stable-id" || headers[1] != "stable-id" {
		t.Fatalf("client message id headers = %v, want [stable-id stable-id]", headers)
	}
}

func TestSlackAPIPostMessageThreadAndBroadcastFields(t *testing.T) {
	cases := []struct {
		name          string
		req           func(base PostMessageRequest) PostMessageRequest
		wantThreadTS  string
		wantBroadcast bool
	}{
		{
			name:         "root",
			req:          func(b PostMessageRequest) PostMessageRequest { return b },
			wantThreadTS: "",
		},
		{
			name: "thread reply",
			req: func(b PostMessageRequest) PostMessageRequest {
				b.ThreadTS = "1700000000.000100"
				return b
			},
			wantThreadTS: "1700000000.000100",
		},
		{
			name: "broadcast reply",
			req: func(b PostMessageRequest) PostMessageRequest {
				b.ThreadTS = "1700000000.000100"
				b.ReplyBroadcast = true
				return b
			},
			wantThreadTS:  "1700000000.000100",
			wantBroadcast: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var gotBody map[string]any
			client := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				gotBody = decodeBody(t, r)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"2.2"}`))
			})
			req := c.req(PostMessageRequest{Channel: "C123", Text: "hi"})
			if _, err := client.PostMessage(context.Background(), req); err != nil {
				t.Fatalf("PostMessage() error = %v", err)
			}
			if ts, _ := gotBody["thread_ts"].(string); ts != c.wantThreadTS {
				t.Fatalf("thread_ts = %q, want %q", ts, c.wantThreadTS)
			}
			broadcast, _ := gotBody["reply_broadcast"].(bool)
			if broadcast != c.wantBroadcast {
				t.Fatalf("reply_broadcast = %v, want %v", broadcast, c.wantBroadcast)
			}
		})
	}
}

// ----------------------------------------------------------------------
// chat.update
// ----------------------------------------------------------------------

func TestSlackAPIUpdateMessageSuccess(t *testing.T) {
	var gotBody map[string]any
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat.update") {
			t.Fatalf("request path = %q, want chat.update", r.URL.Path)
		}
		gotBody = decodeBody(t, r)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1700000000.000100"}`))
	})

	res, err := c.UpdateMessage(context.Background(), UpdateMessageRequest{
		Channel: "C123", TS: "1700000000.000100", Text: "updated",
	})
	if err != nil {
		t.Fatalf("UpdateMessage() error = %v", err)
	}
	if res.Channel != "C123" || res.TS != "1700000000.000100" {
		t.Fatalf("UpdateMessage() = %+v, want the edited coordinates echoed back", res)
	}
	if gotBody["ts"] != "1700000000.000100" {
		t.Fatalf("request body ts = %v, want 1700000000.000100", gotBody["ts"])
	}
}

// ----------------------------------------------------------------------
// auth.test
// ----------------------------------------------------------------------

func TestSlackAPIAuthTestSuccess(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/auth.test") {
			t.Fatalf("request path = %q, want auth.test", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"team":"T1","user":"alertint"}`))
	})
	if err := c.AuthTest(context.Background()); err != nil {
		t.Fatalf("AuthTest() error = %v", err)
	}
}

func TestSlackAPIAuthTestInvalidAuthIsConfigurationBlocking(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
	})
	err := c.AuthTest(context.Background())
	assertAPIError(t, err, ErrorClassConfiguration, "invalid_auth")
}

// ----------------------------------------------------------------------
// Classification: retryable / configuration-blocking / invalid.
// ----------------------------------------------------------------------

func assertAPIError(t *testing.T, err error, wantClass ErrorClass, wantCode string) {
	t.Helper()
	if err == nil {
		t.Fatal("error = nil, want an APIError")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error = %v (%T), want *APIError", err, err)
	}
	if apiErr.Class != wantClass {
		t.Fatalf("error class = %q, want %q (err=%v)", apiErr.Class, wantClass, err)
	}
	if wantCode != "" && apiErr.Code != wantCode {
		t.Fatalf("error code = %q, want %q", apiErr.Code, wantCode)
	}
}

func TestSlackAPIClassifiesRetryable(t *testing.T) {
	cases := []struct {
		name      string
		handler   http.HandlerFunc
		wantCode  string
		wantRetry time.Duration
	}{
		{
			name: "http 500",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
			wantCode: "http_500",
		},
		{
			name: "http 503",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusServiceUnavailable)
			},
			wantCode: "http_503",
		},
		{
			name: "http 429 with Retry-After",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Retry-After", "42")
				w.WriteHeader(http.StatusTooManyRequests)
			},
			wantCode:  "ratelimited",
			wantRetry: 42 * time.Second,
		},
		{
			name: "slack ratelimited error body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Retry-After", "5")
				_, _ = w.Write([]byte(`{"ok":false,"error":"ratelimited"}`))
			},
			wantCode:  "ratelimited",
			wantRetry: 5 * time.Second,
		},
		{
			name: "slack internal_error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":false,"error":"internal_error"}`))
			},
			wantCode: "internal_error",
		},
		{
			name: "undecodable 200 body",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`not json`))
			},
			wantCode: "undecodable_response",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := testClient(t, c.handler)
			err := client.AuthTest(context.Background())
			assertAPIError(t, err, ErrorClassRetryable, c.wantCode)
			var apiErr *APIError
			errors.As(err, &apiErr)
			if apiErr.RetryAfter != c.wantRetry {
				t.Fatalf("RetryAfter = %s, want %s", apiErr.RetryAfter, c.wantRetry)
			}
		})
	}
}

func TestSlackAPIClassifiesTransportFailureAsRetryable(t *testing.T) {
	// A closed server: the request never gets a response at all.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	c := NewClient(Config{BotToken: "xoxb-test", BaseURL: url, TimeoutSeconds: 1})
	err := c.AuthTest(context.Background())
	assertAPIError(t, err, ErrorClassRetryable, "transport_error")
}

func TestSlackAPIClassifiesTimeoutAsRetryable(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(500 * time.Millisecond):
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := c.AuthTest(ctx)
	assertAPIError(t, err, ErrorClassRetryable, "timeout")
}

func TestSlackAPIClassifiesConfigurationBlocking(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		code    string
	}{
		{
			name: "invalid_auth",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
			},
			code: "invalid_auth",
		},
		{
			name: "missing_scope",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":false,"error":"missing_scope"}`))
			},
			code: "missing_scope",
		},
		{
			name: "channel_not_found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
			},
			code: "channel_not_found",
		},
		{
			name: "not_in_channel",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":false,"error":"not_in_channel"}`))
			},
			code: "not_in_channel",
		},
		{
			name: "http 401",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			},
			code: "http_401",
		},
		{
			name: "http 403",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusForbidden)
			},
			code: "http_403",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := testClient(t, c.handler)
			err := client.AuthTest(context.Background())
			assertAPIError(t, err, ErrorClassConfiguration, c.code)
		})
	}
}

func TestSlackAPIClassifiesInvalidPayload(t *testing.T) {
	cases := []struct {
		name    string
		handler http.HandlerFunc
		code    string
	}{
		{
			name: "invalid_blocks",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_blocks"}`))
			},
			code: "invalid_blocks",
		},
		{
			name: "msg_too_long",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":false,"error":"msg_too_long"}`))
			},
			code: "msg_too_long",
		},
		{
			name: "message_not_found",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"ok":false,"error":"message_not_found"}`))
			},
			code: "message_not_found",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			client := testClient(t, c.handler)
			err := client.AuthTest(context.Background())
			assertAPIError(t, err, ErrorClassInvalid, c.code)
		})
	}
}

func TestSlackAPIPostMessageValidatesLocallyBeforeCalling(t *testing.T) {
	called := false
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C","ts":"1"}`))
	})

	cases := []struct {
		name string
		req  PostMessageRequest
	}{
		{"missing channel", PostMessageRequest{Text: "hi"}},
		{"missing text and blocks", PostMessageRequest{Channel: "C123"}},
		{"broadcast without thread", PostMessageRequest{Channel: "C123", Text: "hi", ReplyBroadcast: true}},
	}
	for _, c2 := range cases {
		t.Run(c2.name, func(t *testing.T) {
			called = false
			_, err := c.PostMessage(context.Background(), c2.req)
			assertAPIError(t, err, ErrorClassInvalid, "")
			if called {
				t.Fatal("a locally-invalid request must never reach the Slack API")
			}
		})
	}
}

// ----------------------------------------------------------------------
// Redaction: never the token, never the raw response body.
// ----------------------------------------------------------------------

func TestSlackAPIErrorNeverLeaksTokenOrBody(t *testing.T) {
	const secretToken = "xoxb-super-secret-do-not-leak"
	const sensitiveBody = `{"ok":false,"error":"invalid_auth","extra_sensitive_field":"do-not-leak-this-either"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(sensitiveBody))
	}))
	defer srv.Close()

	c := NewClient(Config{BotToken: secretToken, BaseURL: srv.URL, TimeoutSeconds: 2})
	err := c.AuthTest(context.Background())
	if err == nil {
		t.Fatal("want an error")
	}
	msg := err.Error()
	if strings.Contains(msg, secretToken) {
		t.Fatalf("error message leaked the bot token: %q", msg)
	}
	if strings.Contains(msg, "extra_sensitive_field") || strings.Contains(msg, "do-not-leak-this-either") {
		t.Fatalf("error message leaked the raw response body: %q", msg)
	}
}
