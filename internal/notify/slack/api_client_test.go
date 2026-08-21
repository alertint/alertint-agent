// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAPIClientPostSendsBearerAuthAndClientMsgID(t *testing.T) {
	var gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/chat.postMessage" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1700000000.000100"}`))
	}))
	defer srv.Close()

	client := NewHTTPAPIClient("xoxb-secret-token")
	client.baseURL = srv.URL

	channel, ts, err := client.Post(context.Background(), PostRequest{
		Channel: "C123", Text: "hello", ClientMsgID: "cmid-1",
		Metadata: MessageMetadata{EventType: "situation_root", EventPayload: map[string]any{"situation_id": "s1"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if channel != "C123" || ts != "1700000000.000100" {
		t.Fatalf("channel=%s ts=%s", channel, ts)
	}
	if gotAuth != "Bearer xoxb-secret-token" {
		t.Fatalf("authorization header=%q", gotAuth)
	}
	if gotBody["client_msg_id"] != "cmid-1" {
		t.Fatalf("body=%v missing client_msg_id", gotBody)
	}
	if gotBody["channel"] != "C123" {
		t.Fatalf("body=%v missing channel", gotBody)
	}
}

func TestAPIClientPostNeverLeaksTokenOnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":false,"error":"channel_not_found"}`))
	}))
	defer srv.Close()

	client := NewHTTPAPIClient("xoxb-super-secret")
	client.baseURL = srv.URL
	_, _, err := client.Post(context.Background(), PostRequest{Channel: "C000", Text: "hi", ClientMsgID: "cmid-2"})
	if err == nil {
		t.Fatal("expected an error for ok:false")
	}
	if strings.Contains(err.Error(), "xoxb-super-secret") {
		t.Fatalf("error leaked the bot token: %v", err)
	}
	if !strings.Contains(err.Error(), "channel_not_found") {
		t.Fatalf("error missing slack error code: %v", err)
	}
}

func TestAPIClientPostHonorsRetryAfter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"ok":false,"error":"ratelimited"}`))
	}))
	defer srv.Close()

	client := NewHTTPAPIClient("xoxb-token")
	client.baseURL = srv.URL
	_, _, err := client.Post(context.Background(), PostRequest{Channel: "C1", Text: "hi", ClientMsgID: "cmid-3"})
	if err == nil {
		t.Fatal("expected a rate-limit error")
	}
	var rl *RateLimitError
	if !asRateLimitError(err, &rl) {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if rl.RetryAfter.Seconds() != 7 {
		t.Fatalf("retry after=%s", rl.RetryAfter)
	}
}

func TestAPIClientUpdateTargetsExistingMessage(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat.update" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"channel":"C123","ts":"1700000000.000100"}`))
	}))
	defer srv.Close()

	client := NewHTTPAPIClient("xoxb-secret-token")
	client.baseURL = srv.URL
	err := client.Update(context.Background(), UpdateRequest{Channel: "C123", TS: "1700000000.000100", Text: "updated"})
	if err != nil {
		t.Fatal(err)
	}
	if gotBody["ts"] != "1700000000.000100" || gotBody["channel"] != "C123" {
		t.Fatalf("body=%v", gotBody)
	}
}

func asRateLimitError(err error, out **RateLimitError) bool {
	rl, ok := err.(*RateLimitError)
	if ok {
		*out = rl
	}
	return ok
}
