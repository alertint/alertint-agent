// SPDX-License-Identifier: FSL-1.1-ALv2

package anthropic_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/anthropic"
)

func TestProbeIsMetadataGETOnly(t *testing.T) {
	var gotMethod, gotPath, gotKey, gotVersion string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotKey, gotVersion = r.Header.Get("X-Api-Key"), r.Header.Get("Anthropic-Version")
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"claude-sonnet-5","type":"model"}`))
	}))
	defer srv.Close()
	c := anthropic.NewWithHTTPClient(anthropic.Config{APIKey: "k", Model: "claude-sonnet-5"}, nil, nil, srv.URL)

	res := c.Probe(context.Background())

	if res.Outcome != llm.ProbeOK || gotMethod != http.MethodGet || gotPath != "/v1/models/claude-sonnet-5" {
		t.Fatalf("res=%+v method=%s path=%s", res, gotMethod, gotPath)
	}
	if gotKey != "k" || gotVersion == "" || len(body) != 0 {
		t.Fatalf("headers/body: key=%q version=%q body=%q", gotKey, gotVersion, body)
	}
	if res.Method != http.MethodGet || res.Path != "/v1/models/claude-sonnet-5" {
		t.Fatalf("result must echo the request: %+v", res)
	}
}

func TestProbeStatusMapping(t *testing.T) {
	cases := []struct {
		code    int
		outcome llm.ProbeOutcome
		wantAPI bool
		wantRet bool
	}{
		{200, llm.ProbeOK, false, false},
		{404, llm.ProbeUnsupported, false, false},
		{405, llm.ProbeUnsupported, false, false},
		{401, llm.ProbeFailed, true, false},
		{429, llm.ProbeFailed, false, true},
		{503, llm.ProbeFailed, false, true},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Errorf("probe used %s", r.Method)
			}
			w.WriteHeader(tc.code)
			_, _ = w.Write([]byte(`{"error":{"message":"SECRET BODY"}}`))
		}))
		c := anthropic.NewWithHTTPClient(anthropic.Config{APIKey: "k"}, nil, nil, srv.URL)
		res := c.Probe(context.Background())
		srv.Close()
		if res.Outcome != tc.outcome || res.StatusCode != tc.code {
			t.Errorf("code %d: res=%+v", tc.code, res)
		}
		var apiErr *llm.APIError
		var retErr *llm.RetryableError
		if tc.wantAPI && (!errors.As(res.Err, &apiErr) || apiErr.Message != "") {
			t.Errorf("code %d: want bodiless APIError, got %v", tc.code, res.Err)
		}
		if tc.wantRet && !errors.As(res.Err, &retErr) {
			t.Errorf("code %d: want RetryableError, got %v", tc.code, res.Err)
		}
		if res.Err != nil && strings.Contains(res.Err.Error(), "SECRET BODY") {
			t.Errorf("code %d: probe error leaked the response body: %v", tc.code, res.Err)
		}
	}
}

func TestProbeNeverHitsMessages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" || r.Method == http.MethodPost {
			t.Fatalf("probe reached a generation endpoint: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	c := anthropic.NewWithHTTPClient(anthropic.Config{APIKey: "k"}, nil, nil, srv.URL)
	if res := c.Probe(context.Background()); res.Outcome != llm.ProbeUnsupported {
		t.Fatalf("res=%+v", res)
	}
}
