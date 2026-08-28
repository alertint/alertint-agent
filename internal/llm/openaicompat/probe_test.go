// SPDX-License-Identifier: FSL-1.1-ALv2

package openaicompat_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alertint/alertint-agent/internal/llm"
	"github.com/alertint/alertint-agent/internal/llm/openaicompat"
)

func guardAgainstGeneration(t *testing.T, r *http.Request) {
	t.Helper()
	if r.Method == http.MethodPost || r.URL.Path == "/v1/chat/completions" {
		t.Fatalf("probe reached a generation endpoint: %s %s", r.Method, r.URL.Path)
	}
}

func TestProbeHostedOpenAIIsModelMetadataGET(t *testing.T) {
	var gotMethod, gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guardAgainstGeneration(t, r)
		gotMethod, gotPath, gotAuth = r.Method, r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := openaicompat.NewForTest(openaicompat.Config{BaseURL: srv.URL, APIKey: "k", Model: "gpt-5"}, true)
	res := c.Probe(context.Background())

	if res.Outcome != llm.ProbeOK || gotMethod != http.MethodGet || gotPath != "/v1/models/gpt-5" {
		t.Fatalf("res=%+v method=%s path=%s", res, gotMethod, gotPath)
	}
	if gotAuth != "Bearer k" {
		t.Fatalf("auth header = %q", gotAuth)
	}
	if res.Method != http.MethodGet || res.Path != "/v1/models/gpt-5" {
		t.Fatalf("result must echo the request: %+v", res)
	}
}

func TestProbeGenericHealthEndpointOK(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guardAgainstGeneration(t, r)
		requests = append(requests, r.URL.Path)
		if r.URL.Path == "/health" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := openaicompat.New(openaicompat.Config{BaseURL: srv.URL, Model: "local-model"}, nil, nil)
	res := c.Probe(context.Background())

	if res.Outcome != llm.ProbeOK || res.Path != "/health" {
		t.Fatalf("res=%+v", res)
	}
	if len(requests) != 1 {
		t.Fatalf("expected exactly one request, got %v", requests)
	}
}

func TestProbeGenericFallsBackToModelsWhenHealthUnsupported(t *testing.T) {
	var requests []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guardAgainstGeneration(t, r)
		requests = append(requests, r.URL.Path)
		switch r.URL.Path {
		case "/health":
			w.WriteHeader(http.StatusNotFound)
		case "/v1/models":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := openaicompat.New(openaicompat.Config{BaseURL: srv.URL, Model: "local-model"}, nil, nil)
	res := c.Probe(context.Background())

	if res.Outcome != llm.ProbeOK || res.Path != "/v1/models" {
		t.Fatalf("res=%+v", res)
	}
	if len(requests) != 2 || requests[0] != "/health" || requests[1] != "/v1/models" {
		t.Fatalf("requests = %v", requests)
	}
}

func TestProbeGenericBothRoutesUnsupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guardAgainstGeneration(t, r)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := openaicompat.New(openaicompat.Config{BaseURL: srv.URL, Model: "local-model"}, nil, nil)
	res := c.Probe(context.Background())

	if res.Outcome != llm.ProbeUnsupported || res.Path != "/v1/models" {
		t.Fatalf("res=%+v", res)
	}
}

func TestProbeOmitsAuthHeaderWhenNoAPIKey(t *testing.T) {
	var gotAuth string
	seen := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		guardAgainstGeneration(t, r)
		gotAuth, seen = r.Header.Get("Authorization"), true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := openaicompat.New(openaicompat.Config{BaseURL: srv.URL, Model: "local-model"}, nil, nil)
	if res := c.Probe(context.Background()); res.Outcome != llm.ProbeOK {
		t.Fatalf("res=%+v", res)
	}
	if !seen || gotAuth != "" {
		t.Fatalf("auth header = %q, want empty", gotAuth)
	}
}
