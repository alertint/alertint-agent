// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/llm"
	llmanthropic "github.com/alertint/alertint-agent/internal/llm/anthropic"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// candidateEntry is a rung-3a weak prefilter candidate the classifier judges, on
// the fixed candidateKeyForClassify (one label off from currentKeyForClassify).
func candidateEntry(rootCause string, conf float64) acutetriage.RecalledEntry {
	return acutetriage.RecalledEntry{
		IncidentID: "inc_cand",
		GroupKey:   candidateKeyForClassify,
		RootCause:  rootCause,
		Confidence: conf,
		AnalyzedAt: time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC),
		Weak:       true,
	}
}

const currentKeyForClassify = "cluster=prod-eu1,namespace=storage,service=nfs-02"
const candidateKeyForClassify = "cluster=prod-eu1,namespace=storage,service=nfs-01"

// TestClassify_Matched: a clean "matched" reply returns VerdictMatched with the
// evaluated candidate id and the summed token count for the audit row.
func TestClassify_Matched(t *testing.T) {
	fllm := &fakeLLM{response: json.RawMessage(`{"verdict":"matched"}`)}
	got := acutetriage.Classify(context.Background(), fllm, currentKeyForClassify,
		candidateEntry("NFS volume filling from orphaned snapshots", 0.8))
	if got.Verdict != acutetriage.VerdictMatched {
		t.Errorf("verdict = %q, want matched", got.Verdict)
	}
	if got.Candidate != "inc_cand" {
		t.Errorf("candidate = %q, want inc_cand", got.Candidate)
	}
	if got.Tokens != 33 { // 11 input + 22 output from fakeLLM
		t.Errorf("tokens = %d, want 33", got.Tokens)
	}
}

// TestClassify_NoMatch: a clean "no-match" reply returns VerdictNoMatch.
func TestClassify_NoMatch(t *testing.T) {
	fllm := &fakeLLM{response: json.RawMessage(`{"verdict":"no-match"}`)}
	got := acutetriage.Classify(context.Background(), fllm, currentKeyForClassify,
		candidateEntry("unrelated", 0.5))
	if got.Verdict != acutetriage.VerdictNoMatch {
		t.Errorf("verdict = %q, want no-match", got.Verdict)
	}
}

// TestClassify_SchemaErrorNeverMatches: an LLM error (schema violation, HTTP)
// maps to unsure-error — a failure can never manufacture a match (R25).
func TestClassify_SchemaErrorNeverMatches(t *testing.T) {
	fllm := &fakeLLM{err: fmt.Errorf("%w: missing keys [verdict]", llm.ErrSchemaViolation)}
	got := acutetriage.Classify(context.Background(), fllm, currentKeyForClassify,
		candidateEntry("x", 0.5))
	if got.Verdict != acutetriage.VerdictUnsureError {
		t.Errorf("verdict = %q, want unsure-error", got.Verdict)
	}
}

// TestClassify_ErrSurfacesForLogging: the call error rides along in Err so the
// caller can log the actionable cause — in particular a truncated reply (the
// model's reasoning ate the completion budget) stays matchable via errors.Is.
func TestClassify_ErrSurfacesForLogging(t *testing.T) {
	truncErr := fmt.Errorf("%w=1024 (raise llm.max_tokens)", llm.ErrResponseTruncated)
	fllm := &fakeLLM{err: truncErr}
	got := acutetriage.Classify(context.Background(), fllm, currentKeyForClassify,
		candidateEntry("x", 0.5))
	if got.Verdict != acutetriage.VerdictUnsureError {
		t.Errorf("verdict = %q, want unsure-error", got.Verdict)
	}
	if !errors.Is(got.Err, llm.ErrResponseTruncated) {
		t.Errorf("Err = %v, want it to wrap llm.ErrResponseTruncated", got.Err)
	}

	clean := &fakeLLM{response: json.RawMessage(`{"verdict":"matched"}`)}
	if got := acutetriage.Classify(context.Background(), clean, currentKeyForClassify,
		candidateEntry("x", 0.5)); got.Err != nil {
		t.Errorf("clean reply: Err = %v, want nil", got.Err)
	}
}

// TestClassify_ModelUnsureIsDistinct: the model's own "unsure" reply is recorded
// as VerdictUnsure, not conflated with the unsure-error failure variant, so the
// graduation audit log can tell deliberate uncertainty from a broken call.
func TestClassify_ModelUnsureIsDistinct(t *testing.T) {
	fllm := &fakeLLM{response: json.RawMessage(`{"verdict":"unsure"}`)}
	got := acutetriage.Classify(context.Background(), fllm, currentKeyForClassify,
		candidateEntry("x", 0.5))
	if got.Verdict != acutetriage.VerdictUnsure {
		t.Errorf("verdict = %q, want unsure", got.Verdict)
	}
}

// TestClassify_GarbageVerdictIsUnsureError: a present-but-unrecognized verdict
// value is treated as unsure-error, not a match — only a clean matched/no-match
// is trusted.
func TestClassify_GarbageVerdictIsUnsureError(t *testing.T) {
	fllm := &fakeLLM{response: json.RawMessage(`{"verdict":"probably yes"}`)}
	got := acutetriage.Classify(context.Background(), fllm, currentKeyForClassify,
		candidateEntry("x", 0.5))
	if got.Verdict != acutetriage.VerdictUnsureError {
		t.Errorf("verdict = %q, want unsure-error", got.Verdict)
	}
}

// TestClassify_TimeoutMapsToUnsureTimeout: a real Haiku client whose 1 s HTTP
// timeout fires against a hanging server maps to unsure-timeout (distinct from
// unsure-error) so graduation metrics can separate slow calls from broken ones.
func TestClassify_TimeoutMapsToUnsureTimeout(t *testing.T) {
	// The handler blocks past the 1 s client timeout. It unblocks on `done`
	// (closed before Close via LIFO defers) rather than r.Context().Done(): a
	// client-side timeout does not reliably cancel the server request context, so
	// relying on it deadlocks srv.Close() on the still-active connection.
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-done:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(done)

	client := llmanthropic.NewWithHTTPClient(llmanthropic.Config{APIKey: "k", Model: "claude-haiku-4-5", TimeoutSeconds: 1}, nil, nil, srv.URL)
	start := time.Now()
	got := acutetriage.Classify(context.Background(), client, currentKeyForClassify,
		candidateEntry("x", 0.5))
	if got.Verdict != acutetriage.VerdictUnsureTimeout {
		t.Errorf("verdict = %q, want unsure-timeout", got.Verdict)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("classify took %v — the 1 s classifier timeout did not bound it", elapsed)
	}
}

// TestClassify_PromptRendersDeltaNotLabelsJSON: the prompt renders the structured
// group-key delta (shared + differing pairs) and the capped prior summary — never
// raw labels_json (R22).
func TestClassify_PromptRendersDeltaNotLabelsJSON(t *testing.T) {
	fllm := &fakeLLM{response: json.RawMessage(`{"verdict":"no-match"}`)}
	_ = acutetriage.Classify(context.Background(), fllm, currentKeyForClassify,
		candidateEntry("NFS volume filling from orphaned snapshots", 0.8))

	p := fllm.lastUser
	if !strings.Contains(p, "shared:") || !strings.Contains(p, "differing:") {
		t.Errorf("prompt missing structured delta:\n%s", p)
	}
	// The shared pairs (cluster, namespace) and the one differing label (service).
	for _, want := range []string{"cluster=prod-eu1", "namespace=storage", "service", "nfs-01", "nfs-02"} {
		if !strings.Contains(p, want) {
			t.Errorf("prompt missing %q:\n%s", want, p)
		}
	}
	if !strings.Contains(p, "NFS volume filling from orphaned snapshots") {
		t.Errorf("prompt missing prior summary:\n%s", p)
	}
	if strings.Contains(p, "labels_json") {
		t.Errorf("prompt leaked labels_json:\n%s", p)
	}
}

// TestClassify_PriorSummaryCapped: an over-long prior summary is truncated so the
// classifier prompt stays within its ~200–300 token budget by construction.
func TestClassify_PriorSummaryCapped(t *testing.T) {
	fllm := &fakeLLM{response: json.RawMessage(`{"verdict":"no-match"}`)}
	huge := strings.Repeat("A", 4000)
	_ = acutetriage.Classify(context.Background(), fllm, currentKeyForClassify,
		candidateEntry(huge, 0.8))
	if len(fllm.lastUser) > 3000 {
		t.Errorf("prompt not bounded: %d bytes", len(fllm.lastUser))
	}
}
