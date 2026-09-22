// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
)

// oversizedEnvelope is a syntactically valid success envelope whose decoded
// size is just past model.MaxDecodedResponseBytes.
func oversizedEnvelope() []byte {
	pad := strings.Repeat("x", model.MaxDecodedResponseBytes)
	return []byte(`{"status":"success","data":{"resultType":"matrix","result":[],"pad":"` + pad + `"}}`)
}

func gzipped(t *testing.T, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestQueryRangeBounded_RefusesOversizedDecodedBody proves the proactive
// path never buffers a decoded body past model.MaxDecodedResponseBytes: it
// returns ErrResponseTooLarge instead of decoding it (F10).
func TestQueryRangeBounded_RefusesOversizedDecodedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(oversizedEnvelope())
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	end := time.Now()
	_, err := c.QueryRangeBounded(context.Background(), `up`, end.Add(-time.Hour), end, 0, 21)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

// TestQueryRangeBounded_GzipIsCappedAfterDecoding proves the cap applies to
// the DECODED stream: a small gzip body on the wire that inflates past the
// cap is refused, while a small gzip body that inflates within the cap is
// transparently decoded by http.Transport and parsed normally.
func TestQueryRangeBounded_GzipIsCappedAfterDecoding(t *testing.T) {
	big := gzipped(t, oversizedEnvelope())
	small := gzipped(t, []byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	if len(big) > 64*1024 {
		t.Fatalf("test premise: the oversized body must compress small on the wire, got %d bytes", len(big))
	}

	var serveBig bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") == "" {
			t.Error("http.Transport must negotiate gzip itself so the body arrives decoded")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		if serveBig {
			_, _ = w.Write(big)
			return
		}
		_, _ = w.Write(small)
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	end := time.Now()
	if _, err := c.QueryRangeBounded(context.Background(), `up`, end.Add(-time.Hour), end, 0, 21); err != nil {
		t.Fatalf("small gzip body must decode transparently: %v", err)
	}
	serveBig = true
	_, err := c.QueryRangeBounded(context.Background(), `up`, end.Add(-time.Hour), end, 0, 21)
	if !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge for a gzip body that inflates past the cap", err)
	}
}

// redirectServer answers every request with a 302 to a fresh path and
// counts the physical requests received, so a redirect-following client is
// visibly distinguishable from a refusing one.
func redirectServer(t *testing.T, final []byte) (*httptest.Server, *int32) {
	t.Helper()
	var physical int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		physical++
		if physical < 3 {
			http.Redirect(w, r, "/hop/"+strconv.Itoa(int(physical)), http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(final)
	}))
	t.Cleanup(srv.Close)
	return srv, &physical
}

// TestQueryRangeBounded_RefusesRedirect proves the bounded path treats a
// 3xx as the final answer (ErrRedirectRefused) after exactly one physical
// request — a followed redirect would be an unreserved second dispatch
// (F19).
func TestQueryRangeBounded_RefusesRedirect(t *testing.T) {
	srv, physical := redirectServer(t, []byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	c := NewClient(Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	end := time.Now()
	_, err := c.QueryRangeBounded(context.Background(), `up`, end.Add(-time.Hour), end, 0, 21)
	if !errors.Is(err, ErrRedirectRefused) {
		t.Fatalf("err = %v, want ErrRedirectRefused", err)
	}
	if *physical != 1 {
		t.Fatalf("physical requests = %d, want 1", *physical)
	}
}

// TestQueryRange_LegacyFollowsRedirect pins that the legacy path keeps
// http.Client's default redirect policy.
func TestQueryRange_LegacyFollowsRedirect(t *testing.T) {
	srv, physical := redirectServer(t, []byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`))
	c := NewClient(Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	end := time.Now()
	if _, err := c.QueryRange(context.Background(), `up`, end.Add(-time.Hour), end, 0); err != nil {
		t.Fatalf("legacy QueryRange must still follow redirects: %v", err)
	}
	if *physical != 3 {
		t.Fatalf("physical requests = %d, want 3 (two hops followed)", *physical)
	}
}

// TestQueryRange_LegacyPathNotCapped pins that the existing unbounded
// QueryRange (MCP passthrough) is unaffected by the bounded sibling's cap.
func TestQueryRange_LegacyPathNotCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(oversizedEnvelope())
	}))
	defer srv.Close()

	c := NewClient(Config{BaseURL: srv.URL, TimeoutSeconds: 5})
	end := time.Now()
	if _, err := c.QueryRange(context.Background(), `up`, end.Add(-time.Hour), end, 0); err != nil {
		t.Fatalf("legacy QueryRange must remain uncapped: %v", err)
	}
}
