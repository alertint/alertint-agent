// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

func oversizedRPCBody() []byte {
	pad := strings.Repeat("x", model.MaxDecodedResponseBytes)
	return []byte(`{"jsonrpc":"2.0","id":1,"result":[],"pad":"` + pad + `"}`)
}

// TestProblemHistory_RefusesOversizedDecodedBody proves the instrumented
// (proactive) JSON-RPC path caps the decoded body at
// model.MaxDecodedResponseBytes and reports ErrResponseTooLarge after
// exactly one accounted physical request (F10).
func TestProblemHistory_RefusesOversizedDecodedBody(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		_, _ = w.Write(oversizedRPCBody())
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	var befores int
	var afterErrs []error
	_, err := c.ProblemHistory(context.Background(), "web01", "1", time.Now().Add(-time.Hour), time.Now(), "", 20,
		func() error { befores++; return nil },
		func(started bool, err error) { afterErrs = append(afterErrs, err) })
	if !errors.Is(err, zabbix.ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
	if calls != 1 || befores != 1 || len(afterErrs) != 1 || !errors.Is(afterErrs[0], zabbix.ErrResponseTooLarge) {
		t.Fatalf("physical=%d befores=%d afters=%v, want one accounted request carrying the sentinel", calls, befores, afterErrs)
	}
}

// TestMetricHistoryBounded_RefusesOversizedDecodedBody covers the
// metric-range capability's own instrumented path.
func TestMetricHistoryBounded_RefusesOversizedDecodedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if readRPC(r).Method == "item.get" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"100","value_type":"0"}],"id":1}`))
			return
		}
		_, _ = w.Write(oversizedRPCBody())
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	now := time.Now()
	_, err := c.MetricHistoryBounded(context.Background(), "web01", "system.cpu.util", now.Add(-time.Hour), now, 100,
		func() error { return nil }, func(bool, error) {})
	if !errors.Is(err, zabbix.ErrResponseTooLarge) {
		t.Fatalf("err = %v, want ErrResponseTooLarge", err)
	}
}

// redirectServer answers the first two requests with a 307 (which a
// following client would re-POST) and the third with body, counting
// physical requests.
func redirectServer(t *testing.T, body string) (*httptest.Server, *int32) {
	t.Helper()
	var physical int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		physical++
		if physical < 3 {
			http.Redirect(w, r, "/hop/"+strconv.Itoa(int(physical))+"/api_jsonrpc.php", http.StatusTemporaryRedirect)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &physical
}

// TestProblemHistory_RefusesRedirect proves the instrumented JSON-RPC path
// treats a 3xx as the final answer (ErrRedirectRefused, reported through
// after()) after exactly one physical request — never a re-POST (F19).
func TestProblemHistory_RefusesRedirect(t *testing.T) {
	srv, physical := redirectServer(t, `{"jsonrpc":"2.0","id":1,"result":[]}`)
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	var befores int
	var afterErrs []error
	_, err := c.ProblemHistory(context.Background(), "web01", "1", time.Now().Add(-time.Hour), time.Now(), "", 20,
		func() error { befores++; return nil },
		func(started bool, err error) { afterErrs = append(afterErrs, err) })
	if !errors.Is(err, zabbix.ErrRedirectRefused) {
		t.Fatalf("err = %v, want ErrRedirectRefused", err)
	}
	if *physical != 1 || befores != 1 || len(afterErrs) != 1 || !errors.Is(afterErrs[0], zabbix.ErrRedirectRefused) {
		t.Fatalf("physical=%d befores=%d afters=%v, want one accounted request carrying the sentinel", *physical, befores, afterErrs)
	}
}

// TestMetricHistory_LegacyFollowsRedirect pins that the legacy
// uninstrumented path keeps http.Client's default redirect policy.
func TestMetricHistory_LegacyFollowsRedirect(t *testing.T) {
	srv, physical := redirectServer(t, `{"jsonrpc":"2.0","id":1,"result":[{"itemid":"100","value_type":"0"}]}`)
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	now := time.Now()
	if _, err := c.MetricHistory(context.Background(), "web01", "k", now.Add(-time.Hour), now, 10); err != nil {
		t.Fatalf("legacy MetricHistory must still follow redirects: %v", err)
	}
	if *physical < 3 {
		t.Fatalf("physical requests = %d, want the two hops followed", *physical)
	}
}

// TestMetricHistory_LegacyPathNotCapped pins that the existing
// uninstrumented MetricHistory (Acute Triage / MCP) stays unbounded and
// keeps its exact-then-fuzzy item resolution.
func TestMetricHistory_LegacyPathNotCapped(t *testing.T) {
	pad := strings.Repeat("x", model.MaxDecodedResponseBytes)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if readRPC(r).Method == "item.get" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"100","value_type":"0"}],"id":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[{"clock":"1750000000","value":"1"}],"pad":"` + pad + `"}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	now := time.Now()
	s, err := c.MetricHistory(context.Background(), "web01", "system.cpu.util", now.Add(-time.Hour), now, 100)
	if err != nil {
		t.Fatalf("legacy MetricHistory must remain uncapped: %v", err)
	}
	if len(s.Points) != 1 {
		t.Fatalf("points = %d, want 1", len(s.Points))
	}
}
