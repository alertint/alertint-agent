// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"

	"github.com/alertint/alertint-agent/internal/logs/loki"
	"github.com/alertint/alertint-agent/internal/observation"
	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/prometheus"
	"github.com/alertint/alertint-agent/internal/sentry"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// redirectingServer answers every request with a 302 to a fresh path (so a
// redirect-following client would keep issuing new physical requests) and
// counts the physical requests it actually received.
func redirectingServer(t *testing.T) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var physical atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := physical.Add(1)
		http.Redirect(w, r, "/redirected/"+strconv.Itoa(int(n)), http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	return srv, &physical
}

// assertRedirectRefused is the F19 contract every proactive connector must
// meet: a 3xx is a transport failure with outcome code redirect_refused,
// exactly ONE physical request was made, and exactly one before/after
// reservation pair accounts for it — never a second, unreserved dispatch.
func assertRedirectRefused(t *testing.T, name string, physical *atomic.Int32, rec *capturingRecorder, err error) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: a refused redirect must fail the plan as a transport failure", name)
	}
	if got := physical.Load(); got != 1 {
		t.Fatalf("%s: physical requests = %d, want exactly 1 (redirects must never be followed)", name, got)
	}
	if rec.reservations != 1 || len(rec.outcomes) != 1 {
		t.Fatalf("%s: reservations=%d outcomes=%d, want one before/after pair", name, rec.reservations, len(rec.outcomes))
	}
	if got := rec.outcomes[0].Code; got != "redirect_refused" {
		t.Fatalf("%s: outcome code = %q, want redirect_refused", name, got)
	}
	if rec.outcomes[0].RequestStarted != model.RequestStartedTrue {
		t.Fatalf("%s: request started = %q, want true (the 3xx response was received)", name, rec.outcomes[0].RequestStarted)
	}
}

func TestPrometheusExecutorRefusesRedirects(t *testing.T) {
	srv, physical := redirectingServer(t)
	e := &PrometheusExecutor{Client: prometheus.NewClient(prometheus.Config{BaseURL: srv.URL, TimeoutSeconds: 5})}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	rec := &capturingRecorder{}
	_, err := e.Execute(context.Background(), plan, rec)
	assertRedirectRefused(t, "prometheus", physical, rec, err)
}

func TestLokiExecutorRefusesRedirects(t *testing.T) {
	srv, physical := redirectingServer(t)
	e := &LokiExecutor{Client: loki.NewClient(loki.Config{BaseURL: srv.URL, TimeoutSeconds: 5, LineFilter: `|~ "error"`})}
	plan := testStorePlan()
	plan.Scope.Labels = map[string]string{"service": "checkout"}
	rec := &capturingRecorder{}
	_, err := e.Execute(context.Background(), plan, rec)
	// With a line_filter configured the client would normally fall back to
	// an unfiltered second query on an empty result; a refused redirect must
	// short-circuit before that too.
	assertRedirectRefused(t, "loki", physical, rec, err)
}

func TestSentryExecutorRefusesRedirects(t *testing.T) {
	srv, physical := redirectingServer(t)
	e := &SentryExecutor{
		Client:     sentry.NewClient(sentry.Config{BaseURL: srv.URL, Org: "acme", Token: "t", TimeoutSeconds: 5}),
		ProjectEnv: mappedProjectEnv("checkout", "prod"),
	}
	rec := &capturingRecorder{}
	_, err := e.Execute(context.Background(), testStorePlan(), rec)
	// Sentry's own retry loop must treat a 3xx as non-retryable: one attempt.
	assertRedirectRefused(t, "sentry", physical, rec, err)
}

func TestZabbixExecutorsRefuseRedirects(t *testing.T) {
	run := func(t *testing.T, name string, exec observation.Executor, plan model.Plan, physical *atomic.Int32) {
		t.Helper()
		rec := &capturingRecorder{}
		_, err := exec.Execute(context.Background(), plan, rec)
		assertRedirectRefused(t, name, physical, rec, err)
	}

	t.Run("metric", func(t *testing.T) {
		srv, physical := redirectingServer(t)
		client := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok", TimeoutSeconds: 5})
		run(t, "zabbix metric", &ZabbixMetricExecutor{Client: client},
			planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "system.cpu.util"}), physical)
	})
	t.Run("problem", func(t *testing.T) {
		srv, physical := redirectingServer(t)
		client := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok", TimeoutSeconds: 5})
		plan := testStorePlan()
		plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "18422"})
		run(t, "zabbix problem", &ZabbixProblemExecutor{Client: client}, plan, physical)
	})
}
