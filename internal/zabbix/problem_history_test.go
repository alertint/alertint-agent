// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/zabbix"
)

type rpcCall struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

func readRPC(r *http.Request) rpcCall {
	body, _ := io.ReadAll(r.Body)
	var c rpcCall
	_ = json.Unmarshal(body, &c)
	return c
}

// TestProblemHistoryResolvesRecoveryClock exercises the exact scenario
// plan.md pins: a problem event at clock=1788714000 recovered by event 20
// at clock=1788714300 — a 300s episode with UTC source_api timing.
func TestProblemHistoryResolvesRecoveryClock(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		call := readRPC(r)
		switch {
		case call.Method == "event.get" && call.Params["value"] != nil:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[
				{"eventid":"18422","objectid":"18422","clock":"1788714000","r_eventid":"20",
				 "severity":"3","acknowledged":"0","suppressed":"0","cause_eventid":"0","tags":[]}
			]}`))
		case call.Method == "event.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[{"eventid":"20","clock":"1788714300"}]}`))
		default:
			t.Fatalf("unexpected method %q", call.Method)
		}
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	res, err := c.ProblemHistory(context.Background(), "web01", "18422",
		time.Unix(1788714000, 0).Add(-time.Minute), time.Unix(1788714600, 0), "", 20, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Episodes) != 1 {
		t.Fatalf("episodes = %d, want 1", len(res.Episodes))
	}
	ep := res.Episodes[0]
	if ep.Ongoing {
		t.Fatal("expected a resolved episode, got Ongoing")
	}
	if ep.Recovery == nil {
		t.Fatal("expected a resolved recovery time")
	}
	gotDuration := ep.Recovery.Sub(ep.Start)
	if gotDuration != 300*time.Second {
		t.Fatalf("episode duration = %v, want 300s", gotDuration)
	}
	if ep.Start.Location() != time.UTC || ep.Recovery.Location() != time.UTC {
		t.Fatal("expected UTC timestamps")
	}
	if calls != 2 {
		t.Fatalf("physical calls = %d, want 2 (primary + recovery batch)", calls)
	}
}

func TestProblemHistoryMissingRecoveryEventIsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := readRPC(r)
		switch {
		case call.Params["value"] != nil:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[
				{"eventid":"1","objectid":"1","clock":"1788714000","r_eventid":"99",
				 "severity":"2","acknowledged":"0","suppressed":"0","cause_eventid":"0"}
			]}`))
		default:
			// The recovery event lookup returns nothing — the recovery event
			// is empty/inaccessible.
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[]}`))
		}
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	res, err := c.ProblemHistory(context.Background(), "web01", "1", time.Now().Add(-time.Hour), time.Now(), "", 20, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Episodes[0].Ongoing {
		t.Fatal("an r_eventid-carrying event must not report Ongoing")
	}
	if !res.Episodes[0].RecoveryUnknown {
		t.Fatal("expected RecoveryUnknown for an inaccessible recovery event")
	}
	if res.Episodes[0].Recovery != nil {
		t.Fatal("must never fabricate a recovery time")
	}
	if res.UnresolvedRecoveryCount != 1 {
		t.Fatalf("unresolved recovery count = %d, want 1", res.UnresolvedRecoveryCount)
	}
}

func TestProblemHistoryStillOngoingWithoutRecoveryEvent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[
			{"eventid":"1","objectid":"1","clock":"1788714000","r_eventid":"0",
			 "severity":"3","acknowledged":"0","suppressed":"0","cause_eventid":"0"}
		]}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	res, err := c.ProblemHistory(context.Background(), "web01", "1", time.Now().Add(-time.Hour), time.Now(), "", 20, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Episodes[0].Ongoing {
		t.Fatal("r_eventid=0 must report Ongoing")
	}
	if res.Episodes[0].RecoveryUnknown {
		t.Fatal("an ongoing episode is not RecoveryUnknown")
	}
}

func TestProblemHistoryTruncatesAtLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := readRPC(r)
		limitVal, _ := call.Params["limit"].(float64)
		limit := int(limitVal)
		if limit != 3 {
			t.Fatalf("limit sent = %d, want 3 (2+1 overflow sentinel)", limit)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[
			{"eventid":"1","objectid":"1","clock":"1","r_eventid":"0"},
			{"eventid":"2","objectid":"1","clock":"2","r_eventid":"0"},
			{"eventid":"3","objectid":"1","clock":"3","r_eventid":"0"}
		]}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	res, err := c.ProblemHistory(context.Background(), "web01", "1", time.Now().Add(-time.Hour), time.Now(), "", 2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || res.Complete {
		t.Fatal("expected a truncated, incomplete result")
	}
	if len(res.Episodes) != 2 {
		t.Fatalf("episodes = %d, want 2 (bounded)", len(res.Episodes))
	}
}

func TestProblemHistoryBudgetExhaustedDuringRecoveryLookupPreservesPrimaryResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[
			{"eventid":"1","objectid":"1","clock":"1788714000","r_eventid":"20",
			 "severity":"3","acknowledged":"0","suppressed":"0","cause_eventid":"0"}
		]}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	var calls int
	before := func() error {
		calls++
		if calls == 2 {
			return errBudgetExhausted
		}
		return nil
	}
	res, err := c.ProblemHistory(context.Background(), "web01", "1", time.Now().Add(-time.Hour), time.Now(), "", 20, before, func(bool, error) {})
	if err != nil {
		t.Fatalf("primary evidence must survive a budget-withheld secondary lookup: %v", err)
	}
	if len(res.Episodes) != 1 {
		t.Fatalf("episodes = %d, want 1 (primary result preserved)", len(res.Episodes))
	}
	if !res.Episodes[0].RecoveryUnknown {
		t.Fatal("expected RecoveryUnknown when the recovery lookup was withheld by budget")
	}
}

func TestEventLifecycleOngoing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[{"eventid":"1","clock":"100","r_eventid":"0"}]}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})

	got, err := c.EventLifecycle(context.Background(), "1", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Ongoing || got.Recovery != nil {
		t.Fatalf("expected ongoing with no recovery: %+v", got)
	}
}

func TestEventLifecycleResolved(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := readRPC(r)
		ids, _ := call.Params["eventids"].([]any)
		if ids[0] == "2" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[{"eventid":"2","clock":"200","r_eventid":"5"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[{"eventid":"5","clock":"260"}]}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})

	got, err := c.EventLifecycle(context.Background(), "2", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ongoing {
		t.Fatal("expected a resolved event")
	}
	if got.Recovery == nil || got.Recovery.Sub(got.Start) != 60*time.Second {
		t.Fatalf("expected a 60s episode, got %+v", got)
	}
}

var errBudgetExhausted = &testError{"budget exhausted"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
