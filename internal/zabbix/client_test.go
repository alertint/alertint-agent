// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/zabbix"
)

func TestAPIVersion_SendsNoAuthAndUnwrapsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json-rpc" {
			t.Errorf("content-type: got %q", ct)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("apiinfo.version must not send auth, got %q", auth)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"7.0.0","id":1}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	v, err := c.APIVersion(context.Background())
	if err != nil || v != "7.0.0" {
		t.Fatalf("got (%q,%v) want (7.0.0,nil)", v, err)
	}
}

func TestCall_SurfacesJSONRPCError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Bearer tok" {
			t.Errorf("auth: got %q want 'Bearer tok'", auth)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params","data":"bad"},"id":1}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	_, err := c.OpenProblems(context.Background(), "web01", zabbix.ProblemSelector{})
	if err == nil || !strings.Contains(err.Error(), "Invalid params") {
		t.Fatalf("want JSON-RPC error surfaced, got %v", err)
	}
}

func TestMetricHistory_ResolvesValueTypeForFloat(t *testing.T) {
	var gotHistoryParam string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		switch req.Method {
		case "item.get": // float item → value_type "0"
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"100","value_type":"0","name":"CPU","units":"%"}],"id":1}`))
		case "history.get":
			if hv, ok := req.Params["history"]; ok {
				gotHistoryParam = fmt.Sprintf("%v", hv)
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"clock":"1750000000","value":"93.2"}],"id":1}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[],"id":1}`))
		}
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t", HistoryRetentionDays: 7})
	now := time.Now()
	s, err := c.MetricHistory(context.Background(), "web01", "system.cpu.util", now.Add(-30*time.Minute), now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if gotHistoryParam != "0" { // MUST pass the resolved float type, not the default 3
		t.Fatalf("history param: got %q want 0 (float)", gotHistoryParam)
	}
	if s.Source != "history" || len(s.Points) != 1 {
		t.Fatalf("series: got source=%q points=%d", s.Source, len(s.Points))
	}
}

// TestMetricHistory_ExactKeyWinsOverAmbiguousSubstring proves an unambiguous
// key resolves via an exact filter, never a fuzzy substring search that could
// silently pick an unrelated longer key (e.g. system.cpu.util[,iowait]) that
// happens to substring-match the requested one.
func TestMetricHistory_ExactKeyWinsOverAmbiguousSubstring(t *testing.T) {
	var sawSearch bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		switch req.Method {
		case "item.get":
			if _, ok := req.Params["search"]; ok {
				sawSearch = true
			}
			// The exact filter matches immediately — no ambiguity, no fuzzy fallback.
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"100","value_type":"0"}],"id":1}`))
		case "history.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"clock":"1750000000","value":"1"}],"id":1}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[],"id":1}`))
		}
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	now := time.Now()
	if _, err := c.MetricHistory(context.Background(), "web01", "system.cpu.util", now.Add(-time.Hour), now, 100); err != nil {
		t.Fatal(err)
	}
	if sawSearch {
		t.Fatal("an exact match must resolve via filter alone, never falling back to search")
	}
}

// TestMetricHistory_FuzzyFallbackWhenNoExactMatch proves the fuzzy search
// still runs (as a second call) when no item exactly matches the given key.
func TestMetricHistory_FuzzyFallbackWhenNoExactMatch(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		switch req.Method {
		case "item.get":
			calls++
			if _, ok := req.Params["filter"]; ok {
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[],"id":1}`)) // no exact match
				return
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"101","value_type":"0"}],"id":1}`))
		case "history.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"clock":"1750000000","value":"1"}],"id":1}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[],"id":1}`))
		}
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	now := time.Now()
	s, err := c.MetricHistory(context.Background(), "web01", "cpu.util", now.Add(-time.Hour), now, 100)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("want exact-then-fuzzy = 2 item.get calls, got %d", calls)
	}
	if s.ItemID != "101" {
		t.Fatalf("want the fuzzy-matched item, got %+v", s)
	}
}

func TestMetricHistory_OldWindowUsesTrends(t *testing.T) {
	var calledTrend bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &req)
		switch req.Method {
		case "item.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"100","value_type":"0"}],"id":1}`))
		case "trend.get":
			calledTrend = true
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"clock":"1740000000","value_avg":"50","value_min":"10","value_max":"90"}],"id":1}`))
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[],"id":1}`))
		}
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t", HistoryRetentionDays: 7})
	to := time.Now().Add(-30 * 24 * time.Hour) // older than retention
	s, err := c.MetricHistory(context.Background(), "web01", "k", to.Add(-time.Hour), to, 100)
	if err != nil {
		t.Fatal(err)
	}
	if !calledTrend || s.Source != "trends" {
		t.Fatalf("want trend.get used, got calledTrend=%v source=%q", calledTrend, s.Source)
	}
}

func TestHostGroups_ResolvesNamesToIDsAndCounts(t *testing.T) {
	var gotMethod string
	var gotParams map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		gotMethod, gotParams = req.Method, req.Params
		// selectHosts:"count" renders the count as a string in "hosts".
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[
			{"groupid":"4","name":"Databases","hosts":"17"},
			{"groupid":"9","name":"Linux servers","hosts":"77"}],"id":1}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	infos, err := c.HostGroups(context.Background(), []string{"Databases", "Linux servers"})
	if err != nil {
		t.Fatalf("HostGroups: %v", err)
	}
	if gotMethod != "hostgroup.get" {
		t.Fatalf("method = %q, want hostgroup.get", gotMethod)
	}
	if gotParams["selectHosts"] != "count" {
		t.Fatalf("selectHosts = %v, want count", gotParams["selectHosts"])
	}
	want := []zabbix.HostGroupInfo{{GroupID: "4", Name: "Databases", Hosts: 17}, {GroupID: "9", Name: "Linux servers", Hosts: 77}}
	if !reflect.DeepEqual(infos, want) {
		t.Fatalf("infos = %+v, want %+v", infos, want)
	}
}

// TestHostGroups_MalformedHostsCountReturnsError guards against a degraded or
// proxied Zabbix response silently ranking a group as size 0 (the parse
// error must surface, not be swallowed) — a size-0 group would jump the
// queue in the neighbor check's smallest-first scope selection ahead of
// legitimately small groups.
func TestHostGroups_MalformedHostsCountReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[
			{"groupid":"4","name":"Databases","hosts":"not-a-number"}],"id":1}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	infos, err := c.HostGroups(context.Background(), []string{"Databases"})
	if err == nil {
		t.Fatalf("HostGroups: want error on malformed host count, got infos = %+v", infos)
	}
	if !strings.Contains(err.Error(), "Databases") {
		t.Fatalf("err = %v, want it to name the offending group", err)
	}
}

func TestGroupOpenProblems_QueriesByGroupIDs(t *testing.T) {
	var gotMethod string
	var gotParams map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		gotMethod, gotParams = req.Method, req.Params
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[
			{"eventid":"101","name":"Disk full","severity":"4","clock":"1700000000","acknowledged":"0","suppressed":"1","tags":[]}],"id":1}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	probs, err := c.GroupOpenProblems(context.Background(), []string{"4", "9"}, zabbix.ProblemSelector{})
	if err != nil {
		t.Fatalf("GroupOpenProblems: %v", err)
	}
	if gotMethod != "problem.get" {
		t.Fatalf("method = %q, want problem.get", gotMethod)
	}
	if _, ok := gotParams["hostids"]; ok {
		t.Fatal("hostids must not be set on a group-scoped query")
	}
	if got, ok := gotParams["groupids"].([]any); !ok || len(got) != 2 {
		t.Fatalf("groupids = %v, want 2 ids", got)
	}
	if len(probs) != 1 || probs[0].EventID != "101" || !probs[0].Suppressed {
		t.Fatalf("probs = %+v", probs)
	}
}

func TestHostContext_NoHostWrapsErrNotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[],"id":1}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	_, err := c.HostContext(context.Background(), "ghost")
	if !errors.Is(err, zabbix.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestProblemHistoryUsesAssociatedRecoveryEventClock(t *testing.T) {
	var methods []string
	var problemParams, recoveryParams map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, req.Method)
		switch req.Method {
		case "host.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"hostid":"17"}],"id":1}`))
		case "event.get":
			if _, recovering := req.Params["eventids"]; recovering {
				recoveryParams = req.Params
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"eventid":"601","clock":"1787187600"}],"id":1}`))
				return
			}
			problemParams = req.Params
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{
				"eventid":"501","objectid":"71","name":"CPU {$WINDOW}","clock":"1787184000","r_eventid":"601",
				"severity":"4","acknowledged":"1","suppressed":"0","tags":[{"tag":"service","value":"db"}],"cause_eventid":"99"
			}],"id":1}`))
		default:
			t.Fatalf("unexpected method %q", req.Method)
		}
	}))
	defer srv.Close()

	client := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	start := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 8, 21, 0, 0, 0, 0, time.UTC)
	rows, err := client.ProblemHistory(context.Background(), "db-1", start, end, "3", 20)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
	row := rows[0]
	if row.StartedAt.Unix() != 1787184000 || row.ResolvedAt == nil || row.ResolvedAt.Unix() != 1787187600 || row.Ongoing || row.DurationSeconds != 3600 {
		t.Fatalf("row=%+v", row)
	}
	if row.EventID != "501" || row.TriggerID != "71" || row.Name != "CPU {$WINDOW}" || !row.Acknowledged || row.Suppressed || row.CauseEventID != "99" {
		t.Fatalf("identity row=%+v", row)
	}
	if !reflect.DeepEqual(methods, []string{"host.get", "event.get", "event.get"}) {
		t.Fatalf("methods=%v", methods)
	}
	if got := problemParams["hostids"]; !reflect.DeepEqual(got, []any{"17"}) {
		t.Fatalf("hostids=%v", got)
	}
	if problemParams["value"] != float64(1) || problemParams["source"] != float64(0) || problemParams["object"] != float64(0) {
		t.Fatalf("read-only problem-event params=%v", problemParams)
	}
	if problemParams["problem_time_from"] != float64(start.Unix()) || problemParams["problem_time_till"] != float64(end.Unix()) || problemParams["time_from"] != nil || problemParams["time_till"] != nil {
		t.Fatalf("overlap params=%v", problemParams)
	}
	output, ok := problemParams["output"].([]any)
	if !ok {
		t.Fatalf("output=%T %v", problemParams["output"], problemParams["output"])
	}
	for _, field := range output {
		if field == "r_clock" {
			t.Fatalf("unsupported event.get r_clock requested: %v", output)
		}
	}
	if got := recoveryParams["eventids"]; !reflect.DeepEqual(got, []any{"601"}) {
		t.Fatalf("recovery eventids=%v", got)
	}
}

func TestProblemHistoryPreservesTruncationAndOngoingDuration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string         `json:"method"`
			Params map[string]any `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "host.get" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"hostid":"17"}],"id":1}`))
			return
		}
		if req.Params["limit"] != float64(2) {
			t.Fatalf("limit=%v, want limit+1", req.Params["limit"])
		}
		if req.Params["problem_time_from"] != float64(1787184000) || req.Params["problem_time_till"] != float64(1787187600) {
			t.Fatalf("overlap params=%v", req.Params)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[
			{"eventid":"2","objectid":"7","name":"ongoing","clock":"1787180000","r_eventid":"0","severity":"3","acknowledged":"0","suppressed":"0","tags":[]},
			{"eventid":"1","objectid":"7","name":"older","clock":"1787170000","r_eventid":"0","severity":"3","acknowledged":"0","suppressed":"0","tags":[]}
		],"id":1}`))
	}))
	defer srv.Close()
	client := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	start := time.Unix(1787184000, 0).UTC()
	end := time.Unix(1787187600, 0).UTC()
	rows, err := client.ProblemHistory(context.Background(), "db-1", start, end, "3", 1)
	if err != nil || len(rows) != 1 || !rows[0].Ongoing || !rows[0].Truncated || rows[0].DurationSeconds != 7600 || !rows[0].StartedAt.Before(start) {
		t.Fatalf("rows=%+v err=%v", rows, err)
	}
}

func TestProblemHistoryRejectsMalformedSourceClock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Method == "host.get" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"hostid":"17"}],"id":1}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"eventid":"1","objectid":"7","name":"bad","clock":"not-a-clock","r_eventid":"0","severity":"3"}],"id":1}`))
	}))
	defer srv.Close()
	client := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	_, err := client.ProblemHistory(context.Background(), "db-1", time.Now().UTC().Add(-time.Hour), time.Now().UTC(), "3", 1)
	if err == nil || !strings.Contains(err.Error(), "clock") {
		t.Fatalf("err=%v", err)
	}
}
