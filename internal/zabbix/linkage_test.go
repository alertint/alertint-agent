// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/zabbix"
)

// TestMetricHistoryBounded_ExactOnlyNeverFuzzy proves the proactive path
// (F17) issues exactly one exact-filter item.get with the host scope and
// selectHosts linkage, and reports ErrNotFound — never a second fuzzy
// search — when no exact item exists.
func TestMetricHistoryBounded_ExactOnlyNeverFuzzy(t *testing.T) {
	var itemGets []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := readRPC(r)
		if call.Method == "item.get" {
			itemGets = append(itemGets, call.Params)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[],"id":1}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	now := time.Now()
	_, err := c.MetricHistoryBounded(context.Background(), "web01", "cpu.util", now.Add(-time.Hour), now, 10, nil, nil)
	if !errors.Is(err, zabbix.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if len(itemGets) != 1 {
		t.Fatalf("item.get calls = %d, want exactly 1 (no fuzzy fallback)", len(itemGets))
	}
	p := itemGets[0]
	if _, fuzzy := p["search"]; fuzzy {
		t.Fatal("proactive lookup must be an exact filter, never search")
	}
	if p["host"] != "web01" || p["selectHosts"] == nil {
		t.Fatalf("item.get must carry the host filter and selectHosts, got %v", p)
	}
}

// TestMetricHistoryBounded_RejectsItemNotLinkedToHost proves an item whose
// selectHosts data names a different host is ErrNotFound, with no history
// read.
func TestMetricHistoryBounded_RejectsItemNotLinkedToHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch readRPC(r).Method {
		case "item.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"100","hostid":"2","value_type":"0","hosts":[{"hostid":"2","host":"web02"}]}],"id":1}`))
		default:
			t.Fatal("history must not be read for an unlinked item")
		}
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	now := time.Now()
	_, err := c.MetricHistoryBounded(context.Background(), "web01", "system.cpu.util", now.Add(-time.Hour), now, 10, nil, nil)
	if !errors.Is(err, zabbix.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound for a foreign-host item", err)
	}
}

// TestMetricHistoryBounded_AcceptsLinkedItem is the positive twin: a
// linked item resolves and its history is read with the resolved
// value_type.
func TestMetricHistoryBounded_AcceptsLinkedItem(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch readRPC(r).Method {
		case "item.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"100","hostid":"1","value_type":"0","name":"CPU","hosts":[{"hostid":"1","host":"web01"}]}],"id":1}`))
		case "history.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"clock":"1750000000","value":"1.5"}],"id":1}`))
		}
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "t"})
	now := time.Now()
	s, err := c.MetricHistoryBounded(context.Background(), "web01", "system.cpu.util", now.Add(-time.Hour), now, 10, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s.ItemID != "100" || len(s.Points) != 1 {
		t.Fatalf("series = %+v", s)
	}
}

// TestProblemHistory_DropsForeignRows proves rows for another trigger or
// another host never become episodes and are counted as dropped.
func TestProblemHistory_DropsForeignRows(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := readRPC(r)
		if call.Params["value"] != nil {
			if call.Params["selectHosts"] == nil {
				t.Error("event.get must request selectHosts")
			}
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[
				{"eventid":"1","objectid":"5","clock":"100","r_eventid":"0","hosts":[{"hostid":"10","host":"web01"}]},
				{"eventid":"2","objectid":"6","clock":"101","r_eventid":"0","hosts":[{"hostid":"10","host":"web01"}]},
				{"eventid":"3","objectid":"5","clock":"102","r_eventid":"0","hosts":[{"hostid":"11","host":"web02"}]},
				{"eventid":"4","objectid":"5","clock":"103","r_eventid":"0"}
			]}`))
			return
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":[]}`))
	}))
	defer srv.Close()

	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	res, err := c.ProblemHistory(context.Background(), "web01", "5", time.Now().Add(-time.Hour), time.Now(), "", 20, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Episodes) != 1 || res.ForeignRowsDropped != 3 || res.Complete {
		t.Fatalf("episodes=%d dropped=%d, want 1 linked episode and 3 dropped", len(res.Episodes), res.ForeignRowsDropped)
	}
	if res.Episodes[0].EventID != "1" || res.Episodes[0].HostID != "10" {
		t.Fatalf("episode = %+v, want event 1 with its proven hostid", res.Episodes[0])
	}
}
