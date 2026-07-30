// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
