// SPDX-License-Identifier: FSL-1.1-ALv2

package zabbix

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func baseRuleSnapshot() ruleSnapshot {
	return ruleSnapshot{
		RootTriggerID: "1001",
		Triggers: []ruleTrigger{{
			TriggerID: "1001", Description: "CPU high", EventName: "CPU high on {HOST.NAME}",
			Status: "0", Priority: "2", Type: "0", Expression: "avg(/db/system.cpu.util,5m)>80",
			RecoveryMode: "1", RecoveryExpression: "avg(/db/system.cpu.util,5m)<60",
			CorrelationMode: "0", ManualClose: "0", TemplateID: "9001", UUID: "trigger-uuid",
			Hosts:     []zHostRef{{HostID: "42", Host: "db-prod-1"}},
			Functions: []ruleFunction{{ItemID: "2001", Function: "avg", Parameter: "5m"}},
			Tags:      []KV{{Tag: "service", Value: "billing"}, {Tag: "scope", Value: "capacity"}},
		}},
		Items: []ruleItem{{
			ItemID: "2001", HostID: "42", TemplateID: "8001", Key: "system.cpu.util",
			Type: "0", ValueType: "0", Status: "0", Delay: "1m", MasterItemID: "0", ValueMapID: "0",
			Preprocessing: []rulePreprocessing{{Type: "1", Params: "2", ErrorHandler: "0"}},
		}},
	}
}

func TestCanonicalRuleVersionStableAcrossUnorderedRows(t *testing.T) {
	a := baseRuleSnapshot()
	b := baseRuleSnapshot()
	b.Triggers[0].Tags[0], b.Triggers[0].Tags[1] = b.Triggers[0].Tags[1], b.Triggers[0].Tags[0]
	b.Triggers[0].Hosts = append([]zHostRef{{HostID: "99", Host: "other"}}, b.Triggers[0].Hosts...)
	a.Triggers[0].Hosts = append(a.Triggers[0].Hosts, zHostRef{HostID: "99", Host: "other"})

	av, err := canonicalRuleVersion("prod-zbx", "endpoint-a", a)
	if err != nil {
		t.Fatal(err)
	}
	bv, err := canonicalRuleVersion("prod-zbx", "endpoint-a", b)
	if err != nil {
		t.Fatal(err)
	}
	if av.Version != bv.Version {
		t.Fatalf("reordered source rows changed version: %s != %s", av.Version, bv.Version)
	}
}

func TestCanonicalRuleVersionChangesForRelevantConfiguration(t *testing.T) {
	base := baseRuleSnapshot()
	want, err := canonicalRuleVersion("prod-zbx", "endpoint-a", base)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*ruleSnapshot){
		"problem expression":  func(s *ruleSnapshot) { s.Triggers[0].Expression += "+1" },
		"recovery expression": func(s *ruleSnapshot) { s.Triggers[0].RecoveryExpression += "+1" },
		"severity":            func(s *ruleSnapshot) { s.Triggers[0].Priority = "4" },
		"enabled state":       func(s *ruleSnapshot) { s.Triggers[0].Status = "1" },
		"scope tag":           func(s *ruleSnapshot) { s.Triggers[0].Tags[0].Value = "payments" },
		"item key":            func(s *ruleSnapshot) { s.Items[0].Key = "system.cpu.load" },
		"preprocessing":       func(s *ruleSnapshot) { s.Items[0].Preprocessing[0].Params = "3" },
		"installation":        func(s *ruleSnapshot) {},
		"endpoint":            func(s *ruleSnapshot) {},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			gotSnapshot := baseRuleSnapshot()
			mutate(&gotSnapshot)
			instance := "prod-zbx"
			endpoint := "endpoint-a"
			if name == "installation" {
				instance = "staging-zbx"
			}
			if name == "endpoint" {
				endpoint = "endpoint-b"
			}
			got, err := canonicalRuleVersion(instance, endpoint, gotSnapshot)
			if err != nil {
				t.Fatal(err)
			}
			if got.Version == want.Version {
				t.Fatalf("%s did not change version", name)
			}
		})
	}
}

func TestCanonicalRuleVersionRejectsUnsupportedEffectiveInputs(t *testing.T) {
	cases := map[string]func(*ruleSnapshot){
		"item macro":        func(s *ruleSnapshot) { s.Items[0].Delay = "{$CPU_INTERVAL}" },
		"tag macro":         func(s *ruleSnapshot) { s.Triggers[0].Tags[0].Value = "{$SERVICE}" },
		"masked expression": func(s *ruleSnapshot) { s.Triggers[0].Expression = "last(/db/key)>******" },
		"dependent item":    func(s *ruleSnapshot) { s.Items[0].Type, s.Items[0].MasterItemID = "18", "2999" },
		"nested dependency": func(s *ruleSnapshot) {
			s.Triggers = append(s.Triggers, ruleTrigger{TriggerID: "1002", Dependencies: []string{"1003"}})
			s.Triggers[0].Dependencies = []string{"1002"}
		},
		"duplicate trigger": func(s *ruleSnapshot) { s.Triggers = append(s.Triggers, s.Triggers[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := baseRuleSnapshot()
			mutate(&s)
			if _, err := canonicalRuleVersion("prod-zbx", "endpoint-a", s); err == nil {
				t.Fatal("expected unavailable configuration")
			}
		})
	}
}

func TestSourceRuleVersionBoundedRejectsConfigurationChangingBetweenReads(t *testing.T) {
	triggerCalls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req.Method == "item.get" {
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"itemid":"2001","hostid":"42","templateid":"8001","key_":"system.cpu.util","type":"0","value_type":"0","status":"0","delay":"1m","params":"","master_itemid":"0","valuemapid":"0","preprocessing":[]}],"id":1}`))
			return
		}
		triggerCalls++
		priority := "2"
		if triggerCalls > 1 {
			priority = "4"
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{"triggerid":"1001","description":"CPU high","event_name":"CPU high","status":"0","priority":"` + priority + `","type":"0","expression":"avg(/db/system.cpu.util,5m)>80","recovery_mode":"0","recovery_expression":"","correlation_mode":"0","correlation_tag":"","manual_close":"0","templateid":"9001","uuid":"u1","hosts":[{"hostid":"42","host":"db-prod-1"}],"functions":[{"itemid":"2001","function":"avg","parameter":"5m"}],"dependencies":[],"tags":[]}],"id":1}`))
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, APIToken: "token", InstanceID: "prod-zbx"})
	_, err := client.SourceRuleVersionBounded(context.Background(), "prod-zbx", "db-prod-1", "1001", func() error { return nil }, func(bool, error) {})
	if reason, ok := DefinitionUnavailableReason(err); !ok || reason != "inconsistent_read" {
		t.Fatalf("reason=%q ok=%v err=%v", reason, ok, err)
	}
}

func TestSourceRuleVersionBoundedReadsConsistentConfiguration(t *testing.T) {
	var methods []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Method string `json:"method"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		methods = append(methods, req.Method)
		switch req.Method {
		case "trigger.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{
				"triggerid":"1001","description":"CPU high","event_name":"CPU high on {HOST.NAME}",
				"status":"0","priority":"2","type":"0","expression":"avg(/db/system.cpu.util,5m)>80",
				"recovery_mode":"1","recovery_expression":"avg(/db/system.cpu.util,5m)<60",
				"correlation_mode":"0","correlation_tag":"","manual_close":"0","templateid":"9001","uuid":"u1",
				"hosts":[{"hostid":"42","host":"db-prod-1"}],
				"functions":[{"itemid":"2001","function":"avg","parameter":"5m"}],
				"dependencies":[],"tags":[{"tag":"service","value":"billing"}]
			}],"id":1}`))
		case "item.get":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":[{
				"itemid":"2001","hostid":"42","templateid":"8001","key_":"system.cpu.util","type":"0",
				"value_type":"0","status":"0","delay":"1m","params":"","master_itemid":"0","valuemapid":"0",
				"preprocessing":[{"type":"1","params":"2","error_handler":"0","error_handler_params":""}]
			}],"id":1}`))
		default:
			t.Fatalf("unexpected method %q", req.Method)
		}
	}))
	defer srv.Close()

	client := NewClient(Config{BaseURL: srv.URL, APIToken: "token", InstanceID: "prod-zbx"})
	beforeCalls, afterCalls := 0, 0
	got, err := client.SourceRuleVersionBounded(context.Background(), "prod-zbx", "db-prod-1", "1001",
		func() error { beforeCalls++; return nil }, func(started bool, err error) {
			if !started {
				t.Error("request was not marked started")
			}
			afterCalls++
		})
	if err != nil {
		t.Fatal(err)
	}
	if got.InstanceID != "prod-zbx" || got.RuleID != "1001" || got.Version == "" {
		t.Fatalf("definition = %+v", got)
	}
	if len(methods) != 4 || beforeCalls != 4 || afterCalls != 4 {
		t.Fatalf("methods=%v before=%d after=%d, want four bounded requests", methods, beforeCalls, afterCalls)
	}
}

func TestSourceRuleVersionBoundedRejectsInstanceMismatchBeforeAPI(t *testing.T) {
	client := NewClient(Config{BaseURL: "https://zbx.example.com", APIToken: "token", InstanceID: "prod-zbx"})
	_, err := client.SourceRuleVersionBounded(context.Background(), "other-zbx", "db-prod-1", "1001", nil, nil)
	if reason, ok := DefinitionUnavailableReason(err); !ok || reason != "instance_mismatch" {
		t.Fatalf("reason = %q ok=%v err=%v", reason, ok, err)
	}
}
