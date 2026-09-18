// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"

	model "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// rpcCall is one JSON-RPC request a fake Zabbix frontend received.
type rpcCall struct {
	Method string         `json:"method"`
	Params map[string]any `json:"params"`
}

// fakeZabbixRPC serves a JSON-RPC endpoint that records every call and
// answers each with respond(call) — the result JSON to wrap, or "" for an
// empty result.
func fakeZabbixRPC(t *testing.T, respond func(call rpcCall) string) (*zabbix.Client, *[]rpcCall) {
	t.Helper()
	calls := &[]rpcCall{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var call rpcCall
		_ = json.Unmarshal(body, &call)
		*calls = append(*calls, call)
		result := respond(call)
		if result == "" {
			result = "[]"
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":` + result + `}`))
	}))
	t.Cleanup(srv.Close)
	return zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok", TimeoutSeconds: 5}), calls
}

func methodsOf(calls []rpcCall) []string {
	out := make([]string, 0, len(calls))
	for _, c := range calls {
		out = append(out, c.Method)
	}
	return out
}

const linkedItem = `[{"itemid":"100","hostid":"10084","value_type":"0","name":"CPU","units":"%","hosts":[{"hostid":"10084","host":"web01"}]}]`

// TestZabbixMetricExecutorExactLinkedLookupOverRPC proves the proactive
// metric path (F17): one EXACT item.get carrying the host filter and
// selectHosts, then one history.get for that item — two reservations, two
// ok outcomes, and a confirmed_value run.
func TestZabbixMetricExecutorExactLinkedLookupOverRPC(t *testing.T) {
	client, calls := fakeZabbixRPC(t, func(call rpcCall) string {
		switch call.Method {
		case "item.get":
			return linkedItem
		case "history.get":
			return `[{"clock":"1750000000","value":"93.2"}]`
		}
		return ""
	})
	e := &ZabbixMetricExecutor{Client: client}
	plan := planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "system.cpu.util"})
	rec := &capturingRecorder{}

	run, err := e.Execute(context.Background(), plan, rec)
	if err != nil {
		t.Fatal(err)
	}
	if got := methodsOf(*calls); !slices.Equal(got, []string{"item.get", "history.get"}) {
		t.Fatalf("methods = %v, want exactly [item.get history.get]", got)
	}
	itemGet := (*calls)[0].Params
	if _, fuzzy := itemGet["search"]; fuzzy {
		t.Fatal("the proactive path must never issue a fuzzy search lookup")
	}
	if filter, _ := itemGet["filter"].(map[string]any); filter["key_"] != "system.cpu.util" {
		t.Fatalf("item.get filter = %v, want the exact key", itemGet["filter"])
	}
	if itemGet["host"] != "web01" || itemGet["selectHosts"] == nil {
		t.Fatalf("item.get must scope to the host and request selectHosts linkage, got %v", itemGet)
	}
	if (*calls)[1].Params["itemids"] != "100" {
		t.Fatalf("history.get itemids = %v, want the resolved item 100", (*calls)[1].Params["itemids"])
	}
	if rec.reservations != 2 || !slices.Equal(rec.codes(), []string{"ok", "ok"}) {
		t.Fatalf("reservations=%d codes=%v, want 2 / [ok ok]", rec.reservations, rec.codes())
	}
	if run.Status != model.ResultConfirmedValue || run.Coverage.Returned != 1 {
		t.Fatalf("run = status %q returned %d, want confirmed_value/1", run.Status, run.Coverage.Returned)
	}
}

// TestZabbixMetricExecutorNoExactItemIsUnresolvedWithoutFuzzyFallback
// proves a missing exact item is vocabulary_unresolved after ONE request —
// never a second, fuzzy substitute lookup.
func TestZabbixMetricExecutorNoExactItemIsUnresolvedWithoutFuzzyFallback(t *testing.T) {
	client, calls := fakeZabbixRPC(t, func(rpcCall) string { return "" })
	rec := &capturingRecorder{}
	run, err := (&ZabbixMetricExecutor{Client: client}).Execute(context.Background(),
		planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "cpu.util"}), rec)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.ResultVocabularyUnresolved {
		t.Fatalf("status = %q, want vocabulary_unresolved", run.Status)
	}
	if got := methodsOf(*calls); !slices.Equal(got, []string{"item.get"}) || rec.reservations != 1 {
		t.Fatalf("methods=%v reservations=%d, want one exact item.get and nothing more", got, rec.reservations)
	}
}

// TestZabbixMetricExecutorForeignHostItemIsUnresolved proves an item the
// source does not link to the requested host is refused, not read.
func TestZabbixMetricExecutorForeignHostItemIsUnresolved(t *testing.T) {
	client, calls := fakeZabbixRPC(t, func(call rpcCall) string {
		if call.Method == "item.get" {
			return `[{"itemid":"100","hostid":"10085","value_type":"0","hosts":[{"hostid":"10085","host":"web02"}]}]`
		}
		t.Fatalf("unexpected %s after a foreign-host item", call.Method)
		return ""
	})
	rec := &capturingRecorder{}
	run, err := (&ZabbixMetricExecutor{Client: client}).Execute(context.Background(),
		planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "system.cpu.util"}), rec)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.ResultVocabularyUnresolved || len(*calls) != 1 || rec.reservations != 1 {
		t.Fatalf("status=%q calls=%d reservations=%d, want unresolved after the single item.get", run.Status, len(*calls), rec.reservations)
	}
}

// TestZabbixMetricExecutorSecondReservationDeniedIsWithheld proves the
// two-request path degrades cleanly when only one reservation is granted:
// the item.get is accounted for, history.get is never dispatched, and the
// run is withheld_by_budget.
func TestZabbixMetricExecutorSecondReservationDeniedIsWithheld(t *testing.T) {
	client, calls := fakeZabbixRPC(t, func(call rpcCall) string {
		if call.Method == "item.get" {
			return linkedItem
		}
		t.Fatalf("history.get dispatched without a reservation")
		return ""
	})
	rec := &capturingRecorder{denyAfter: 1}
	run, err := (&ZabbixMetricExecutor{Client: client}).Execute(context.Background(),
		planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "system.cpu.util"}), rec)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.ResultWithheldByBudget {
		t.Fatalf("status = %q, want withheld_by_budget", run.Status)
	}
	if got := methodsOf(*calls); !slices.Equal(got, []string{"item.get"}) {
		t.Fatalf("methods = %v, want only the reserved item.get", got)
	}
	if rec.reservations != 1 || !slices.Equal(rec.codes(), []string{"ok"}) {
		t.Fatalf("reservations=%d codes=%v, want the first request fully accounted", rec.reservations, rec.codes())
	}
}

// TestZabbixProblemExecutorDropsRowsNotLinkedToTriggerAndHost proves F17
// for problem history: rows for another trigger or another host are
// dropped before the recovery lookup, which is then batched only for the
// surviving episode.
func TestZabbixProblemExecutorDropsRowsNotLinkedToTriggerAndHost(t *testing.T) {
	client, calls := fakeZabbixRPC(t, func(call rpcCall) string {
		switch {
		case call.Method == "event.get" && call.Params["value"] != nil:
			return `[
				{"eventid":"31","objectid":"18422","clock":"1788714000","r_eventid":"40","hosts":[{"hostid":"10084","host":"web01"}]},
				{"eventid":"32","objectid":"999","clock":"1788714100","r_eventid":"41","hosts":[{"hostid":"10084","host":"web01"}]},
				{"eventid":"33","objectid":"18422","clock":"1788714200","r_eventid":"42","hosts":[{"hostid":"10085","host":"web02"}]}
			]`
		case call.Method == "event.get":
			return `[{"eventid":"40","clock":"1788714300"}]`
		}
		return ""
	})
	e := &ZabbixProblemExecutor{Client: client}
	plan := testStorePlan()
	plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "18422"})
	rec := &capturingRecorder{}

	run, err := e.Execute(context.Background(), plan, rec)
	if err != nil {
		t.Fatal(err)
	}
	primary := (*calls)[0].Params
	if ids, _ := primary["objectids"].([]any); len(ids) != 1 || ids[0] != "18422" {
		t.Fatalf("event.get objectids = %v, want the requested trigger only", primary["objectids"])
	}
	if primary["selectHosts"] == nil {
		t.Fatal("event.get must request selectHosts so host linkage can be verified")
	}
	if len(*calls) != 2 {
		t.Fatalf("calls = %v, want primary + one recovery batch", methodsOf(*calls))
	}
	if ids, _ := (*calls)[1].Params["eventids"].([]any); len(ids) != 1 || ids[0] != "40" {
		t.Fatalf("recovery lookup eventids = %v, want only the linked episode's recovery event", (*calls)[1].Params["eventids"])
	}
	var episodes []zabbix.ProblemEpisode
	if err := json.Unmarshal(run.Facts[0].Value, &episodes); err != nil {
		t.Fatal(err)
	}
	if len(episodes) != 1 || episodes[0].EventID != "31" || episodes[0].HostID != "10084" || episodes[0].Recovery == nil {
		t.Fatalf("episodes = %+v, want the single linked, resolved episode with its proven hostid", episodes)
	}
	if run.Status != model.ResultTruncated || run.Coverage.Complete || run.Coverage.Omitted != 2 || rec.reservations != 2 {
		t.Fatalf("run=%+v reservations=%d, want incomplete coverage with two rejected rows and two reservations", run, rec.reservations)
	}
}

// TestZabbixProblemExecutorSecondReservationDeniedKeepsPrimary proves a
// budget-denied recovery lookup degrades to recovery_unknown while the
// primary evidence and its accounting survive.
func TestZabbixProblemExecutorSecondReservationDeniedKeepsPrimary(t *testing.T) {
	client, calls := fakeZabbixRPC(t, func(call rpcCall) string {
		if call.Params["value"] != nil {
			return `[{"eventid":"31","objectid":"18422","clock":"1788714000","r_eventid":"40","hosts":[{"hostid":"10084","host":"web01"}]}]`
		}
		t.Fatal("recovery lookup dispatched without a reservation")
		return ""
	})
	plan := testStorePlan()
	plan.Parameters = mustMarshal(zabbixProblemParameters{Host: "web01", TriggerID: "18422"})
	rec := &capturingRecorder{denyAfter: 1}

	run, err := (&ZabbixProblemExecutor{Client: client}).Execute(context.Background(), plan, rec)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != model.ResultConfirmedValue || !slices.Contains(run.LimitationCodes, "recovery_unknown") {
		t.Fatalf("run = status %q codes %v, want confirmed_value with recovery_unknown", run.Status, run.LimitationCodes)
	}
	if len(*calls) != 1 || rec.reservations != 1 || !slices.Equal(rec.codes(), []string{"ok"}) {
		t.Fatalf("calls=%d reservations=%d codes=%v, want one accounted primary request", len(*calls), rec.reservations, rec.codes())
	}
}

func TestZabbixMetricExecutorMissingHostLinkageIsUnresolved(t *testing.T) {
	for _, row := range []string{
		`[{"itemid":"100","hostid":"10084","value_type":"0"}]`,
		`[{"itemid":"100","hostid":"10084","value_type":"0","hosts":[{"hostid":"10085","host":"web01"}]}]`,
	} {
		t.Run(row, func(t *testing.T) {
			client, calls := fakeZabbixRPC(t, func(call rpcCall) string {
				if call.Method == "item.get" {
					return row
				}
				return `[]`
			})
			rec := &capturingRecorder{}
			run, err := (&ZabbixMetricExecutor{Client: client}).Execute(context.Background(),
				planWithParams(zabbixMetricParameters{Host: "web01", ItemKey: "system.cpu.util"}), rec)
			if err != nil {
				t.Fatal(err)
			}
			if run.Status != model.ResultVocabularyUnresolved || len(*calls) != 1 || rec.reservations != 1 {
				t.Fatalf("run=%+v calls=%d reservations=%d; missing or contradictory linkage must stop after item.get", run, len(*calls), rec.reservations)
			}
		})
	}
}

func TestZabbixProblemExecutorUnprovenRowsCannotConfirmEmpty(t *testing.T) {
	for _, row := range []string{
		`[{"eventid":"31","objectid":"18422","clock":"1788714000","r_eventid":"40"}]`,
		`[{"eventid":"31","objectid":"18422","clock":"1788714000","r_eventid":"40","hosts":[{"host":"web02","hostid":"2"}]}]`,
	} {
		t.Run(row, func(t *testing.T) {
			client, calls := fakeZabbixRPC(t, func(call rpcCall) string {
				if call.Params["value"] != nil {
					return row
				}
				return `[]`
			})
			plan := planWithParams(zabbixProblemParameters{Host: "web01", TriggerID: "18422"})
			rec := &capturingRecorder{}
			run, err := (&ZabbixProblemExecutor{Client: client}).Execute(context.Background(), plan, rec)
			if err != nil {
				t.Fatal(err)
			}
			if run.Status != model.ResultVocabularyUnresolved || run.Coverage.Complete || len(run.Facts) != 0 || len(*calls) != 1 || rec.reservations != 1 {
				t.Fatalf("run=%+v calls=%d reservations=%d; unproven rows must not become confirmed evidence", run, len(*calls), rec.reservations)
			}
		})
	}
}
