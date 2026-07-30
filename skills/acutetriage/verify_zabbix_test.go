// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// -- floorHosts --------------------------------------------------------------

func TestFloorHosts_FrequencyRankedTieLexicographicCapped(t *testing.T) {
	alerts := []store.Alert{
		alertWithLabels(map[string]string{"host": "web-02", "zabbix_event_id": "1"}),
		alertWithLabels(map[string]string{"host": "web-02", "zabbix_event_id": "2"}),
		alertWithLabels(map[string]string{"host": "db-01", "zabbix_event_id": "3"}),
		alertWithLabels(map[string]string{"host": "web-01", "zabbix_event_id": "4"}),
		alertWithLabels(map[string]string{"host": "cache-01", "zabbix_event_id": "5"}),
	}
	hosts, total := floorHosts(alerts, "host")
	// web-02 (2 alerts) first; db-01/web-01/cache-01 tie at 1 → lexicographic; capped at 3.
	want := []string{"web-02", "cache-01", "db-01"}
	if !reflect.DeepEqual(hosts, want) {
		t.Fatalf("hosts = %v, want %v", hosts, want)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
}

func TestFloorHosts_NoHostLabelMeansNone(t *testing.T) {
	alerts := []store.Alert{alertWithLabels(map[string]string{"alertname": "x"})}
	hosts, total := floorHosts(alerts, "host")
	if len(hosts) != 0 || total != 0 {
		t.Fatalf("hosts=%v total=%d, want empty", hosts, total)
	}
}

// -- zabbixFloorQueries ------------------------------------------------------

func TestZabbixFloorQueries_TwoFloorQueriesWithIdentityParams(t *testing.T) {
	alerts := []store.Alert{
		alertWithLabels(map[string]string{"host": "db-01", "zabbix_event_id": "42"}),
	}
	qs := zabbixFloorQueries(alerts, "host")
	if len(qs) != 2 {
		t.Fatalf("got %d queries, want 2", len(qs))
	}
	if qs[0].Kind != kindZabbixReachability || qs[1].Kind != kindZabbixNeighborProblems {
		t.Fatalf("kinds = %s,%s", qs[0].Kind, qs[1].Kind)
	}
	for _, q := range qs {
		if q.Source != "floor" {
			t.Fatalf("source = %q, want floor", q.Source)
		}
		if got := hostsFromParams(q.Params); !reflect.DeepEqual(got, []string{"db-01"}) {
			t.Fatalf("hosts = %v", got)
		}
		if !excludeEventIDsFromParams(q.Params)["42"] {
			t.Fatal("member event id 42 missing from exclusion set")
		}
	}
	// Params maps must be independent copies — mutating one query's map must
	// not leak into the other.
	qs[0].Params["hosts"] = []string{"mutated"}
	if got := hostsFromParams(qs[1].Params); !reflect.DeepEqual(got, []string{"db-01"}) {
		t.Fatalf("params aliased between queries: %v", got)
	}
}

func TestZabbixFloorQueries_NotApplicableWithoutHosts(t *testing.T) {
	if qs := zabbixFloorQueries([]store.Alert{alertWithLabels(map[string]string{"a": "b"})}, "host"); qs != nil {
		t.Fatalf("qs = %v, want nil", qs)
	}
}

// -- params round-trip -------------------------------------------------------

func TestHostsFromParams_NormalizesJSONRoundTrip(t *testing.T) {
	// Post-JSON, []string becomes []any.
	params := map[string]any{"hosts": []any{"a", "b"}}
	if got := hostsFromParams(params); !reflect.DeepEqual(got, []string{"a", "b"}) {
		t.Fatalf("got %v", got)
	}
	if got := hostsTotalFromParams(map[string]any{"hosts_total": float64(7)}); got != 7 {
		t.Fatalf("total = %d, want 7", got)
	}
}

// -- zabbixVerifier: runReachability -----------------------------------------

// scriptedZabbixReader scripts the three reads the floor uses; every other
// ZabbixReader method panics — a floor query must never touch them.
type scriptedZabbixReader struct {
	hostCtx      func(host string) (zabbix.Topology, error)
	hostGroupsFn func(names []string) ([]zabbix.HostGroupInfo, error)
	groupProbsFn func(groupIDs []string) ([]zabbix.Problem, error)
	hostCtxCalls []string
}

func (s *scriptedZabbixReader) HostContext(_ context.Context, host string) (zabbix.Topology, error) {
	s.hostCtxCalls = append(s.hostCtxCalls, host)
	return s.hostCtx(host)
}
func (s *scriptedZabbixReader) HostGroups(_ context.Context, names []string) ([]zabbix.HostGroupInfo, error) {
	return s.hostGroupsFn(names)
}
func (s *scriptedZabbixReader) GroupOpenProblems(_ context.Context, groupIDs []string, _ zabbix.ProblemSelector) ([]zabbix.Problem, error) {
	return s.groupProbsFn(groupIDs)
}
func (s *scriptedZabbixReader) TriggerContext(context.Context, string) (zabbix.Operator, error) {
	panic("floor must not call TriggerContext")
}
func (s *scriptedZabbixReader) ProblemContext(context.Context, string) (zabbix.ProblemDetail, error) {
	panic("floor must not call ProblemContext")
}
func (s *scriptedZabbixReader) OpenProblems(context.Context, string, zabbix.ProblemSelector) ([]zabbix.Problem, error) {
	panic("floor must not call OpenProblems")
}
func (s *scriptedZabbixReader) FlapCount(context.Context, string, time.Time) (int, error) {
	panic("floor must not call FlapCount")
}

func reachQuery(hosts []string, total int) *VerificationQuery {
	return &VerificationQuery{Kind: kindZabbixReachability, Source: "floor",
		Params: map[string]any{"hosts": hosts, "hosts_total": float64(total)}}
}

func TestRunReachability_AllReachable(t *testing.T) {
	z := &scriptedZabbixReader{hostCtx: func(host string) (zabbix.Topology, error) {
		return zabbix.Topology{Interfaces: []zabbix.IfaceState{{Addr: "10.0.0.1", Available: "1"}}}, nil
	}}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := reachQuery([]string{"db-01"}, 1)
	zv.runReachability(context.Background(), q)
	if q.Outcome != OutcomeFetched {
		t.Fatalf("outcome = %s, want fetched", q.Outcome)
	}
	if q.Result != "db-01 reachable (1 interface); not in maintenance" {
		t.Fatalf("result = %q", q.Result)
	}
}

func TestRunReachability_UnavailableAndMaintenanceRender(t *testing.T) {
	z := &scriptedZabbixReader{hostCtx: func(host string) (zabbix.Topology, error) {
		return zabbix.Topology{MaintenanceActive: true, Interfaces: []zabbix.IfaceState{
			{Addr: "10.0.0.5", Available: "2", Error: "timeout"}}}, nil
	}}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := reachQuery([]string{"db-01"}, 1)
	zv.runReachability(context.Background(), q)
	if q.Outcome != OutcomeFetched { // Zabbix answered: an unreachable host is evidence, not failure
		t.Fatalf("outcome = %s, want fetched", q.Outcome)
	}
	if q.Result != `db-01: interface 10.0.0.5 unavailable ("timeout"); in maintenance` {
		t.Fatalf("result = %q", q.Result)
	}
}

func TestRunReachability_PartialFailureAnyFetchedWins(t *testing.T) {
	z := &scriptedZabbixReader{hostCtx: func(host string) (zabbix.Topology, error) {
		if host == "ghost" {
			return zabbix.Topology{}, fmt.Errorf("zabbix: no host %q: %w", host, zabbix.ErrNotFound)
		}
		return zabbix.Topology{Interfaces: []zabbix.IfaceState{{Addr: "a", Available: "1"}}}, nil
	}}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := reachQuery([]string{"web-01", "ghost"}, 5)
	zv.runReachability(context.Background(), q)
	if q.Outcome != OutcomeFetched {
		t.Fatalf("outcome = %s, want fetched (spec G4: any-fetched wins)", q.Outcome)
	}
	want := "web-01 reachable (1 interface); not in maintenance | ghost: no host matching | +3 hosts not checked"
	if q.Result != want {
		t.Fatalf("result = %q\nwant     %q", q.Result, want)
	}
}

func TestRunReachability_AllFailedClassification(t *testing.T) {
	// all timeouts → degraded
	z := &scriptedZabbixReader{hostCtx: func(string) (zabbix.Topology, error) {
		return zabbix.Topology{}, context.DeadlineExceeded
	}}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := reachQuery([]string{"a", "b"}, 2)
	zv.runReachability(context.Background(), q)
	if q.Outcome != OutcomeDegraded {
		t.Fatalf("outcome = %s, want degraded", q.Outcome)
	}
	// any hard error → failed (hard error beats timeout)
	z = &scriptedZabbixReader{hostCtx: func(host string) (zabbix.Topology, error) {
		if host == "a" {
			return zabbix.Topology{}, context.DeadlineExceeded
		}
		return zabbix.Topology{}, fmt.Errorf("boom")
	}}
	zv = newZabbixVerifier(z, nil, "inc-1")
	q = reachQuery([]string{"a", "b"}, 2)
	zv.runReachability(context.Background(), q)
	if q.Outcome != OutcomeFailed {
		t.Fatalf("outcome = %s, want failed", q.Outcome)
	}
}

func TestHostContext_MemoizedAcrossQueries(t *testing.T) {
	z := &scriptedZabbixReader{hostCtx: func(string) (zabbix.Topology, error) {
		return zabbix.Topology{Interfaces: []zabbix.IfaceState{{Addr: "a", Available: "1"}}}, nil
	}}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := reachQuery([]string{"db-01"}, 1)
	zv.runReachability(context.Background(), q)
	zv.runReachability(context.Background(), q)
	if len(z.hostCtxCalls) != 1 {
		t.Fatalf("HostContext called %d times, want 1 (memoized)", len(z.hostCtxCalls))
	}
}
