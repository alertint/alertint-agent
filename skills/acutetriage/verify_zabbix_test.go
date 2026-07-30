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
	// zabbix_event_id lives in Annotations on a real receiver-shaped alert
	// (internal/ingress/zabbix.go's setIfPresent), never Labels — this
	// fixture must match that shape or it can't catch a regression to the
	// wrong field.
	alerts := []store.Alert{
		{Labels: map[string]string{"host": "db-01"}, Annotations: map[string]string{"zabbix_event_id": "42"}},
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

// TestSeedHostContext_AvoidsRedundantFetch proves a pre-seeded host never
// hits the live ZabbixReader: chunk-02's FetchZabbixContext already resolved
// this host moments earlier in the same triage invocation, so the round must
// reuse it rather than paying a second host.get for it.
func TestSeedHostContext_AvoidsRedundantFetch(t *testing.T) {
	z := &scriptedZabbixReader{hostCtx: func(string) (zabbix.Topology, error) {
		t.Fatal("floor must not re-fetch a seeded host")
		return zabbix.Topology{}, nil
	}}
	zv := newZabbixVerifier(z, nil, "inc-1")
	zv.seedHostContext(map[string]zabbix.Topology{
		"db-01": {Interfaces: []zabbix.IfaceState{{Addr: "a", Available: "1"}}},
	})
	q := reachQuery([]string{"db-01"}, 1)
	zv.runReachability(context.Background(), q)
	if q.Outcome != OutcomeFetched {
		t.Fatalf("outcome = %s, want fetched from the seeded cache", q.Outcome)
	}
}

// TestSeedHostContext_UnseededHostStillFetchesLive proves the seed is
// additive, not a substitute for the live path: a host absent from the seed
// (e.g. a multi-host incident where FetchZabbixContext only resolved the
// first-seen host) still fetches normally.
func TestSeedHostContext_UnseededHostStillFetchesLive(t *testing.T) {
	var calls []string
	z := &scriptedZabbixReader{hostCtx: func(host string) (zabbix.Topology, error) {
		calls = append(calls, host)
		return zabbix.Topology{Interfaces: []zabbix.IfaceState{{Addr: "a", Available: "1"}}}, nil
	}}
	zv := newZabbixVerifier(z, nil, "inc-1")
	zv.seedHostContext(map[string]zabbix.Topology{"db-01": {}})
	q := reachQuery([]string{"web-01"}, 1)
	zv.runReachability(context.Background(), q)
	if !reflect.DeepEqual(calls, []string{"web-01"}) {
		t.Fatalf("hostCtx calls = %v, want [web-01]", calls)
	}
}

// -- zabbixVerifier: runNeighborProblems -------------------------------------

func neighborQuery(hosts []string, excludeIDs []string) *VerificationQuery {
	ex := make([]any, 0, len(excludeIDs))
	for _, id := range excludeIDs {
		ex = append(ex, id)
	}
	return &VerificationQuery{Kind: kindZabbixNeighborProblems, Source: "floor",
		Params: map[string]any{"hosts": hosts, "hosts_total": float64(len(hosts)), "exclude_event_ids": ex}}
}

// The real operator sample from the grill: functional groups + catch-alls.
func sampleGroups() []zabbix.HostGroupInfo {
	return []zabbix.HostGroupInfo{
		{GroupID: "1", Name: "Databases", Hosts: 17},
		{GroupID: "2", Name: "Virtual machines", Hosts: 17},
		{GroupID: "3", Name: "Linux servers", Hosts: 77},
		{GroupID: "4", Name: "Applications", Hosts: 113},
	}
}

func TestNeighborProblems_SmallestGroupsFirstDropsCatchalls(t *testing.T) {
	var gotGroupIDs []string
	z := &scriptedZabbixReader{
		hostCtx: func(string) (zabbix.Topology, error) {
			return zabbix.Topology{Groups: []string{"Databases", "Virtual machines", "Linux servers", "Applications"}}, nil
		},
		hostGroupsFn: func(names []string) ([]zabbix.HostGroupInfo, error) { return sampleGroups(), nil },
		groupProbsFn: func(groupIDs []string) ([]zabbix.Problem, error) {
			gotGroupIDs = groupIDs
			return []zabbix.Problem{
				{EventID: "900", Name: "Disk full on db-02", Severity: "4"},
				{EventID: "901", Name: "Backup slow", Severity: "2", Suppressed: true},
			}, nil
		},
	}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := neighborQuery([]string{"db-01"}, nil)
	zv.runNeighborProblems(context.Background(), q)
	if q.Outcome != OutcomeFetched {
		t.Fatalf("outcome = %s, want fetched", q.Outcome)
	}
	// Databases(17) + Virtual machines(17) = 34 ≤ 50; Linux servers would hit 111 → dropped.
	if !reflect.DeepEqual(gotGroupIDs, []string{"1", "2"}) {
		t.Fatalf("groupids = %v, want [1 2]", gotGroupIDs)
	}
	// Two chosen groups: Zabbix host-group membership isn't exclusive, so the
	// peer count is qualified as an upper bound rather than claimed exact.
	want := "2 open problems in groups Databases, Virtual machines (up to 33 peer hosts): " +
		"sev 4 Disk full on db-02; sev 2 Backup slow (suppressed); " +
		"not scoped: Linux servers (77), Applications (113)"
	if q.Result != want {
		t.Fatalf("result = %q\nwant     %q", q.Result, want)
	}
}

func TestNeighborProblems_OwnEventsSubtracted(t *testing.T) {
	z := &scriptedZabbixReader{
		hostCtx: func(string) (zabbix.Topology, error) {
			return zabbix.Topology{Groups: []string{"Databases"}}, nil
		},
		hostGroupsFn: func([]string) ([]zabbix.HostGroupInfo, error) {
			return []zabbix.HostGroupInfo{{GroupID: "1", Name: "Databases", Hosts: 17}}, nil
		},
		groupProbsFn: func([]string) ([]zabbix.Problem, error) {
			return []zabbix.Problem{
				{EventID: "42", Name: "This very incident", Severity: "4"},
				{EventID: "900", Name: "Neighbor problem", Severity: "3"},
			}, nil
		},
	}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := neighborQuery([]string{"db-01"}, []string{"42"})
	zv.runNeighborProblems(context.Background(), q)
	want := "1 open problems in groups Databases (16 peer hosts): sev 3 Neighbor problem"
	if q.Result != want {
		t.Fatalf("result = %q\nwant     %q", q.Result, want)
	}
}

//nolint:dupl // intentionally near-identical setup contrasting confirmed-absence vs. vacuous-inconclusive outcomes
func TestNeighborProblems_EmptyWithPeersIsWeighableEmpty(t *testing.T) {
	z := &scriptedZabbixReader{
		hostCtx: func(string) (zabbix.Topology, error) {
			return zabbix.Topology{Groups: []string{"Databases"}}, nil
		},
		hostGroupsFn: func([]string) ([]zabbix.HostGroupInfo, error) {
			return []zabbix.HostGroupInfo{{GroupID: "1", Name: "Databases", Hosts: 17}}, nil
		},
		groupProbsFn: func([]string) ([]zabbix.Problem, error) { return nil, nil },
	}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := neighborQuery([]string{"db-01"}, nil)
	zv.runNeighborProblems(context.Background(), q)
	if q.Outcome != OutcomeEmpty {
		t.Fatalf("outcome = %s, want empty", q.Outcome)
	}
	if q.Result != "0 open problems in groups Databases (16 peer hosts)" {
		t.Fatalf("result = %q", q.Result)
	}
}

//nolint:dupl // intentionally near-identical setup contrasting confirmed-absence vs. vacuous-inconclusive outcomes
func TestNeighborProblems_VacuousScopeRendersInconclusive(t *testing.T) {
	z := &scriptedZabbixReader{
		hostCtx: func(string) (zabbix.Topology, error) {
			return zabbix.Topology{Groups: []string{"Zabbix servers"}}, nil
		},
		hostGroupsFn: func([]string) ([]zabbix.HostGroupInfo, error) {
			return []zabbix.HostGroupInfo{{GroupID: "7", Name: "Zabbix servers", Hosts: 1}}, nil
		},
		groupProbsFn: func([]string) ([]zabbix.Problem, error) { return nil, nil },
	}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := neighborQuery([]string{"zbx-01"}, nil)
	zv.runNeighborProblems(context.Background(), q)
	if q.Outcome != OutcomeEmpty {
		t.Fatalf("outcome = %s, want empty", q.Outcome)
	}
	if q.Result != "no peer hosts share zbx-01's host groups — inconclusive" {
		t.Fatalf("result = %q", q.Result)
	}
}

func TestNeighborProblems_ScopeUnresolvable(t *testing.T) {
	z := &scriptedZabbixReader{hostCtx: func(string) (zabbix.Topology, error) {
		return zabbix.Topology{}, fmt.Errorf("boom")
	}}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := neighborQuery([]string{"db-01"}, nil)
	zv.runNeighborProblems(context.Background(), q)
	if q.Outcome != OutcomeFailed {
		t.Fatalf("outcome = %s, want failed", q.Outcome)
	}
	if q.Result != "unavailable (scope unresolvable)" {
		t.Fatalf("result = %q", q.Result)
	}
}

func TestNeighborProblems_AlwaysAtLeastOneGroup(t *testing.T) {
	// Host only in a catch-all bigger than the cap: take it anyway.
	z := &scriptedZabbixReader{
		hostCtx: func(string) (zabbix.Topology, error) {
			return zabbix.Topology{Groups: []string{"Applications"}}, nil
		},
		hostGroupsFn: func([]string) ([]zabbix.HostGroupInfo, error) {
			return []zabbix.HostGroupInfo{{GroupID: "4", Name: "Applications", Hosts: 113}}, nil
		},
		groupProbsFn: func([]string) ([]zabbix.Problem, error) { return nil, nil },
	}
	zv := newZabbixVerifier(z, nil, "inc-1")
	q := neighborQuery([]string{"app-01"}, nil)
	zv.runNeighborProblems(context.Background(), q)
	if q.Result != "0 open problems in groups Applications (112 peer hosts)" {
		t.Fatalf("result = %q", q.Result)
	}
}
