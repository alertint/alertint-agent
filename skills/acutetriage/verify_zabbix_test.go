// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"reflect"
	"testing"

	"github.com/alertint/alertint-agent/internal/store"
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
