// SPDX-License-Identifier: FSL-1.1-ALv2

// Zabbix floor source (ADR-0034): deterministic contrast queries served by
// the Zabbix Source when the incident carries host identity — per-interface
// reachability and group-scope open problems. Both kinds are floor-only and
// model-unproposable, like up_ratio.

package acutetriage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

const (
	kindZabbixReachability     = "zabbix_reachability"
	kindZabbixNeighborProblems = "zabbix_neighbor_problems"

	// zabbixFloorMaxHosts caps how many distinct member hosts the floor
	// checks (spec G2): three samples plus the neighbor scan already answer
	// "is the neighborhood on fire"; beyond-cap hosts render as "+N not
	// checked" — never a silent cap.
	zabbixFloorMaxHosts = 3

	// zabbixScopeMaxHosts bounds the neighbor scope (spec G3): groups rank
	// smallest-first and accumulate while the cumulative host count stays
	// within this bound, so functional groups (Databases, 17 hosts) win over
	// catch-alls (Linux servers, 77) — a raw union is a weather report.
	zabbixScopeMaxHosts = 50
)

// alertLabel reads one label value off a member alert, mirroring the same
// direct a.Labels[key] access sharedLabelValues/parentScope already use in
// this package (logs.go) — never a new label-read pattern.
func alertLabel(a store.Alert, key string) string {
	return a.Labels[key]
}

// floorHosts derives the capped host list for the Zabbix floor: distinct
// hostLabel values across member alerts, frequency-ranked (the storm's core
// first), ties broken lexicographically, capped at zabbixFloorMaxHosts.
// Deterministic — same alerts always yield the same list (replay identity,
// spec G6). total is the uncapped distinct count, for render honesty.
func floorHosts(alerts []store.Alert, hostLabel string) (hosts []string, total int) {
	counts := map[string]int{}
	for _, a := range alerts {
		if h := alertLabel(a, hostLabel); h != "" {
			counts[h]++
		}
	}
	for h := range counts {
		hosts = append(hosts, h)
	}
	sort.Slice(hosts, func(i, j int) bool {
		if counts[hosts[i]] != counts[hosts[j]] {
			return counts[hosts[i]] > counts[hosts[j]]
		}
		return hosts[i] < hosts[j]
	})
	total = len(hosts)
	if len(hosts) > zabbixFloorMaxHosts {
		hosts = hosts[:zabbixFloorMaxHosts]
	}
	return hosts, total
}

// zabbixFloorQueries is the Zabbix floor source's contribution (ADR-0034):
// nil when no member alert carries the host label (not applicable). Params
// carry the checked host list (the replay match identity, spec G6), the
// uncapped distinct count (the "+N not checked" render line), and the member
// event ids the neighbor check subtracts (spec G3). Each query gets its own
// params copy — VerificationQuery results are filled in place and must not
// alias.
func zabbixFloorQueries(alerts []store.Alert, hostLabel string) []VerificationQuery {
	hosts, total := floorHosts(alerts, hostLabel)
	if len(hosts) == 0 {
		return nil
	}
	var eventIDs []string
	for _, a := range alerts {
		if id := alertLabel(a, "zabbix_event_id"); id != "" {
			eventIDs = append(eventIDs, id)
		}
	}
	sort.Strings(eventIDs)
	params := func() map[string]any {
		return map[string]any{
			"hosts":             append([]string(nil), hosts...),
			"hosts_total":       float64(total),
			"exclude_event_ids": append([]string(nil), eventIDs...),
		}
	}
	return []VerificationQuery{
		{Kind: kindZabbixReachability, Source: "floor", Params: params(),
			Why: "affected-host reachability: is the host actually down or in maintenance?"},
		{Kind: kindZabbixNeighborProblems, Source: "floor", Params: params(),
			Why: "group-scope contrast: is the neighborhood broken the way the hypothesis predicts?"},
	}
}

// hostsFromParams reads the "hosts" param — []string live, []any after a JSON
// round-trip (frozen envelopes) — mirroring windowMinutesFromParams' tolerance.
func hostsFromParams(params map[string]any) []string {
	switch v := params["hosts"].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// hostsTotalFromParams reads "hosts_total" (float64 post-JSON, int live).
func hostsTotalFromParams(params map[string]any) int {
	switch v := params["hosts_total"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

// excludeEventIDsFromParams reads "exclude_event_ids" into a lookup set.
func excludeEventIDsFromParams(params map[string]any) map[string]bool {
	out := map[string]bool{}
	switch v := params["exclude_event_ids"].(type) {
	case []string:
		for _, s := range v {
			out[s] = true
		}
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				out[s] = true
			}
		}
	}
	return out
}

// zabbixVerifier executes the Zabbix floor kinds for one round, memoizing
// HostContext per host so reachability and the neighbor scope share one call
// per host (two Zabbix round-trips total in the single-host case). Not safe
// for concurrent use — the round loop is sequential, like snapshotExecutor.
type zabbixVerifier struct {
	zbx    ZabbixReader
	logger *slog.Logger
	incID  string
	cache  map[string]hostCtxResult
}

type hostCtxResult struct {
	top zabbix.Topology
	err error
}

func newZabbixVerifier(zbx ZabbixReader, logger *slog.Logger, incID string) *zabbixVerifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &zabbixVerifier{zbx: zbx, logger: logger, incID: incID, cache: map[string]hostCtxResult{}}
}

func (zv *zabbixVerifier) hostContext(ctx context.Context, host string) hostCtxResult {
	if r, ok := zv.cache[host]; ok {
		return r
	}
	top, err := zv.zbx.HostContext(ctx, host)
	r := hostCtxResult{top: top, err: err}
	zv.cache[host] = r
	return r
}

// runReachability fills q for kindZabbixReachability: one line per checked
// host from Zabbix's own per-interface polling verdict plus maintenance
// state. Any-fetched wins (spec G4): one answered host makes the query
// fetched — an unreachable host is evidence, not a failed check — and every
// sub-failure renders inline. All-failed classifies hard-error-beats-timeout
// (the classifyPairErrs precedent).
func (zv *zabbixVerifier) runReachability(ctx context.Context, q *VerificationQuery) {
	if zv.zbx == nil {
		q.Outcome = OutcomeFailed
		q.Result = renderUnavailable("zabbix not configured")
		return
	}
	hosts := hostsFromParams(q.Params)
	var lines []string
	var fetched int
	var hardErr bool
	for _, h := range hosts {
		r := zv.hostContext(ctx, h)
		if r.err != nil {
			switch {
			case errors.Is(r.err, zabbix.ErrNotFound):
				hardErr = true
				lines = append(lines, h+": no host matching")
			case errors.Is(r.err, context.DeadlineExceeded):
				lines = append(lines, h+": timed out")
			default:
				hardErr = true
				lines = append(lines, h+": lookup failed")
			}
			zv.logger.Warn("acutetriage: verify: zabbix reachability lookup failed",
				"host", h, "err", r.err, "incident", zv.incID)
			continue
		}
		fetched++
		lines = append(lines, renderHostReachability(h, r.top))
	}
	if extra := hostsTotalFromParams(q.Params) - len(hosts); extra > 0 {
		lines = append(lines, fmt.Sprintf("+%d hosts not checked", extra))
	}
	switch {
	case fetched > 0:
		q.Outcome = OutcomeFetched
	case hardErr:
		q.Outcome = OutcomeFailed
	default:
		q.Outcome = OutcomeDegraded
	}
	q.Result = capText(flattenRecalled(strings.Join(lines, " | ")), 400)
}

// renderHostReachability renders one host's line: unavailable interfaces win
// the line (they are the signal); all-available renders a count; anything
// else is honestly unknown. Maintenance renders on every shape — a host in a
// window explains "down" without a hypothesis.
func renderHostReachability(host string, top zabbix.Topology) string {
	var b strings.Builder
	var unavailable []zabbix.IfaceState
	available := 0
	for _, i := range top.Interfaces {
		switch i.Available {
		case "2":
			unavailable = append(unavailable, i)
		case "1":
			available++
		}
	}
	switch {
	case len(unavailable) > 0:
		parts := make([]string, 0, len(unavailable))
		for _, i := range unavailable {
			parts = append(parts, fmt.Sprintf("interface %s unavailable (%q)", i.Addr, i.Error))
		}
		b.WriteString(host + ": " + strings.Join(parts, ", "))
	case available > 0:
		fmt.Fprintf(&b, "%s reachable (%s)", host, pluralize(available, "interface"))
	default:
		b.WriteString(host + ": availability unknown")
	}
	if top.MaintenanceActive {
		b.WriteString("; in maintenance")
	} else {
		b.WriteString("; not in maintenance")
	}
	return b.String()
}
