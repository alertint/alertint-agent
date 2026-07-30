// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

// ZabbixReader is the read surface the Zabbix context fetch consumes; the
// consumer owns the interface (the SentryReader idiom) so tests inject fakes.
// *zabbix.Client satisfies it. Pass a TRUE nil interface when unconfigured.
type ZabbixReader interface {
	TriggerContext(ctx context.Context, triggerID string) (zabbix.Operator, error)
	ProblemContext(ctx context.Context, eventID string) (zabbix.ProblemDetail, error)
	HostContext(ctx context.Context, host string) (zabbix.Topology, error)
	FlapCount(ctx context.Context, triggerID string, since time.Time) (int, error)
	OpenProblems(ctx context.Context, host string, sel zabbix.ProblemSelector) ([]zabbix.Problem, error)
}

// ZabbixParams carries the zabbix.api tunables the fetch needs.
type ZabbixParams struct {
	TimeoutSeconds  int
	HostLabel       string
	FlapWindowHours int
}

// Bounding caps (ADR-0032): the evidence pack stays bounded no matter how
// chatty the instance is. Internal constants, not config (the Loki Normalize
// philosophy).
const (
	zabbixRunbookMaxChars  = 2000
	zabbixOtherProblemsMax = 20
	zabbixAcknowledgesMax  = 20
	zabbixDependenciesMax  = 20
)

// ZabbixContext is the Zabbix context (CONTEXT.md): the curated, bounded
// bundle persisted as the `zabbix` section of the enrichment envelope.
// Persist-as-rendered — prompt, store, and MCP replay see this exact shape.
type ZabbixContext struct {
	Source   string              `json:"source"`             // "zabbix"
	Operator *ZabbixOperatorView `json:"operator,omitempty"` // class 1; needs zabbix_trigger_id
	Topology *ZabbixTopologyView `json:"topology,omitempty"` // class 2; needs only the host label
	Problem  *ZabbixProblemView  `json:"problem,omitempty"`  // class 3; needs zabbix_event_id
	// Outcome is the context-level roll-up (worst class wins: failed >
	// degraded > fetched; no_selector when no class was applicable) — it feeds
	// the Evidence line. Per-class specifics go in Note.
	Outcome   Outcome   `json:"outcome,omitempty"`
	Note      string    `json:"note,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
}

// ZabbixOperatorView is class 1 — operator knowledge from the trigger config.
type ZabbixOperatorView struct {
	TriggerName  string              `json:"trigger_name,omitempty"`
	Runbook      string              `json:"runbook,omitempty"` // capped; renders untrusted (ADR-0028 frame)
	URL          string              `json:"url,omitempty"`
	Expression   string              `json:"expression,omitempty"`
	Dependencies []zabbix.DepTrigger `json:"dependencies,omitempty"`
	FlapCount    int                 `json:"flap_count"`
	FlapWindowH  int                 `json:"flap_window_hours,omitempty"`
}

// ZabbixTopologyView is class 2 — CMDB/topology; survives non-Zabbix-origin.
type ZabbixTopologyView struct {
	VisibleName       string              `json:"visible_name,omitempty"`
	Description       string              `json:"description,omitempty"`
	Inventory         map[string]string   `json:"inventory,omitempty"`
	Templates         []string            `json:"templates,omitempty"`
	Groups            []string            `json:"groups,omitempty"`
	MaintenanceActive bool                `json:"maintenance_active"`
	Interfaces        []zabbix.IfaceState `json:"interfaces,omitempty"`
	OtherOpenProblems []zabbix.Problem    `json:"other_open_problems,omitempty"` // capped
}

// ZabbixProblemView is class 3 — problem detail & human interaction.
type ZabbixProblemView struct {
	Severity     string             `json:"severity,omitempty"`
	Ongoing      bool               `json:"ongoing"`
	DurationSecs int64              `json:"duration_secs,omitempty"`
	Acknowledges []zabbix.AckEntry  `json:"acknowledges,omitempty"` // capped; messages render untrusted
	Suppression  zabbix.Suppression `json:"suppression"`
	OpData       string             `json:"opdata,omitempty"`
	CauseEventID string             `json:"cause_eventid,omitempty"`
}

// FetchZabbixContext assembles the Zabbix context: three classes fanned out
// concurrently under one timeout budget, each independently best-effort.
// Never blocks or fails triage; nil client → nil (source disabled).
func FetchZabbixContext(ctx context.Context, client ZabbixReader, params ZabbixParams, alerts []store.Alert, t time.Time, incidentID string, logger *slog.Logger) *ZabbixContext {
	if client == nil {
		return nil
	}
	hostLabel := params.HostLabel
	if hostLabel == "" {
		hostLabel = "host"
	}
	var triggerID, eventID, host string
	for _, a := range alerts {
		if triggerID == "" {
			triggerID = a.Labels["zabbix_trigger_id"]
		}
		if eventID == "" {
			eventID = a.Annotations["zabbix_event_id"]
		}
		if host == "" {
			host = a.Labels[hostLabel]
		}
	}

	z := &ZabbixContext{Source: "zabbix", FetchedAt: t}
	if triggerID == "" && eventID == "" && host == "" {
		z.Outcome = OutcomeNoSelector
		z.Note = "no zabbix identity on this incident (no trigger id, event id, or host label)"
		return z
	}

	timeout := time.Duration(params.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	flapWindow := time.Duration(params.FlapWindowHours) * time.Hour
	if flapWindow <= 0 {
		flapWindow = 24 * time.Hour
	}

	var mu sync.Mutex
	var notes []string
	var degraded, failed bool
	record := func(class string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if errors.Is(err, context.DeadlineExceeded) {
			degraded = true
			notes = append(notes, class+": timed out (slow, not down)")
		} else {
			failed = true
			notes = append(notes, class+": "+err.Error())
		}
		logger.Warn("acutetriage: zabbix class fetch failed",
			"incident_id", incidentID, "class", class, "err", err.Error())
	}

	var wg sync.WaitGroup
	// Class 1 — operator knowledge (needs trigger id).
	if triggerID != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			op, err := client.TriggerContext(fetchCtx, triggerID)
			if err != nil {
				record("operator", err)
				return
			}
			view := &ZabbixOperatorView{
				TriggerName:  op.TriggerName,
				Runbook:      capChars(op.Runbook, zabbixRunbookMaxChars),
				URL:          op.URL,
				Expression:   op.Expression,
				Dependencies: capDeps(op.Dependencies, zabbixDependenciesMax),
				FlapWindowH:  int(flapWindow.Hours()),
			}
			if n, err := client.FlapCount(fetchCtx, triggerID, t.Add(-flapWindow)); err == nil {
				view.FlapCount = n
			}
			mu.Lock()
			z.Operator = view
			mu.Unlock()
		}()
	}
	// Class 2 — CMDB/topology (needs only host).
	if host != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			top, err := client.HostContext(fetchCtx, host)
			if err != nil {
				record("topology", err)
				return
			}
			view := &ZabbixTopologyView{
				VisibleName: top.VisibleName, Description: top.Description,
				Inventory: top.Inventory, Templates: top.Templates, Groups: top.Groups,
				MaintenanceActive: top.MaintenanceActive, Interfaces: top.Interfaces,
			}
			if probs, err := client.OpenProblems(fetchCtx, host, zabbix.ProblemSelector{}); err == nil {
				if len(probs) > zabbixOtherProblemsMax {
					probs = probs[:zabbixOtherProblemsMax]
				}
				view.OtherOpenProblems = probs
			}
			mu.Lock()
			z.Topology = view
			mu.Unlock()
		}()
	}
	// Class 3 — problem detail (needs event id).
	if eventID != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pd, err := client.ProblemContext(fetchCtx, eventID)
			if err != nil {
				record("problem", err)
				return
			}
			acks := pd.Acknowledges
			if len(acks) > zabbixAcknowledgesMax {
				acks = acks[:zabbixAcknowledgesMax]
			}
			mu.Lock()
			z.Problem = &ZabbixProblemView{
				Severity: pd.Severity, Ongoing: pd.Ongoing, DurationSecs: pd.DurationSecs,
				Acknowledges: acks, Suppression: pd.Suppression,
				OpData: pd.OpData, CauseEventID: pd.CauseEventID,
			}
			mu.Unlock()
		}()
	}
	wg.Wait()

	if triggerID == "" && eventID == "" {
		notes = append(notes, "not zabbix-origin: operator/problem classes skipped (no zabbix identity labels)")
	}
	switch {
	case failed:
		z.Outcome = OutcomeFailed
	case degraded:
		z.Outcome = OutcomeDegraded
	default:
		z.Outcome = OutcomeFetched
	}
	z.Note = strings.Join(notes, "; ")
	return z
}

// zabbixEntryCount is the Evidence line count: context entries given to triage.
func zabbixEntryCount(z *ZabbixContext) int {
	if z == nil {
		return 0
	}
	n := 0
	if z.Operator != nil {
		if z.Operator.Runbook != "" {
			n++
		}
		n += len(z.Operator.Dependencies)
	}
	if z.Topology != nil {
		n += len(z.Topology.OtherOpenProblems)
		if z.Topology.MaintenanceActive {
			n++
		}
		if z.Topology.VisibleName != "" || len(z.Topology.Inventory) > 0 {
			n++
		}
	}
	if z.Problem != nil {
		n += len(z.Problem.Acknowledges)
		if z.Problem.Suppression.Kind != "" && z.Problem.Suppression.Kind != "none" {
			n++
		}
	}
	return n
}

func capChars(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen]
}

func capDeps(d []zabbix.DepTrigger, maxLen int) []zabbix.DepTrigger {
	if len(d) <= maxLen {
		return d
	}
	return d[:maxLen]
}
