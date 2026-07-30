// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/internal/zabbix"
)

type fakeZabbix struct {
	trigger     zabbix.Operator
	triggerErr  error
	problem     zabbix.ProblemDetail
	problemErr  error
	host        zabbix.Topology
	hostErr     error
	flap        int
	flapErr     error
	problems    []zabbix.Problem
	problemsErr error
	slow        time.Duration
}

func (f *fakeZabbix) TriggerContext(ctx context.Context, id string) (zabbix.Operator, error) {
	if f.slow > 0 {
		select {
		case <-time.After(f.slow):
		case <-ctx.Done():
			return zabbix.Operator{}, ctx.Err()
		}
	}
	return f.trigger, f.triggerErr
}
func (f *fakeZabbix) ProblemContext(ctx context.Context, id string) (zabbix.ProblemDetail, error) {
	return f.problem, f.problemErr
}
func (f *fakeZabbix) HostContext(ctx context.Context, host string) (zabbix.Topology, error) {
	return f.host, f.hostErr
}
func (f *fakeZabbix) FlapCount(ctx context.Context, id string, since time.Time) (int, error) {
	return f.flap, f.flapErr
}
func (f *fakeZabbix) OpenProblems(ctx context.Context, host string, sel zabbix.ProblemSelector) ([]zabbix.Problem, error) {
	return f.problems, f.problemsErr
}

func zabbixOriginAlerts() []store.Alert {
	return []store.Alert{{
		Labels:      map[string]string{"alertname": "T", "host": "db01", "severity": "high", "zabbix_trigger_id": "22713"},
		Annotations: map[string]string{"zabbix_event_id": "9134"},
	}}
}

func TestFetchZabbixContext_ZabbixOriginGetsAllThreeClasses(t *testing.T) {
	f := &fakeZabbix{
		trigger:  zabbix.Operator{TriggerName: "T", Runbook: "check the backup job", Severity: "4"},
		problem:  zabbix.ProblemDetail{Severity: "4", Ongoing: true},
		host:     zabbix.Topology{VisibleName: "DB primary", MaintenanceActive: false},
		flap:     3,
		problems: []zabbix.Problem{{EventID: "1", Name: "other problem"}},
	}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 5, HostLabel: "host", FlapWindowHours: 24},
		zabbixOriginAlerts(), time.Now(), "inc-1", slog.Default())
	if z == nil || z.Operator == nil || z.Topology == nil || z.Problem == nil {
		t.Fatalf("all three classes expected: %+v", z)
	}
	if z.Operator.FlapCount != 3 || z.Operator.Runbook != "check the backup job" {
		t.Fatalf("operator class: %+v", z.Operator)
	}
	if len(z.Topology.OtherOpenProblems) != 1 {
		t.Fatalf("topology other problems: %+v", z.Topology)
	}
	if z.Outcome != OutcomeFetched {
		t.Fatalf("outcome: %q", z.Outcome)
	}
}

func TestFetchZabbixContext_AlertmanagerOriginOnlyTopology(t *testing.T) {
	f := &fakeZabbix{host: zabbix.Topology{VisibleName: "web"}}
	alerts := []store.Alert{{Labels: map[string]string{"alertname": "x", "host": "web01"}}}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 5, HostLabel: "host"},
		alerts, time.Now(), "inc-2", slog.Default())
	if z.Operator != nil || z.Problem != nil {
		t.Fatalf("non-zabbix-origin must skip operator/problem: %+v", z)
	}
	if z.Topology == nil {
		t.Fatal("topology must still be attempted via the host label")
	}
	if !strings.Contains(z.Note, "not zabbix-origin") {
		t.Fatalf("note must explain the skipped classes: %q", z.Note)
	}
}

func TestFetchZabbixContext_NoIdentityAtAll(t *testing.T) {
	f := &fakeZabbix{}
	alerts := []store.Alert{{Labels: map[string]string{"alertname": "x"}}}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 5, HostLabel: "host"},
		alerts, time.Now(), "inc-3", slog.Default())
	if z == nil {
		t.Fatal("card must be non-nil even with nothing to fetch (visibility-over-silence)")
	}
	if z.Outcome != OutcomeNoSelector {
		t.Fatalf("outcome: got %q want no_selector", z.Outcome)
	}
}

func TestFetchZabbixContext_ClassFailureIsNotedOthersSurvive(t *testing.T) {
	f := &fakeZabbix{
		triggerErr: errors.New("boom"),
		host:       zabbix.Topology{VisibleName: "db"},
		problem:    zabbix.ProblemDetail{Ongoing: true},
	}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 5, HostLabel: "host"},
		zabbixOriginAlerts(), time.Now(), "inc-4", slog.Default())
	if z.Operator != nil {
		t.Fatal("failed class must be nil")
	}
	if z.Topology == nil || z.Problem == nil {
		t.Fatal("other classes must survive a class failure")
	}
	if z.Outcome != OutcomeFailed || !strings.Contains(z.Note, "operator") {
		t.Fatalf("roll-up: outcome=%q note=%q", z.Outcome, z.Note)
	}
}

func TestFetchZabbixContext_SlowClassIsDegraded(t *testing.T) {
	f := &fakeZabbix{
		slow:    2 * time.Second, // TriggerContext exceeds the 1s budget
		host:    zabbix.Topology{VisibleName: "db"},
		problem: zabbix.ProblemDetail{Ongoing: true},
	}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 1, HostLabel: "host"},
		zabbixOriginAlerts(), time.Now(), "inc-5", slog.Default())
	if z.Outcome != OutcomeDegraded {
		t.Fatalf("deadline-exceeded must roll up degraded, not failed: %q", z.Outcome)
	}
}

func TestFetchZabbixContext_BoundingCaps(t *testing.T) {
	longRunbook := strings.Repeat("x", 5000)
	manyProblems := make([]zabbix.Problem, 50)
	f := &fakeZabbix{
		trigger:  zabbix.Operator{Runbook: longRunbook},
		problems: manyProblems,
		problem:  zabbix.ProblemDetail{Ongoing: true},
	}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 5, HostLabel: "host"},
		zabbixOriginAlerts(), time.Now(), "inc-6", slog.Default())
	if len(z.Operator.Runbook) > 2000 {
		t.Fatalf("runbook must be capped at 2000 chars, got %d", len(z.Operator.Runbook))
	}
	if len(z.Topology.OtherOpenProblems) > 20 {
		t.Fatalf("other problems must be capped at 20, got %d", len(z.Topology.OtherOpenProblems))
	}
}

func TestFetchZabbixContext_NilClientNilCard(t *testing.T) {
	if z := FetchZabbixContext(context.Background(), nil, ZabbixParams{}, zabbixOriginAlerts(), time.Now(), "inc-7", slog.Default()); z != nil {
		t.Fatal("nil client must yield nil context")
	}
}

// TestFetchZabbixContext_FetchedButEmptyIsNotLiveEvidence covers a class that
// succeeds but returns nothing substantive (e.g. topology-only against a host
// with no groups/templates/interfaces/maintenance and no visible name): the
// context must roll up as OutcomeEmpty, not OutcomeFetched, so it never lifts
// the annotations-only confidence cap (hasLiveEvidence gates specifically on
// OutcomeFetched).
func TestFetchZabbixContext_FetchedButEmptyIsNotLiveEvidence(t *testing.T) {
	f := &fakeZabbix{host: zabbix.Topology{}} // every field zero-valued
	alerts := []store.Alert{{Labels: map[string]string{"alertname": "x", "host": "web01"}}}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 5, HostLabel: "host"},
		alerts, time.Now(), "inc-8", slog.Default())
	if z.Outcome != OutcomeEmpty {
		t.Fatalf("empty-but-fetched must roll up empty, not fetched: %q", z.Outcome)
	}
}

// TestFetchZabbixContext_FlapCountFailureIsNotedNotMisrepresented covers a
// FlapCount error after a successful TriggerContext: it must not surface as a
// silent "fired 0 times" (a real zero is indistinguishable from unknown), and
// the operator class itself must still succeed (a supplement failing is not a
// class failure).
func TestFetchZabbixContext_FlapCountFailureIsNotedNotMisrepresented(t *testing.T) {
	f := &fakeZabbix{
		trigger: zabbix.Operator{TriggerName: "T", Runbook: "r"},
		flapErr: errors.New("timeout"),
	}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 5, HostLabel: "host", FlapWindowHours: 24},
		zabbixOriginAlerts(), time.Now(), "inc-9", slog.Default())
	if z.Operator == nil {
		t.Fatal("a flap-count-only failure must not fail the operator class")
	}
	if z.Operator.FlapWindowH != 0 {
		t.Fatalf("FlapWindowH must stay 0 on a failed count (suppresses the misleading render), got %d", z.Operator.FlapWindowH)
	}
	if !strings.Contains(z.Note, "flap count") {
		t.Fatalf("flap count failure must be noted: %q", z.Note)
	}
}

// TestFetchZabbixContext_OtherProblemsFailureIsNoted covers an OpenProblems
// error after a successful HostContext: the topology class must still
// succeed, but the failure must be visible in Note rather than silently
// rendering "no other open problems".
func TestFetchZabbixContext_OtherProblemsFailureIsNoted(t *testing.T) {
	f := &fakeZabbix{
		host:        zabbix.Topology{VisibleName: "db"},
		problemsErr: errors.New("timeout"),
	}
	alerts := []store.Alert{{Labels: map[string]string{"alertname": "x", "host": "db01"}}}
	z := FetchZabbixContext(context.Background(), f, ZabbixParams{TimeoutSeconds: 5, HostLabel: "host"},
		alerts, time.Now(), "inc-10", slog.Default())
	if z.Topology == nil {
		t.Fatal("an other-open-problems-only failure must not fail the topology class")
	}
	if !strings.Contains(z.Note, "other open problems") {
		t.Fatalf("other-open-problems failure must be noted: %q", z.Note)
	}
}
