// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// ----------------------------------------------------------------------
// Task 9 production wiring proofs.
// ----------------------------------------------------------------------

// TestProductionCorrelatorHasNoAcuteTriageDispatchDependency proves the
// Correlator production wires carries no analyzer/LLM dispatch dependency
// at all: the one IncidentSink runServe hands correlator.New is the no-op
// sink, never a Skill-backed wrapper. The Correlator's own constructor and
// Config carry no LLM client field of their own, so the sink is the
// complete proof surface. Acute Triage dispatch belongs exclusively to the
// Triage worker polling the gated incident_triage schedule.
func TestProductionCorrelatorHasNoAcuteTriageDispatchDependency(t *testing.T) {
	sink := productionIncidentSink()
	if _, ok := sink.(correlator.NopIncidentSink); !ok {
		t.Fatalf("production IncidentSink = %T, want correlator.NopIncidentSink — any other sink hands the Correlator a dispatch dependency it must not own", sink)
	}
	if reflect.TypeOf(sink).NumField() != 0 {
		t.Fatalf("production IncidentSink %T carries %d fields, want 0 — it must hold no Skill, client, or store", sink, reflect.TypeOf(sink).NumField())
	}
}

// The refactored Acute Triage skill structurally satisfies every interface
// the Situation controller runtime's Triage worker needs — proven at
// compile time, so a future signature drift on either side fails the build
// long before any test runs. skills/acutetriage.Skill.Analyze/AfterCommit/
// OnTriageExhausted (Task 7) are what newControllerRuntime passes as
// situation.AcuteAnalyzer/AfterCommitter/ExhaustionNotifier respectively.
var (
	_ situation.AcuteAnalyzer      = (*acutetriage.Skill)(nil)
	_ situation.AfterCommitter     = (*acutetriage.Skill)(nil)
	_ situation.ExhaustionNotifier = (*acutetriage.Skill)(nil)
	// MinimumMemberAlertsPolicy is what lets the Triage worker resolve a
	// below-minimum clean skip BEFORE claiming, so it consumes no attempt.
	_ situation.MinimumMemberAlertsPolicy = (*acutetriage.Skill)(nil)
)

func TestRun_VersionFlagPrintsVersionAndExitsCleanly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run --version: %v (stderr=%q)", err, stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	if got == "" {
		t.Fatal("--version produced empty output")
	}
}

func TestRun_RejectsUnknownLogLevel(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--log-level", "loud"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown log level")
	}
}

// TestBuildLogger_Precedence verifies CLI flag > config > built-in default for
// both level and format, and that auto resolves to json on a non-TTY writer
// (a bytes.Buffer). The returned strings are what the startup line reports.
func TestBuildLogger_Precedence(t *testing.T) {
	cases := []struct {
		name                                       string
		flagLevel, flagFormat, cfgLevel, cfgFormat string
		wantLevel, wantFormat                      string
	}{
		{"defaults when all empty", "", "", "", "", "info", "json"},
		{"config applied over default", "", "", "debug", "json", "debug", "json"},
		{"flag overrides config", "warn", "json", "debug", "console", "warn", "json"},
		{"config format auto resolves to json off-tty", "", "", "", "auto", "info", "json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			_, level, format, err := buildLogger(tc.flagLevel, tc.flagFormat, tc.cfgLevel, tc.cfgFormat, &buf)
			if err != nil {
				t.Fatalf("buildLogger: %v", err)
			}
			if level != tc.wantLevel {
				t.Errorf("level = %q, want %q", level, tc.wantLevel)
			}
			if format != tc.wantFormat {
				t.Errorf("format = %q, want %q", format, tc.wantFormat)
			}
		})
	}
}
