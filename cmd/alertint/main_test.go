// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// ----------------------------------------------------------------------
// Task 9 production wiring proofs.
// ----------------------------------------------------------------------

// TestIncidentSinkCarriesNoDirectLLMDependency proves the Correlator's only
// path to any LLM call is through the Acute Triage skill it is handed
// (incidentSink{skill: skill}.OnIncidentReady -> skill.Run) — the
// Correlator's own constructor (correlator.New) and Config carry no LLM
// client field of their own, so this wrapper's field set is the complete
// proof surface: exactly one field, the skill.
func TestIncidentSinkCarriesNoDirectLLMDependency(t *testing.T) {
	typ := reflect.TypeOf(incidentSink{})
	if typ.NumField() != 1 {
		t.Fatalf("incidentSink has %d fields, want exactly 1 (skill) — a Correlator dispatch/LLM dependency would be a Task 9 regression", typ.NumField())
	}
	if typ.Field(0).Name != "skill" || typ.Field(0).Type != reflect.TypeOf((*acutetriage.Skill)(nil)) {
		t.Fatalf("incidentSink field = %s %s, want skill *acutetriage.Skill", typ.Field(0).Name, typ.Field(0).Type)
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
