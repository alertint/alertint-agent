// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/logs"
)

func basePack() EvidencePack {
	return EvidencePack{
		IncidentID:   "inc-1",
		SharedLabels: map[string]string{"namespace": "prod"},
		AlertCount:   2,
	}
}

func TestUserPrompt_RendersLogLinesNewestFirst(t *testing.T) {
	e := &LogEnrichment{
		Source: "loki",
		Lines: []logs.Line{
			{Timestamp: time.Date(2026, 6, 17, 14, 3, 11, 0, time.UTC), Line: "panic: boom"},
			{Timestamp: time.Date(2026, 6, 17, 14, 3, 10, 0, time.UTC), Line: "ERROR db refused"},
		},
	}
	out := UserPrompt(basePack(), "{}", nil, e)
	if !strings.Contains(out, "Recent logs (loki, most recent first") {
		t.Fatalf("missing logs heading: %s", out)
	}
	iPanic := strings.Index(out, "panic: boom")
	iErr := strings.Index(out, "ERROR db refused")
	if iPanic < 0 || iErr < 0 || iPanic > iErr {
		t.Fatalf("lines not rendered newest-first: %s", out)
	}
}

func TestUserPrompt_RendersNoteWhenEmpty(t *testing.T) {
	e := &LogEnrichment{
		Source: "loki",
		Query:  `{namespace="prod",app="api"}`,
		Note:   "log backend returned no lines for this query",
	}
	out := UserPrompt(basePack(), "{}", nil, e)
	if !strings.Contains(out, "Recent logs (loki): log backend returned no lines") {
		t.Fatalf("note not rendered: %s", out)
	}
	if !strings.Contains(out, `query: {namespace="prod",app="api"}`) {
		t.Errorf("note should include the attempted query: %s", out)
	}
	if !strings.Contains(out, "missing evidence") {
		t.Errorf("note should warn against treating absence as healthy: %s", out)
	}
}

func TestUserPrompt_OmitsSectionWhenNil(t *testing.T) {
	out := UserPrompt(basePack(), "{}", nil, nil)
	if strings.Contains(out, "Recent logs") {
		t.Fatalf("logs section must be omitted when enrichment is nil: %s", out)
	}
}

func TestSystemPrompt_CarriesAbsentLogsGuidance(t *testing.T) {
	if !strings.Contains(SystemPrompt, "do NOT infer the service is healthy") {
		t.Error("SystemPrompt missing 'absent logs != healthy' guidance")
	}
	if !strings.Contains(SystemPrompt, "Recent logs") {
		t.Error("SystemPrompt should reference the Recent logs section")
	}
}
