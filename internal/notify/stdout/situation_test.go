// SPDX-License-Identifier: FSL-1.1-ALv2

package stdout

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

func testSituationStateEvent() SituationStateEvent {
	return SituationStateEvent{
		EventID: "transition:t1", SituationID: "s1", GroupKey: "host=db-prod-1",
		Lifecycle: model.LifecycleActive, Attention: model.AttentionInvestigate, AssessmentSequence: 3,
		SufficientReason: &model.SufficientReason{Code: "duration_outlier"},
		ActionContract:   model.ActionContract{NextActor: model.NextActorAlertint, ActionStatus: model.ActionStatusRunning},
		Limitations:      []string{"metric_samples_unavailable"},
		IncidentIDs:      []string{"inc_1"},
		OccurredAt:       time.Date(2026, 8, 20, 10, 0, 0, 0, time.UTC),
	}
}

func TestEmitSituationStateWritesVersionedLine(t *testing.T) {
	var buf bytes.Buffer
	n := New(&buf, nil, false)
	ev := testSituationStateEvent()
	if err := n.EmitSituationState(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(buf.String())
	var decoded SituationStateEvent
	if err := json.Unmarshal([]byte(line), &decoded); err != nil {
		t.Fatalf("decode: %v, line=%q", err, line)
	}
	if decoded.SchemaVersion != 1 {
		t.Fatalf("schema_version=%d, want 1", decoded.SchemaVersion)
	}
	if decoded.EventID != "transition:t1" || decoded.SituationID != "s1" {
		t.Fatalf("decoded=%+v", decoded)
	}
	if decoded.Handle != nil {
		t.Fatalf("handle should be null before first publication, got %v", *decoded.Handle)
	}
}

func TestEmitSituationStateAlwaysEmitsEvenWhenNotVerbose(t *testing.T) {
	// Situation state is the primary machine-readable stdout unit, unlike
	// the legacy verbose-gated Finding line — it must appear regardless of
	// verbosity, including for a silent (no Slack) Situation.
	var buf bytes.Buffer
	n := New(&buf, nil, false)
	if err := n.EmitSituationState(context.Background(), testSituationStateEvent()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected a state line even when not verbose")
	}
}

func TestEmitSituationStateRejectsMissingIdentity(t *testing.T) {
	var buf bytes.Buffer
	n := New(&buf, nil, false)
	ev := testSituationStateEvent()
	ev.EventID = ""
	if err := n.EmitSituationState(context.Background(), ev); err == nil {
		t.Fatal("expected an error for a missing event id")
	}
}

func TestEmitSituationStateRoundTripsDrillAndHandle(t *testing.T) {
	var buf bytes.Buffer
	n := New(&buf, nil, false)
	ev := testSituationStateEvent()
	handle := "db-prod-sustained-cpu"
	ev.Handle = &handle
	ev.Drill = true
	if err := n.EmitSituationState(context.Background(), ev); err != nil {
		t.Fatal(err)
	}
	var decoded SituationStateEvent
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Handle == nil || *decoded.Handle != handle || !decoded.Drill {
		t.Fatalf("decoded=%+v", decoded)
	}
}
