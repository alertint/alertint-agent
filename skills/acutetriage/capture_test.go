// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// fakeAnnotationSink is a notify.Notifier that also implements
// notify.AnnotationSink, so capture-engine tests can assert what the fan-out
// saw without a real Slack/stdout notifier.
type fakeAnnotationSink struct {
	events []notify.AnnotationEvent
}

func (f *fakeAnnotationSink) Name() string { return "fake" }
func (f *fakeAnnotationSink) Notify(context.Context, notify.Finding) error { return nil }
func (f *fakeAnnotationSink) OnAnnotation(_ context.Context, ev notify.AnnotationEvent) error {
	f.events = append(f.events, ev)
	return nil
}

// skillForCapture builds a Skill wired for capture-engine tests: the given
// store, a fake LLM (Annotate never calls it; CaptureVerdict tests script it
// separately), a real auditor over the same store, and a Multi notifier
// fanning to sink so annotation events can be asserted.
func skillForCapture(t *testing.T, st *store.Store, sink *fakeAnnotationSink) *acutetriage.Skill {
	t.Helper()
	return acutetriage.New(acutetriage.Config{MinAlerts: 1}, st, &fakeLLM{}, audit.New(st.DB()), notify.NewMulti(nil, sink), slog.Default())
}

// seedAnalyzedIncidentOnKey inserts an incident on groupKey with one member
// alert and a persisted (trivial) finding — status "analyzed" — the input
// shape the capture engine's write tools operate on.
func seedAnalyzedIncidentOnKey(t *testing.T, st *store.Store, groupKey string) store.Incident {
	t.Helper()
	ctx := context.Background()
	now := time.Now()
	inc := store.Incident{
		ID: uuid.NewString(), GroupKey: groupKey,
		FirstAlertAt: now, LastAlertAt: now, ReadyAt: now,
	}
	if err := st.InsertIncident(ctx, inc); err != nil {
		t.Fatalf("insert incident: %v", err)
	}
	if err := st.MarkIncidentReady(ctx, inc.ID); err != nil {
		t.Fatalf("mark incident ready: %v", err)
	}
	insertTestAlert(t, st, ctx, inc.ID, "fp-"+inc.ID, map[string]string{"alertname": "TargetDown"})
	if err := st.SaveIncidentOutput(ctx, inc.ID, `{"analysis_name":"x","overall_issue":"y"}`, "x", "y", 0.7, "{}"); err != nil {
		t.Fatalf("save incident output: %v", err)
	}
	got, err := st.GetIncidentByID(ctx, inc.ID)
	if err != nil {
		t.Fatalf("reload incident: %v", err)
	}
	return *got
}

func TestAnnotate_CorrectionDemotesAuditsNotifies(t *testing.T) {
	st := newTestStore(t)
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCapture(t, st, sink))

	res, err := eng.Annotate(context.Background(), acutetriage.AnnotateRequest{
		IncidentID: inc.ID, Kind: "correction", Note: "not an AZ outage",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Demoted {
		t.Fatal("correction must demote")
	}

	var marks int
	if err := st.DB().QueryRowContext(context.Background(),
		`SELECT memory_refute_marks FROM incidents WHERE id = ?`, inc.ID).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	if marks != 2 { // demotionThreshold
		t.Fatalf("marks floored at 2, got %d", marks)
	}

	if n := auditCount(t, st, "incident.annotated"); n != 1 {
		t.Fatalf("want exactly one incident.annotated audit row, got %d", n)
	}
	auditor := audit.New(st.DB())
	rep, err := auditor.Verify(context.Background())
	if err != nil || !rep.OK {
		t.Fatalf("audit chain must verify: report=%+v err=%v", rep, err)
	}

	if len(sink.events) != 1 || sink.events[0].Kind != "correction" || sink.events[0].Note != "not an AZ outage" {
		t.Fatalf("annotation sink saw %+v", sink.events)
	}
}

func TestAnnotate_Validation(t *testing.T) {
	st := newTestStore(t)
	inc := seedAnalyzedIncidentOnKey(t, st, "service=api")
	sink := &fakeAnnotationSink{}
	eng := acutetriage.NewCaptureEngine(skillForCapture(t, st, sink))
	ctx := context.Background()

	if _, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{IncidentID: inc.ID, Kind: "confirmation", Note: "x"}); err == nil {
		t.Fatal("kind=confirmation must be rejected — only capture writes it")
	}
	if _, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{IncidentID: "nope", Kind: "observation", Note: "x"}); err == nil {
		t.Fatal("unknown incident must error")
	}

	res, err := eng.Annotate(ctx, acutetriage.AnnotateRequest{IncidentID: inc.ID, Kind: "observation", Note: "fyi"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Demoted {
		t.Fatal("an observation must not demote")
	}
	var marks int
	if err := st.DB().QueryRowContext(ctx,
		`SELECT memory_refute_marks FROM incidents WHERE id = ?`, inc.ID).Scan(&marks); err != nil {
		t.Fatal(err)
	}
	if marks != 0 {
		t.Fatalf("an observation must not touch marks, got %d", marks)
	}
}
