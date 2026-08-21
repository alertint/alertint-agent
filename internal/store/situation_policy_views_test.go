// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestListEnvelopesReturnsEveryEnvelopeHead(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-list-env", "host=list-env", "", situationmodel.LifecycleActive, now)

	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-list-env", "host=list-env", now)

	envelopes, err := s.ListEnvelopes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(envelopes) != 1 || envelopes[0].ID != envelopeID {
		t.Fatalf("envelopes=%+v", envelopes)
	}
}

func TestSituationJudgmentsReturnsRecordedJudgments(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-list-judge", "host=list-judge", "", situationmodel.LifecycleActive, now)

	j, err := s.RecordJudgment(ctx, testJudgmentSnapshot("s-list-judge", 1), testJudgmentRequest("s-list-judge"), "slack:U1", now, auditor, testAuditEvents("judgment.recorded"))
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.SituationJudgments(ctx, "s-list-judge")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != j.ID || got[0].AssertedOperator != "alice" {
		t.Fatalf("judgments=%+v", got)
	}
}

func TestSituationEnvelopeEvaluationsReturnsAppendedEvaluations(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	auditor := audit.New(s.DB())
	now := mustSituationTime(t, "2026-08-20T10:00:00Z")
	insertSituationFixture(t, s, "s-list-eval", "host=list-eval", "", situationmodel.LifecycleActive, now)
	_, envelopeID := confirmTestEnvelope(t, s, ctx, auditor, "s-list-eval", "host=list-eval", now)

	e := situationmodel.EnvelopeEvaluation{
		ID: "eval-list", EnvelopeID: envelopeID, EnvelopeVersion: 1, SituationID: "s-list-eval", InputVersion: 1,
		Result: situationmodel.EnvelopeEvaluationMatch, MatchedFields: []string{"schedule"}, QuietingAuthority: true, CreatedAt: now,
	}
	if err := s.AppendEnvelopeEvaluation(ctx, e); err != nil {
		t.Fatal(err)
	}

	got, err := s.SituationEnvelopeEvaluations(ctx, "s-list-eval")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "eval-list" || !got[0].QuietingAuthority || got[0].Result != situationmodel.EnvelopeEvaluationMatch {
		t.Fatalf("evaluations=%+v", got)
	}
}
