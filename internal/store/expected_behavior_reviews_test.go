// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func TestExpectedBehaviorReviewReminderIsDurableSparseAndAdvancesOnlyAfterDelivery(t *testing.T) {
	st := newTestStore(t)
	f := newExpectedBehaviorFixture(t, st)
	created, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), f.confirmRequest(t, st, "review-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	due := f.policy.ReviewDueAt
	planned, err := st.PlanExpectedBehaviorReviews(context.Background(), due, 30)
	if err != nil || len(planned) != 1 {
		t.Fatalf("plan = %+v, %v", planned, err)
	}
	if replay, err := st.PlanExpectedBehaviorReviews(context.Background(), due.Add(time.Minute), 30); err != nil || len(replay) != 0 {
		t.Fatalf("replay = %+v, %v", replay, err)
	}
	claims, err := st.ClaimExpectedBehaviorReviews(context.Background(), "worker", due.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(claims) != 1 || claims[0].Intent.ID != planned[0].ID {
		t.Fatalf("claims = %+v, %v", claims, err)
	}
	if err := st.RetryExpectedBehaviorReview(context.Background(), claims[0], "ratelimited", due.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	claims, err = st.ClaimExpectedBehaviorReviews(context.Background(), "worker", due.Add(3*time.Minute), time.Minute, 1)
	if err != nil || len(claims) != 1 || claims[0].Intent.ID != planned[0].ID {
		t.Fatalf("retry claim = %+v, %v", claims, err)
	}
	deliveredAt := due.Add(4 * time.Minute)
	if err := st.MarkExpectedBehaviorReviewDelivered(context.Background(), claims[0], situation.NotificationDelivery{Channel: "C1", MessageTS: "1.2", DeliveredAs: "root"}, deliveredAt); err != nil {
		t.Fatal(err)
	}
	var last sql.NullString
	if err := st.DB().QueryRowContext(context.Background(), `SELECT last_review_prompt_at FROM expected_behavior_envelope_heads WHERE envelope_id=?`, created.Revision.EnvelopeID).Scan(&last); err != nil {
		t.Fatal(err)
	}
	if !last.Valid || last.String != canonicalTime(deliveredAt) {
		t.Fatalf("last_review_prompt_at = %+v", last)
	}
	if next, err := st.PlanExpectedBehaviorReviews(context.Background(), deliveredAt.Add(29*24*time.Hour), 30); err != nil || len(next) != 0 {
		t.Fatalf("early next = %+v, %v", next, err)
	}
}

func TestExpectedBehaviorRevisionSupersedesPendingReview(t *testing.T) {
	st := newTestStore(t)
	f := newExpectedBehaviorFixture(t, st)
	created, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), f.confirmRequest(t, st, "review-revoke-confirm"))
	if err != nil {
		t.Fatal(err)
	}
	if planned, err := st.PlanExpectedBehaviorReviews(context.Background(), f.policy.ReviewDueAt, 30); err != nil || len(planned) != 1 {
		t.Fatalf("plan = %+v, %v", planned, err)
	}
	revoke := ExpectedBehaviorWrite{Operation: situationmodel.ExpectedBehaviorOperationRevoke, EnvelopeID: created.Revision.EnvelopeID,
		ExpectedCurrentVersion: 1, RequestID: "review-revoke", AssertedOperator: "Janis", Confirmed: true, Now: f.policy.ReviewDueAt.Add(time.Minute)}
	if _, err := st.WriteExpectedBehavior(context.Background(), audit.New(st.DB()), revoke); err != nil {
		t.Fatal(err)
	}
	claims, err := st.ClaimExpectedBehaviorReviews(context.Background(), "worker", f.policy.ReviewDueAt.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(claims) != 0 {
		t.Fatalf("claims after revoke = %+v, %v", claims, err)
	}
}
