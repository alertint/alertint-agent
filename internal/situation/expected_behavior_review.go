// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ExpectedBehaviorReviewIntent is one durable, standalone reminder. It is
// deliberately not a Situation notification or a thread reply.
type ExpectedBehaviorReviewIntent struct {
	ID              string                     `json:"id"`
	EnvelopeID      string                     `json:"envelope_id"`
	EnvelopeVersion int                        `json:"envelope_version"`
	CycleStartedAt  time.Time                  `json:"cycle_started_at"`
	Head            model.ExpectedBehaviorHead `json:"expected_behavior"`
	MatchCount      int                        `json:"match_count"`
	Status          string                     `json:"status"`
	CreatedAt       time.Time                  `json:"created_at"`
	AttemptCount    int                        `json:"attempt_count"`
	DeliveredAt     *time.Time                 `json:"delivered_at,omitempty"`
}

type ExpectedBehaviorReviewClaim struct {
	Intent     ExpectedBehaviorReviewIntent
	ClaimOwner string
	ClaimToken int64
}

// ExpectedBehaviorReviewStore is optional on NotificationWorker so existing
// test doubles and installations without this migration remain decoupled.
type ExpectedBehaviorReviewStore interface {
	PlanExpectedBehaviorReviews(ctx context.Context, now time.Time, intervalDays int) ([]ExpectedBehaviorReviewIntent, error)
	RecoverExpiredExpectedBehaviorReviewClaims(ctx context.Context, now time.Time) (int, error)
	ClaimExpectedBehaviorReviews(ctx context.Context, owner string, now time.Time, lease time.Duration, limit int) ([]ExpectedBehaviorReviewClaim, error)
	MarkExpectedBehaviorReviewDelivered(ctx context.Context, claim ExpectedBehaviorReviewClaim, delivery NotificationDelivery, now time.Time) error
	RetryExpectedBehaviorReview(ctx context.Context, claim ExpectedBehaviorReviewClaim, errorClass string, retryAt time.Time) error
}

type ExpectedBehaviorReviewDeliverer interface {
	DeliverExpectedBehaviorReview(ctx context.Context, intent ExpectedBehaviorReviewIntent) (NotificationDelivery, error)
}
