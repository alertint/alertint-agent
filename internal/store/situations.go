// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import "time"

// SituationInput is one durable, deterministically-idempotent fact destined
// for the situation_input_outbox — the only channel through which a
// correlation-side mutation (a correlated delivery, an Incident's ready
// transition, ...) hands work to the Situation controller. Task 5 needs only
// this struct to insert a Situation input atomically alongside an Incident
// mutation; Task 7 extends this file with the rest of the Situation store
// surface (claims, advancement, and friends).
type SituationInput struct {
	ID             string
	IdempotencyKey string
	IncidentID     string
	Kind           string
	GroupKey       string
	DeliveryID     *string
	OccurredAt     time.Time
}
