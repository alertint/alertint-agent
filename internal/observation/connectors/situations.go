// SPDX-License-Identifier: FSL-1.1-ALv2

package connectors

import (
	"context"
	"sort"
	"time"

	"github.com/alertint/alertint-agent/internal/observation"
	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// SituationReader is the read-only local-store surface the store_read
// capability reduces. It reads AlertINT's own immutable delivery ledger.
type SituationReader interface {
	SituationDeliveries(ctx context.Context, situationID string) ([]store.AlertDelivery, error)
	SituationMemberIncidents(ctx context.Context, situationID string) ([]store.Incident, error)
}

// symptomLifecycleFact is one symptom's bounded lifecycle history across the
// Situation's whole delivery ledger — how often it has been delivered, when it
// was first and last seen, and its current state.
type symptomLifecycleFact struct {
	Source     string    `json:"source"`
	Lifecycle  string    `json:"lifecycle"`
	Severity   string    `json:"severity,omitempty"`
	Deliveries int       `json:"deliveries"`
	Incidents  int       `json:"incidents"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// situationExecutor reduces the Situation's own durable evidence. It is the
// one capability that needs no external connector, so it stays available on a
// zero-integration installation.
type situationExecutor struct {
	store SituationReader
}

func (e situationExecutor) Execute(ctx context.Context, plan observationmodel.Plan) ([]observationmodel.Fact, observation.Cost, error) {
	in, err := newPlanContext(plan)
	if err != nil {
		return nil, observation.Cost{}, err
	}
	cost := observation.Cost{SourceCalls: 1}
	deliveries, err := e.store.SituationDeliveries(ctx, in.SituationID)
	if err != nil {
		return nil, cost, err
	}
	if len(deliveries) == 0 {
		return nil, cost, nil
	}
	incidents, err := e.store.SituationMemberIncidents(ctx, in.SituationID)
	if err != nil {
		return nil, cost, err
	}

	bySymptom := make(map[string]symptomLifecycleFact, len(deliveries))
	for _, delivery := range deliveries {
		key := delivery.Source + ":" + delivery.Alert.Fingerprint
		at := delivery.ReceivedAt.UTC()
		current, seen := bySymptom[key]
		if !seen {
			current = symptomLifecycleFact{Source: delivery.Source, FirstSeen: at, Incidents: len(incidents)}
		}
		current.Deliveries++
		if at.Before(current.FirstSeen) {
			current.FirstSeen = at
		}
		if !at.Before(current.LastSeen) {
			current.LastSeen = at
			current.Lifecycle = delivery.Alert.Status
			current.Severity = delivery.Alert.Labels["severity"]
		}
		bySymptom[key] = current
	}

	keys := make([]string, 0, len(bySymptom))
	for key := range bySymptom {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if in.Limit > 0 && len(keys) > in.Limit {
		keys = keys[:in.Limit]
	}
	facts := make([]observationmodel.Fact, 0, len(keys))
	for _, key := range keys {
		reduced := bySymptom[key]
		fact, err := in.fact(observationmodel.CapabilityStoreRead, "symptom_lifecycle", key, reduced,
			reduced.LastSeen, []string{"situation:" + in.SituationID})
		if err != nil {
			return nil, cost, err
		}
		facts = append(facts, fact)
	}
	return facts, cost, nil
}
