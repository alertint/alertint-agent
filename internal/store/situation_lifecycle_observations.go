// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"time"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

// SourceLifecycleObservations derives one authoritative lifecycle
// observation per member Alert of situationID from its durable deliveries
// — the store_read capability's lifecycle-phase evidence (Plan 4 review
// F1, spec.md A6). For each Alert the chronologically latest delivery
// decides: firing or resolved, its acquisition mode and poll interval,
// the source's own event times/basis, and a deadline anchored at THAT
// observation plus the lifecycle horizon (24 h by default; a profile's
// horizonTier may widen it to 7 d, never shorten). A resolved observation
// never expires; a firing one ages to unobserved past its deadline in the
// reducer. Output is ordered by alert id.
func (s *Store) SourceLifecycleObservations(ctx context.Context, situationID, horizonTier string) ([]observationmodel.SourceLifecycleObservation, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("store: begin source lifecycle observations: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	deliveries, err := loadSituationDeliveriesTx(ctx, tx, situationID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit source lifecycle observations: %w", err)
	}
	return DeriveSourceLifecycleObservations(deliveries, horizonTier), nil
}

// DeriveSourceLifecycleObservations is SourceLifecycleObservations' pure
// reduction over already-loaded deliveries.
func DeriveSourceLifecycleObservations(deliveries []situation.Delivery, horizonTier string) []observationmodel.SourceLifecycleObservation {
	latest := make(map[string]situation.Delivery, len(deliveries))
	for _, d := range deliveries {
		key := d.AlertID
		if key == "" {
			key = "delivery:" + d.ID
		}
		cur, ok := latest[key]
		if !ok || d.ReceivedAt.After(cur.ReceivedAt) || (d.ReceivedAt.Equal(cur.ReceivedAt) && d.ID > cur.ID) {
			latest[key] = d
		}
	}
	keys := make([]string, 0, len(latest))
	for k := range latest {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	horizon := observationmodel.LifecycleHorizon(horizonTier)
	out := make([]observationmodel.SourceLifecycleObservation, 0, len(keys))
	for _, k := range keys {
		d := latest[k]
		state := situation.SourceStateFiring
		basis := string(d.StartedAtBasis)
		if d.Status == situationmodel.DeliveryStatusResolved {
			state = situation.SourceStateResolved
			basis = string(d.ResolvedAtBasis)
		}
		observedAt := d.ReceivedAt.UTC()
		mode := d.AcquisitionMode
		if mode == "" {
			mode = "webhook"
		}
		out = append(out, observationmodel.SourceLifecycleObservation{
			AlertID: k, EpisodeKey: d.EpisodeKey, Source: d.Source, State: state,
			ObservedAt: observedAt, EventStartedAt: utcPtr(d.SourceStartedAt), EventResolvedAt: utcPtr(d.SourceResolvedAt),
			TimeBasis: basis, AcquisitionMode: mode, PollIntervalSeconds: d.PollIntervalSeconds,
			DeadlineAt: observedAt.Add(horizon), HorizonTier: horizonTier,
			EvidenceRefs: []string{"delivery:" + d.ID},
		})
	}
	return out
}

func utcPtr(t *time.Time) *time.Time {
	if t == nil {
		return nil
	}
	u := t.UTC()
	return &u
}
