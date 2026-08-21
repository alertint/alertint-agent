// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// defaultDependencyBroadcastAfter mirrors the strict config default
// (situations.dependency_health.broadcast_after_seconds).
const defaultDependencyBroadcastAfter = 5 * time.Minute

// ErrDependencyNotObserved is the contract a DependencyHealthStore's
// RecordDependencyRecovered returns for a dependency that was never
// recorded degraded/unavailable — a recovery observation for it is a quiet
// no-op, not a failure.
var ErrDependencyNotObserved = errors.New("situation: dependency was never observed unhealthy")

// DependencyHealthState is the durable installation-level state
// DependencyHealthSink needs, mirroring store.DependencyHealth's shape
// without an import (internal/store already imports internal/situation).
type DependencyHealthState struct {
	Dependency    string
	DegradedSince *time.Time
}

// DependencyHealthStore is the narrow durable boundary the dependency
// health sink needs. It is situation-owned rather than *store.Store for the
// same reason as Controller.Store: internal/store already imports
// internal/situation, so this package cannot import it back. A real adapter
// over store.Store's DependencyHealth*/CreateNotificationIntent methods
// lives in cmd/alertint wiring (Task 13).
type DependencyHealthStore interface {
	// RecordDependencyDegraded persists the dependency as degraded (or
	// unavailable), idempotently preserving the first observed
	// degraded_since across repeated calls. transitioned reports whether
	// this call actually moved the dependency out of healthy.
	RecordDependencyDegraded(ctx context.Context, dependency string, unavailable bool, observedAt time.Time) (DependencyHealthState, bool, error)
	// RecordDependencyRecovered persists the dependency as healthy again.
	// transitioned reports whether this call actually moved it out of
	// degraded/unavailable. A dependency never recorded degraded returns
	// ErrDependencyNotObserved — a quiet no-op, not a failure.
	RecordDependencyRecovered(ctx context.Context, dependency string, observedAt time.Time) (DependencyHealthState, bool, error)
	// HasDependencyRootIntent reports whether dependency already owns a
	// health_root notification intent, in any status — the exactly-once
	// guard for the one health root a sustained outage may produce,
	// mirroring PublisherStore.HasRootCreateIntent's situation-level
	// pattern.
	HasDependencyRootIntent(ctx context.Context, dependency string) (bool, error)
	CreateNotificationIntent(ctx context.Context, in model.NotificationIntent) error
	// ScheduleAffectedSituations unions reason into the due reasons of
	// every currently active Situation whose evidence depends on
	// dependency, pulling their next reconciliation earlier — the fan-out
	// counterpart to Controller.Store.MarkDue's single-Situation form.
	ScheduleAffectedSituations(ctx context.Context, dependency string, reason model.DueReason, at time.Time) error
}

// DependencyHealthSink implements health.Sink: it turns installation-level
// probe transitions (and, per spec, any other subsystem's failure
// observation — "LLM failures feed the same installation-level dependency
// state without adding a separate probe") into durable dependency-health
// state, affected-Situation scheduling, and — only once a shared outage has
// been sustained past the configured threshold — the one permitted health
// root, with its one permitted recovery update. It is safe to call directly
// (bypassing health.Registry entirely) and is idempotent regardless of how
// often or how it is invoked: exactly-once root/update creation is enforced
// against durable state, not against call cadence.
type DependencyHealthSink struct {
	store          DependencyHealthStore
	broadcastAfter time.Duration
}

// NewDependencyHealthSink constructs a DependencyHealthSink. broadcastAfter
// <= 0 uses the spec default (5 minutes).
func NewDependencyHealthSink(store DependencyHealthStore, broadcastAfter time.Duration) *DependencyHealthSink {
	if broadcastAfter <= 0 {
		broadcastAfter = defaultDependencyBroadcastAfter
	}
	return &DependencyHealthSink{store: store, broadcastAfter: broadcastAfter}
}

// RecordDependencyStatus implements health.Sink.
func (d *DependencyHealthSink) RecordDependencyStatus(ctx context.Context, status health.Status) error {
	if strings.TrimSpace(status.Name) == "" {
		return errors.New("situation: dependency status requires a name")
	}
	if status.CheckedAt.IsZero() {
		return errors.New("situation: dependency status requires an observation time")
	}
	if status.OK {
		return d.observeRecovered(ctx, status)
	}
	return d.observeFailing(ctx, status)
}

// observeFailing persists the degraded/unavailable observation, schedules
// affected Situations the first time this outage begins, and creates the
// one permitted health root once — and only once — the outage has been
// sustained past the configured broadcast threshold. Every failing
// health.Status is treated as fully unavailable: health.Check has no
// partial/degraded signal today (its Probe returns only nil or an error).
func (d *DependencyHealthSink) observeFailing(ctx context.Context, status health.Status) error {
	current, transitioned, err := d.store.RecordDependencyDegraded(ctx, status.Name, true, status.CheckedAt)
	if err != nil {
		return fmt.Errorf("situation: record dependency degraded: %w", err)
	}
	if transitioned {
		if err := d.store.ScheduleAffectedSituations(ctx, status.Name, model.DueConnectorHealthChanged, status.CheckedAt); err != nil {
			return fmt.Errorf("situation: schedule situations affected by %s degradation: %w", status.Name, err)
		}
	}
	if current.DegradedSince == nil || status.CheckedAt.Sub(*current.DegradedSince) < d.broadcastAfter {
		return nil // not sustained long enough yet — a transient blip never broadcasts
	}
	exists, err := d.store.HasDependencyRootIntent(ctx, status.Name)
	if err != nil {
		return fmt.Errorf("situation: check existing health root for %s: %w", status.Name, err)
	}
	if exists {
		return nil // already broadcast for this outage
	}
	if err := d.store.CreateNotificationIntent(ctx, PlanDependencyHealthIntent(status.Name, true, status.CheckedAt)); err != nil {
		return fmt.Errorf("situation: create health root intent for %s: %w", status.Name, err)
	}
	return nil
}

// observeRecovered persists the recovery, schedules affected Situations
// exactly once (transitioned is true only on the first recovery
// observation after an outage — a later, redundant recovery observation
// reports transitioned=false and is a no-op here), and — only for a
// dependency that actually got a health root — creates the one permitted
// recovery update.
func (d *DependencyHealthSink) observeRecovered(ctx context.Context, status health.Status) error {
	_, transitioned, err := d.store.RecordDependencyRecovered(ctx, status.Name, status.CheckedAt)
	if err != nil {
		if errors.Is(err, ErrDependencyNotObserved) {
			return nil // never degraded: nothing to recover, nothing to broadcast
		}
		return fmt.Errorf("situation: record dependency recovered: %w", err)
	}
	if !transitioned {
		return nil
	}
	if err := d.store.ScheduleAffectedSituations(ctx, status.Name, model.DueConnectorHealthChanged, status.CheckedAt); err != nil {
		return fmt.Errorf("situation: schedule situations affected by %s recovery: %w", status.Name, err)
	}
	rooted, err := d.store.HasDependencyRootIntent(ctx, status.Name)
	if err != nil {
		return fmt.Errorf("situation: check existing health root for %s: %w", status.Name, err)
	}
	if !rooted {
		return nil // this outage never crossed the sustained threshold: recovers silently
	}
	if err := d.store.CreateNotificationIntent(ctx, PlanDependencyHealthIntent(status.Name, false, status.CheckedAt)); err != nil {
		return fmt.Errorf("situation: create health update intent for %s: %w", status.Name, err)
	}
	return nil
}
