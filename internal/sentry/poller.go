// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// connectorStateName is the connector_state row key for the release/deploy
// poller's watermark. Specs 2/3 use their own distinct names.
const connectorStateName = "sentry-releases"

// maxReleasePages bounds how many release pages one project scan paginates per
// cycle — a backstop against a misbehaving API returning an endless next cursor.
// The horizon stop normally ends pagination long before this.
const maxReleasePages = 100

// releaseSource is the narrow read surface the poller needs, satisfied by
// *Client (U2). The poller depends on this interface so poller_test.go injects a
// fake with no HTTP; the wire behavior is covered by the client tests.
type releaseSource interface {
	ListReleases(ctx context.Context, projects []string, cursor string) ([]Release, string, error)
	ListDeploys(ctx context.Context, project, version string) ([]Deploy, error)
}

// PollerConfig carries everything the poller needs that isn't the client itself:
// the host-root base URL and org (for change permalinks/labels, from the client),
// the optional project filter, the cadence/lookback/horizon tunables, and the
// change-retention window. U7 builds it from config + client.BaseURL()/Org().
type PollerConfig struct {
	BaseURL            string
	Org                string
	Projects           []string // empty = org-wide (project label omitted)
	PollInterval       time.Duration
	InitialLookback    time.Duration
	ReleaseScanHorizon time.Duration
	RetentionDays      int
}

// Poller is the Sentry Change source: a background loop that turns newly-seen
// deploys/releases into store.Change rows. It never touches the correlator. Its
// idempotency cursor (the watermark) persists in connector_state so it never
// re-emits across cycles or restarts (R9). Lifecycle mirrors the correlator:
// Start once, Stop to drain.
type Poller struct {
	src    releaseSource
	store  *store.Store
	cfg    PollerConfig
	logger *slog.Logger

	// now is the clock seam; tests set a fixed func for deterministic seed/prune.
	now func() time.Time

	once   sync.Once
	stopCh chan struct{}
	doneCh chan struct{}
}

// NewPoller builds a Poller. A zero PollInterval defaults to 60s; a nil logger
// falls back to slog.Default().
func NewPoller(src releaseSource, st *store.Store, cfg PollerConfig, logger *slog.Logger) *Poller {
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 60 * time.Second
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Poller{
		src:    src,
		store:  st,
		cfg:    cfg,
		logger: logger,
		now:    time.Now,
		stopCh: make(chan struct{}),
		doneCh: make(chan struct{}),
	}
}

// Start launches the background poll loop and returns immediately. It runs one
// cycle right away, then on every PollInterval tick. Call exactly once.
func (p *Poller) Start(ctx context.Context) {
	p.once.Do(func() { go p.loop(ctx) })
}

// Stop signals the loop to exit and waits for the in-flight cycle to finish.
// Must be called after Start.
func (p *Poller) Stop() {
	close(p.stopCh)
	<-p.doneCh
}

func (p *Poller) loop(ctx context.Context) {
	defer close(p.doneCh)

	// pollOnce runs in this goroutine, so a slow cycle delays the next tick
	// rather than overlapping with it.
	p.runCycle(ctx)

	ticker := time.NewTicker(p.cfg.PollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.runCycle(ctx)
		}
	}
}

// runCycle runs one poll cycle, isolating its failure: an error skips the cycle
// (logged WARN per R26) and the loop retries on the next tick — the process
// never crashes (R10).
func (p *Poller) runCycle(ctx context.Context) {
	if err := p.pollOnce(ctx); err != nil {
		p.logger.Warn("sentry poll cycle failed; skipping, will retry next tick", "err", err)
	}
}

// pollOnce is one fetch → map → atomic insert+advance → prune cycle. It loads
// (or seeds) the watermark, scans each in-scope project's recent releases for
// new deploys (or release-without-deploy fallbacks), and commits the batch and
// the advanced watermark in a single transaction (R15). Any error returns early
// without mutating state beyond what already committed.
func (p *Poller) pollOnce(ctx context.Context) error {
	wm, firstRun, err := p.loadWatermark(ctx)
	if err != nil {
		return err
	}

	now := p.now().UTC()
	horizonCutoff := now.Add(-p.cfg.ReleaseScanHorizon)

	var candidates []store.Change
	emit := func(c store.Change) { candidates = append(candidates, c) }
	for _, project := range p.projectsInScope() {
		if err := p.scanProject(ctx, project, wm, horizonCutoff, emit); err != nil {
			return err
		}
	}

	switch {
	case len(candidates) > 0:
		newWM, err := json.Marshal(advanceWatermark(wm, candidates))
		if err != nil {
			return fmt.Errorf("sentry: marshal watermark: %w", err)
		}
		if err := p.store.InsertChangesAndAdvanceWatermark(ctx, candidates, connectorStateName, string(newWM)); err != nil {
			return err
		}
	case firstRun:
		// Anchor the seed even with nothing to emit, so the lookback window
		// doesn't drift forward (and re-skip deploys) on every subsequent cycle.
		seed, err := json.Marshal(wm.persistable())
		if err != nil {
			return fmt.Errorf("sentry: marshal seed watermark: %w", err)
		}
		if err := p.store.SaveConnectorState(ctx, connectorStateName, string(seed)); err != nil {
			return err
		}
	}

	p.prune(ctx, now)
	p.logger.Info("sentry polled", "new_changes", len(candidates))
	return nil
}

// scanProject paginates one project's releases newest-first, stopping as soon as
// a release predates the scan horizon (KTD3) — since the list is date-descending,
// everything past that point is older too.
func (p *Poller) scanProject(ctx context.Context, project string, wm watermark, horizonCutoff time.Time, emit func(store.Change)) error {
	cursor := ""
	for page := 0; page < maxReleasePages; page++ {
		releases, next, err := p.src.ListReleases(ctx, projectFilter(project), cursor)
		if err != nil {
			return err
		}
		for _, r := range releases {
			if r.DateCreated.Before(horizonCutoff) {
				return nil // older than the horizon; date-desc ⇒ done with this project
			}
			if err := p.scanRelease(ctx, project, r, wm, emit); err != nil {
				return err
			}
		}
		if next == "" {
			break
		}
		cursor = next
	}
	return nil
}

// scanRelease decides, for one release, whether to spend the per-release deploys
// call. The inline lastDeploy gate uses the SAME shouldEmit predicate as the
// per-candidate guard: it fires only when the newest deploy is newer than the
// watermark (or equal-but-unseen at the boundary), so quiescent releases cost no
// extra request (KTD3). A release with no deploys at all falls back to one
// release change.
func (p *Poller) scanRelease(ctx context.Context, project string, r Release, wm watermark, emit func(store.Change)) error {
	if r.LastDeploy != nil && wm.shouldEmit(r.LastDeploy.DateFinished, deployKey(r.LastDeploy.ID)) {
		deploys, err := p.src.ListDeploys(ctx, project, r.Version)
		if err != nil {
			return err
		}
		for _, d := range deploys {
			key := deployKey(d.ID)
			if !wm.shouldEmit(d.DateFinished, key) {
				continue
			}
			c := mapDeploy(p.cfg.BaseURL, p.cfg.Org, project, r.Version, d)
			c.ID = key
			p.stamp(&c)
			if p.keep(c) {
				emit(c)
			}
		}
		return nil
	}

	if r.DeployCount == 0 {
		key := releaseKey(project, r.Version)
		if wm.shouldEmit(releaseOccurredAt(r), key) {
			c := mapRelease(p.cfg.BaseURL, p.cfg.Org, project, r)
			c.ID = key
			p.stamp(&c)
			if p.keep(c) {
				emit(c)
			}
		}
	}
	return nil
}

// stamp fills the acquisition timestamp the mapping leaves zero.
func (p *Poller) stamp(c *store.Change) { c.ReceivedAt = p.now().UTC() }

// keep is defense-in-depth: it drops (and WARNs) any candidate that would fail
// validateChange — a zero-label degenerate release (e.g. org-wide with no
// project) or a deploy with no finish time — so one malformed item can't roll
// back the whole cycle's batch.
func (p *Poller) keep(c store.Change) bool {
	if len(c.Labels) == 0 {
		p.logger.Warn("sentry: dropping change with no labels", "kind", c.Kind, "version", c.Version)
		return false
	}
	if c.OccurredAt.IsZero() {
		p.logger.Warn("sentry: dropping change with zero occurred_at", "kind", c.Kind, "version", c.Version)
		return false
	}
	return true
}

// prune bounds the append-only changes table by the configured retention,
// mirroring the change receiver. Pruning failure is non-fatal (logged WARN); it
// never fails the cycle that already committed its changes.
func (p *Poller) prune(ctx context.Context, now time.Time) {
	if p.cfg.RetentionDays <= 0 {
		return
	}
	cutoff := now.AddDate(0, 0, -p.cfg.RetentionDays)
	if _, err := p.store.PruneChanges(ctx, cutoff); err != nil {
		p.logger.Warn("sentry: prune changes failed", "err", err)
	}
}

func (p *Poller) projectsInScope() []string {
	if len(p.cfg.Projects) > 0 {
		return p.cfg.Projects
	}
	return []string{""} // org-wide sentinel
}

// projectFilter maps the in-scope project to the ListReleases filter: a concrete
// slug becomes a one-element filter; the org-wide sentinel ("") becomes nil.
func projectFilter(project string) []string {
	if project == "" {
		return nil
	}
	return []string{project}
}

func (p *Poller) loadWatermark(ctx context.Context) (watermark, bool, error) {
	val, found, err := p.store.LoadConnectorState(ctx, connectorStateName)
	if err != nil {
		return watermark{}, false, err
	}
	if !found {
		seed := watermark{LastEmittedAt: p.now().UTC().Add(-p.cfg.InitialLookback)}
		seed.buildSeen()
		return seed, true, nil
	}
	var wm watermark
	if err := json.Unmarshal([]byte(val), &wm); err != nil {
		return watermark{}, false, fmt.Errorf("sentry: decode watermark: %w", err)
	}
	wm.buildSeen()
	return wm, false, nil
}

// watermark is the persisted idempotency cursor (KTD2). LastEmittedAt is the
// newest occurred_at emitted so far; BoundaryDeployIDs are the boundary keys at
// exactly that instant, so a same-timestamp event that wasn't yet seen still
// gets emitted while already-seen ones don't. seen is the lookup form, rebuilt
// after load (not serialized).
type watermark struct {
	LastEmittedAt     time.Time `json:"last_emitted_at"`
	BoundaryDeployIDs []string  `json:"boundary_deploy_ids"`

	seen map[string]bool
}

func (wm *watermark) buildSeen() {
	wm.seen = make(map[string]bool, len(wm.BoundaryDeployIDs))
	for _, id := range wm.BoundaryDeployIDs {
		wm.seen[id] = true
	}
}

// persistable returns a copy with a non-nil BoundaryDeployIDs so the seed
// serializes as [] rather than null.
func (wm *watermark) persistable() watermark {
	out := *wm
	if out.BoundaryDeployIDs == nil {
		out.BoundaryDeployIDs = []string{}
	}
	return out
}

// shouldEmit is the KTD2 guard: emit when the event is strictly newer than the
// watermark, or exactly at the boundary instant but not already seen there.
func (wm *watermark) shouldEmit(occurred time.Time, key string) bool {
	switch {
	case occurred.After(wm.LastEmittedAt):
		return true
	case occurred.Equal(wm.LastEmittedAt):
		return !wm.seen[key]
	default:
		return false
	}
}

// advanceWatermark computes the next watermark from the emitted batch: the new
// instant is the max occurred_at; the boundary set is every emitted key at that
// instant, carrying forward the previous boundary keys only when the instant did
// not advance (so equal-timestamp keys from earlier cycles aren't forgotten).
func advanceWatermark(prev watermark, emitted []store.Change) watermark {
	maxT := prev.LastEmittedAt
	for _, c := range emitted {
		if c.OccurredAt.After(maxT) {
			maxT = c.OccurredAt
		}
	}
	seen := map[string]bool{}
	if maxT.Equal(prev.LastEmittedAt) {
		for k := range prev.seen {
			seen[k] = true
		}
	}
	for _, c := range emitted {
		if c.OccurredAt.Equal(maxT) {
			seen[c.ID] = true
		}
	}
	ids := make([]string, 0, len(seen))
	for k := range seen {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	return watermark{LastEmittedAt: maxT.UTC(), BoundaryDeployIDs: ids}
}

func deployKey(id string) string { return "deploy:" + id }

func releaseKey(project, version string) string { return "release:" + project + ":" + version }

// releaseOccurredAt prefers the explicit release time, falling back to creation.
func releaseOccurredAt(r Release) time.Time {
	if r.DateReleased != nil {
		return *r.DateReleased
	}
	return r.DateCreated
}
