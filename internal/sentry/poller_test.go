// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// fakeSource is a no-HTTP releaseSource the poller tests drive directly. Fields
// are mutated between cycles to simulate new deploys arriving.
type fakeSource struct {
	mu       sync.Mutex
	releases []Release // returned for any project unless releasesByProject is set
	// releasesByProject, when non-nil, returns per-project release lists so
	// multi-project fan-out is exercised; the projects arg selects the list.
	releasesByProject map[string][]Release
	deploys           map[string][]Deploy
	releasesErr       error
	deploysErr        error
	// forcePages > 0 makes ListReleases always return a non-empty next cursor,
	// forcing scanProject onto the page-cap path.
	forcePages      bool
	relCalls        int
	depCalls        []string
	projectsQueried []string
}

func (f *fakeSource) ListReleases(_ context.Context, projects []string, _ string) ([]Release, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relCalls++
	f.projectsQueried = append(f.projectsQueried, projects...)
	if f.releasesErr != nil {
		return nil, "", f.releasesErr
	}
	next := ""
	if f.forcePages {
		next = "cursor-next"
	}
	rels := f.releases
	if f.releasesByProject != nil {
		key := ""
		if len(projects) > 0 {
			key = projects[0]
		}
		rels = f.releasesByProject[key]
	}
	return rels, next, nil
}

func (f *fakeSource) ListDeploys(_ context.Context, _, version string) ([]Deploy, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.depCalls = append(f.depCalls, version)
	if f.deploysErr != nil {
		return nil, f.deploysErr
	}
	return f.deploys[version], nil
}

func (f *fakeSource) deployCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.depCalls)
}

func (f *fakeSource) releaseCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.relCalls
}

const t0 = "2026-06-25T12:00:00Z"

func mustTime(t *testing.T) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, t0)
	if err != nil {
		t.Fatalf("parse time %q: %v", t0, err)
	}
	return tm.UTC()
}

// newTestPoller wires a poller to a fresh in-memory store with a fixed clock and
// a discard logger. Default cfg targets one project, 60m lookback, 30d horizon.
func newTestPoller(t *testing.T, src releaseSource, now time.Time, mutate func(*PollerConfig)) (*Poller, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	cfg := PollerConfig{
		BaseURL:            "https://sentry.io",
		Org:                "acme",
		Projects:           []string{"checkout"},
		PollInterval:       time.Hour,
		InitialLookback:    60 * time.Minute,
		ReleaseScanHorizon: 30 * 24 * time.Hour,
		RetentionDays:      30,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	logger := slog.New(slog.DiscardHandler)
	p := NewPoller(src, st, cfg, logger)
	p.now = func() time.Time { return now }
	return p, st
}

func wideWindow(now time.Time) (time.Time, time.Time) {
	return now.Add(-90 * 24 * time.Hour), now.Add(time.Hour)
}

func TestPoller_AE1_NewDeployEmittedAndWatermarkAdvances(t *testing.T) {
	now := mustTime(t)
	finished := now.Add(-5 * time.Minute)
	src := &fakeSource{
		releases: []Release{{
			Version:     "v1",
			DateCreated: now.Add(-time.Hour),
			DeployCount: 1,
			LastDeploy:  &Deploy{ID: "d-1", Environment: strptr("production"), DateFinished: finished},
		}},
		deploys: map[string][]Deploy{
			"v1": {{ID: "d-1", Environment: strptr("production"), DateFinished: finished}},
		},
	}
	p, st := newTestPoller(t, src, now, nil)

	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 1 || got[0].Kind != "deploy" || got[0].ID != "deploy:d-1" {
		t.Fatalf("changes = %+v, want one deploy:d-1", got)
	}
	// Watermark advanced to the deploy's finish time.
	val, found, _ := st.LoadConnectorState(context.Background(), connectorStateName)
	if !found {
		t.Fatal("watermark not persisted")
	}
	wm := decodeWM(t, val)
	if !wm.LastEmittedAt.Equal(finished) {
		t.Errorf("watermark LastEmittedAt = %v, want %v", wm.LastEmittedAt, finished)
	}
}

func TestPoller_AE2_RepeatPollNoDuplicate(t *testing.T) {
	now := mustTime(t)
	finished := now.Add(-5 * time.Minute)
	src := &fakeSource{
		releases: []Release{{
			Version: "v1", DateCreated: now.Add(-time.Hour), DeployCount: 1,
			LastDeploy: &Deploy{ID: "d-1", Environment: strptr("production"), DateFinished: finished},
		}},
		deploys: map[string][]Deploy{"v1": {{ID: "d-1", Environment: strptr("production"), DateFinished: finished}}},
	}
	p, st := newTestPoller(t, src, now, nil)

	for i := 0; i < 2; i++ {
		if err := p.pollOnce(context.Background()); err != nil {
			t.Fatalf("pollOnce %d: %v", i, err)
		}
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 1 {
		t.Fatalf("after repeat poll have %d changes, want 1 (no duplicate)", len(got))
	}
	// Second cycle's lastDeploy gate is closed → no second deploys call.
	if src.deployCallCount() != 1 {
		t.Errorf("ListDeploys called %d times, want 1 (gate skips the repeat)", src.deployCallCount())
	}
}

func TestPoller_AE3_RestartNoReEmitNoLoss(t *testing.T) {
	now := mustTime(t)
	finished := now.Add(-5 * time.Minute)
	rel := Release{Version: "v1", DateCreated: now.Add(-time.Hour), DeployCount: 1,
		LastDeploy: &Deploy{ID: "d-1", Environment: strptr("production"), DateFinished: finished}}
	src := &fakeSource{
		releases: []Release{rel},
		deploys:  map[string][]Deploy{"v1": {{ID: "d-1", Environment: strptr("production"), DateFinished: finished}}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}

	// Simulate a restart: a brand-new poller against the SAME persisted store.
	logger := slog.New(slog.DiscardHandler)
	p2 := NewPoller(src, st, p.cfg, logger)
	p2.now = func() time.Time { return now }
	if err := p2.pollOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2 (post-restart): %v", err)
	}

	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 1 {
		t.Fatalf("post-restart have %d changes, want 1 (no re-emit, no loss)", len(got))
	}
}

func TestPoller_AE4_ClientErrorSkipsCycleNoCrash(t *testing.T) {
	now := mustTime(t)
	src := &fakeSource{releasesErr: &APIError{StatusCode: http.StatusTooManyRequests, Body: "rate limited"}}
	p, st := newTestPoller(t, src, now, nil)

	err := p.pollOnce(context.Background())
	if err == nil {
		t.Fatal("expected error from failing client")
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 0 {
		t.Errorf("a failed cycle persisted %d changes, want 0", len(got))
	}
	// runCycle must swallow the error (no panic/crash) and keep going.
	p.runCycle(context.Background())
}

// TestPoller_DeploysErrorSkipsCycleNoChange covers the deploys-endpoint failure
// path — the symmetric counterpart to AE4's releases failure. A release with new
// deploy activity drives the ListDeploys call; when that errors, the cycle aborts
// without persisting changes or advancing/seeding the watermark, and retries next
// tick.
func TestPoller_DeploysErrorSkipsCycleNoChange(t *testing.T) {
	now := mustTime(t)
	src := &fakeSource{
		releases: []Release{{Version: "v1", DateCreated: now.Add(-time.Hour), DeployCount: 1,
			LastDeploy: &Deploy{ID: "d-1", Environment: strptr("production"), DateFinished: now.Add(-5 * time.Minute)}}},
		deploysErr: &APIError{StatusCode: http.StatusTooManyRequests, Body: "rate limited"},
	}
	p, st := newTestPoller(t, src, now, nil)

	if err := p.pollOnce(context.Background()); err == nil {
		t.Fatal("expected error from failing ListDeploys")
	}
	if src.deployCallCount() == 0 {
		t.Fatal("ListDeploys was never called; test does not exercise the deploys path")
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 0 {
		t.Errorf("a failed deploys cycle persisted %d changes, want 0", len(got))
	}
	if _, found, _ := st.LoadConnectorState(context.Background(), connectorStateName); found {
		t.Error("watermark was advanced/seeded despite a failed cycle")
	}
	// runCycle must swallow the error (no panic/crash) and keep going.
	p.runCycle(context.Background())
}

func TestPoller_AE5_ReleaseWithoutDeployEmitsReleaseChange(t *testing.T) {
	now := mustTime(t)
	src := &fakeSource{
		releases: []Release{{Version: "v2", DateCreated: now.Add(-30 * time.Minute), DeployCount: 0}},
		deploys:  map[string][]Deploy{},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 1 || got[0].Kind != "release" || got[0].Labels["project"] != "checkout" {
		t.Fatalf("changes = %+v, want one release change labeled project=checkout", got)
	}
	if src.deployCallCount() != 0 {
		t.Errorf("ListDeploys called for a release with no deploys")
	}
}

func TestPoller_AE9_MultiEnvDeploysEmitDistinctChanges(t *testing.T) {
	now := mustTime(t)
	staging := now.Add(-6 * time.Minute)
	prod := now.Add(-5 * time.Minute)
	src := &fakeSource{
		releases: []Release{{Version: "v3", DateCreated: now.Add(-time.Hour), DeployCount: 2,
			LastDeploy: &Deploy{ID: "d-p", Environment: strptr("production"), DateFinished: prod}}},
		deploys: map[string][]Deploy{"v3": {
			{ID: "d-s", Environment: strptr("staging"), DateFinished: staging},
			{ID: "d-p", Environment: strptr("production"), DateFinished: prod},
		}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 2 {
		t.Fatalf("multi-env produced %d changes, want 2", len(got))
	}
	envs := map[string]bool{}
	for _, c := range got {
		envs[c.Labels["environment"]] = true
	}
	if !envs["staging"] || !envs["production"] {
		t.Errorf("environments = %v, want staging+production", envs)
	}
}

func TestPoller_FirstRunSeedBackfillsWithinLookback(t *testing.T) {
	now := mustTime(t)
	withinLookback := now.Add(-30 * time.Minute) // inside the 60m seed window
	beforeLookback := now.Add(-90 * time.Minute) // older than the seed → excluded
	src := &fakeSource{
		releases: []Release{{Version: "v", DateCreated: now.Add(-2 * time.Hour), DeployCount: 2,
			LastDeploy: &Deploy{ID: "d-new", Environment: strptr("production"), DateFinished: withinLookback}}},
		deploys: map[string][]Deploy{"v": {
			{ID: "d-old", Environment: strptr("staging"), DateFinished: beforeLookback},
			{ID: "d-new", Environment: strptr("production"), DateFinished: withinLookback},
		}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 1 || got[0].ID != "deploy:d-new" {
		t.Fatalf("changes = %+v, want only deploy:d-new (within-lookback backfill)", got)
	}
}

func TestPoller_KTD3_OldReleaseWithinHorizonGetsNewDeploy(t *testing.T) {
	now := mustTime(t)
	// Release created 25d ago (inside the 30d horizon) but deployed today.
	src := &fakeSource{
		releases: []Release{{Version: "old-rel", DateCreated: now.AddDate(0, 0, -25), DeployCount: 1,
			LastDeploy: &Deploy{ID: "d-today", Environment: strptr("production"), DateFinished: now.Add(-time.Minute)}}},
		deploys: map[string][]Deploy{"old-rel": {{ID: "d-today", Environment: strptr("production"), DateFinished: now.Add(-time.Minute)}}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 1 || got[0].ID != "deploy:d-today" {
		t.Fatalf("changes = %+v, want the new deploy on the 25d-old release", got)
	}
}

func TestPoller_KTD3_LastDeployGateSkipsQuiescentRelease(t *testing.T) {
	now := mustTime(t)
	// Persist a watermark 10m old; the release's lastDeploy is 20m old (older).
	seed := `{"last_emitted_at":"` + now.Add(-10*time.Minute).Format(time.RFC3339Nano) + `","boundary_event_ids":[]}`
	src := &fakeSource{
		releases: []Release{{Version: "v", DateCreated: now.Add(-time.Hour), DeployCount: 1,
			LastDeploy: &Deploy{ID: "d-old", Environment: strptr("production"), DateFinished: now.Add(-20 * time.Minute)}}},
		deploys: map[string][]Deploy{"v": {{ID: "d-old", Environment: strptr("production"), DateFinished: now.Add(-20 * time.Minute)}}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := st.SaveConnectorState(context.Background(), connectorStateName, seed); err != nil {
		t.Fatalf("seed watermark: %v", err)
	}
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	if src.deployCallCount() != 0 {
		t.Errorf("ListDeploys called %d times; gate should skip a quiescent release", src.deployCallCount())
	}
	start, end := wideWindow(now)
	if got, _ := st.ChangesInWindow(context.Background(), start, end); len(got) != 0 {
		t.Errorf("emitted %d changes for a quiescent release, want 0", len(got))
	}
}

func TestPoller_KTD3_ReleaseOlderThanHorizonNotScanned(t *testing.T) {
	now := mustTime(t)
	// Created 40d ago (past the 30d horizon) with a fresh deploy today.
	src := &fakeSource{
		releases: []Release{{Version: "ancient", DateCreated: now.AddDate(0, 0, -40), DeployCount: 1,
			LastDeploy: &Deploy{ID: "d-new", Environment: strptr("production"), DateFinished: now}}},
		deploys: map[string][]Deploy{"ancient": {{ID: "d-new", Environment: strptr("production"), DateFinished: now}}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	if src.deployCallCount() != 0 {
		t.Errorf("ListDeploys called for a release past the horizon")
	}
	start, end := wideWindow(now)
	if got, _ := st.ChangesInWindow(context.Background(), start, end); len(got) != 0 {
		t.Errorf("emitted %d changes for an over-horizon release (documented miss), want 0", len(got))
	}
}

func TestPoller_R9_EqualTimestampBoundaryAcrossCycles(t *testing.T) {
	now := mustTime(t)
	tEq := now.Add(-5 * time.Minute)
	src := &fakeSource{
		releases: []Release{{Version: "v", DateCreated: now.Add(-time.Hour), DeployCount: 1,
			LastDeploy: &Deploy{ID: "d-1", Environment: strptr("envA"), DateFinished: tEq}}},
		deploys: map[string][]Deploy{"v": {{ID: "d-1", Environment: strptr("envA"), DateFinished: tEq}}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("cycle 1: %v", err)
	}

	// A second deploy lands at the EXACT same finish time, different env.
	src.mu.Lock()
	src.releases[0].LastDeploy = &Deploy{ID: "d-2", Environment: strptr("envB"), DateFinished: tEq}
	src.deploys["v"] = []Deploy{
		{ID: "d-1", Environment: strptr("envA"), DateFinished: tEq},
		{ID: "d-2", Environment: strptr("envB"), DateFinished: tEq},
	}
	src.mu.Unlock()

	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 2 {
		t.Fatalf("equal-timestamp boundary produced %d changes, want 2 (each once)", len(got))
	}
	ids := map[string]bool{}
	for _, c := range got {
		ids[c.ID] = true
	}
	if !ids["deploy:d-1"] || !ids["deploy:d-2"] {
		t.Errorf("change ids = %v, want both deploy:d-1 and deploy:d-2", ids)
	}
}

func TestPoller_PruneRunsWithRetentionCutoff(t *testing.T) {
	now := mustTime(t)
	ctx := context.Background()
	src := &fakeSource{releases: nil} // nothing new this cycle
	p, st := newTestPoller(t, src, now, nil)

	// An ancient change well past the 30d retention.
	old := store.Change{
		ID: "old-1", Source: "sentry", Kind: "deploy", Title: "old",
		Labels: map[string]string{"project": "checkout"}, OccurredAt: now.AddDate(0, 0, -40), ReceivedAt: now.AddDate(0, 0, -40),
	}
	if err := st.InsertChange(ctx, old); err != nil {
		t.Fatalf("seed old change: %v", err)
	}
	if err := p.pollOnce(ctx); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(ctx, start, end)
	if len(got) != 0 {
		t.Errorf("retention prune did not remove the 40d-old change: %+v", got)
	}
}

func TestPoller_ZeroLabelReleaseDropped(t *testing.T) {
	now := mustTime(t)
	// Org-wide (no project filter): a release with no deploys maps to a change
	// with no labels, which must be dropped rather than fail the batch insert.
	src := &fakeSource{
		releases: []Release{{Version: "v", DateCreated: now.Add(-10 * time.Minute), DeployCount: 0}},
		deploys:  map[string][]Deploy{},
	}
	p, st := newTestPoller(t, src, now, func(c *PollerConfig) { c.Projects = nil })
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	if got, _ := st.ChangesInWindow(context.Background(), start, end); len(got) != 0 {
		t.Errorf("zero-label release was not dropped: %+v", got)
	}
}

func TestPoller_StartStopGraceful(t *testing.T) {
	now := mustTime(t)
	src := &fakeSource{releases: nil}
	p, _ := newTestPoller(t, src, now, func(c *PollerConfig) { c.PollInterval = 5 * time.Millisecond })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p.Start(ctx)

	// Wait for the immediate cycle to run.
	deadline := time.Now().Add(2 * time.Second)
	for src.releaseCallCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("poller did not run its first cycle")
		}
		time.Sleep(time.Millisecond)
	}

	done := make(chan struct{})
	go func() { p.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return; goroutine leak / deadlock")
	}
}

func decodeWM(t *testing.T, val string) watermark {
	t.Helper()
	var wm watermark
	if err := json.Unmarshal([]byte(val), &wm); err != nil {
		t.Fatalf("decode watermark %q: %v", val, err)
	}
	return wm
}

// --- regression tests for the code-review fixes ---

// TestPoller_DuplicateChangeIDDeduped guards the poison-pill: two candidates
// sharing a Change.ID must not fail the batch's PK constraint and wedge the
// poller — finalizeBatch drops the duplicate, the batch commits, and the
// watermark advances so the next cycle proceeds.
func TestPoller_DuplicateChangeIDDeduped(t *testing.T) {
	now := mustTime(t)
	finished := now.Add(-5 * time.Minute)
	// Two deploys with the SAME id (a degenerate/buggy response) → same Change.ID.
	src := &fakeSource{
		releases: []Release{{Version: "v", DateCreated: now.Add(-time.Hour), DeployCount: 2,
			LastDeploy: &Deploy{ID: "dup", Environment: strptr("production"), DateFinished: finished}}},
		deploys: map[string][]Deploy{"v": {
			{ID: "dup", Environment: strptr("staging"), DateFinished: finished},
			{ID: "dup", Environment: strptr("production"), DateFinished: finished},
		}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce wedged on duplicate id: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 1 {
		t.Fatalf("duplicate id produced %d rows, want 1 (deduped)", len(got))
	}
	// Watermark advanced → next cycle is not wedged.
	if _, found, _ := st.LoadConnectorState(context.Background(), connectorStateName); !found {
		t.Fatal("watermark did not advance after deduped batch")
	}
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("second cycle failed (poller wedged): %v", err)
	}
}

// TestPoller_FutureDatedChangeDropped guards the watermark against a future
// timestamp: a deploy dated well ahead of now is dropped (not emitted) and must
// not poison the watermark, so a later real deploy still lands.
func TestPoller_FutureDatedChangeDropped(t *testing.T) {
	now := mustTime(t)
	future := now.Add(time.Hour) // well beyond futureSkew
	src := &fakeSource{
		releases: []Release{{Version: "v", DateCreated: now.Add(-time.Hour), DeployCount: 1,
			LastDeploy: &Deploy{ID: "d-future", Environment: strptr("production"), DateFinished: future}}},
		deploys: map[string][]Deploy{"v": {{ID: "d-future", Environment: strptr("production"), DateFinished: future}}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	if got, _ := st.ChangesInWindow(context.Background(), start, end); len(got) != 0 {
		t.Fatalf("future-dated deploy was emitted: %+v", got)
	}
	// Watermark must NOT have been pushed into the future. A real deploy at
	// now-5m on the next cycle should therefore still emit.
	src.mu.Lock()
	realFinish := now.Add(-5 * time.Minute)
	src.releases = []Release{{Version: "v2", DateCreated: now.Add(-time.Hour), DeployCount: 1,
		LastDeploy: &Deploy{ID: "d-real", Environment: strptr("production"), DateFinished: realFinish}}}
	src.deploys = map[string][]Deploy{"v2": {{ID: "d-real", Environment: strptr("production"), DateFinished: realFinish}}}
	src.mu.Unlock()
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("second pollOnce: %v", err)
	}
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 1 || got[0].ID != "deploy:d-real" {
		t.Fatalf("real deploy not emitted after a future-dated one — watermark poisoned: %+v", got)
	}
}

// TestPoller_DeployCountWithNilLastDeployFetchesDeploys guards the gate gap: a
// release reporting deploys but no inline lastDeploy must still be polled.
func TestPoller_DeployCountWithNilLastDeployFetchesDeploys(t *testing.T) {
	now := mustTime(t)
	finished := now.Add(-5 * time.Minute)
	src := &fakeSource{
		releases: []Release{{Version: "v", DateCreated: now.Add(-time.Hour), DeployCount: 1, LastDeploy: nil}},
		deploys:  map[string][]Deploy{"v": {{ID: "d-1", Environment: strptr("production"), DateFinished: finished}}},
	}
	p, st := newTestPoller(t, src, now, nil)
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	if src.deployCallCount() != 1 {
		t.Errorf("ListDeploys called %d times, want 1 (nil lastDeploy must not be read as 'nothing new')", src.deployCallCount())
	}
	start, end := wideWindow(now)
	if got, _ := st.ChangesInWindow(context.Background(), start, end); len(got) != 1 {
		t.Fatalf("deploy not emitted for DeployCount>0 / nil lastDeploy: %+v", got)
	}
}

// TestPoller_MultiProjectFanOut exercises the per-project iteration: each
// configured project is queried and its deploys accumulate into one batch + one
// watermark advance.
func TestPoller_MultiProjectFanOut(t *testing.T) {
	now := mustTime(t)
	fin := now.Add(-5 * time.Minute)
	src := &fakeSource{
		releasesByProject: map[string][]Release{
			"alpha": {{Version: "va", DateCreated: now.Add(-time.Hour), DeployCount: 1,
				LastDeploy: &Deploy{ID: "da", Environment: strptr("production"), DateFinished: fin}}},
			"beta": {{Version: "vb", DateCreated: now.Add(-time.Hour), DeployCount: 1,
				LastDeploy: &Deploy{ID: "db", Environment: strptr("production"), DateFinished: fin}}},
		},
		deploys: map[string][]Deploy{
			"va": {{ID: "da", Environment: strptr("production"), DateFinished: fin}},
			"vb": {{ID: "db", Environment: strptr("production"), DateFinished: fin}},
		},
	}
	p, st := newTestPoller(t, src, now, func(c *PollerConfig) { c.Projects = []string{"alpha", "beta"} })
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	start, end := wideWindow(now)
	got, _ := st.ChangesInWindow(context.Background(), start, end)
	if len(got) != 2 {
		t.Fatalf("multi-project produced %d changes, want 2", len(got))
	}
	src.mu.Lock()
	queried := append([]string(nil), src.projectsQueried...)
	src.mu.Unlock()
	seen := map[string]bool{}
	for _, q := range queried {
		seen[q] = true
	}
	if !seen["alpha"] || !seen["beta"] {
		t.Errorf("projects queried = %v, want both alpha and beta", queried)
	}
	ids := map[string]bool{}
	for _, c := range got {
		ids[c.Labels["project"]] = true
	}
	if !ids["alpha"] || !ids["beta"] {
		t.Errorf("change project labels = %v, want alpha+beta", ids)
	}
}

// TestPoller_ReleasePageCapWarns asserts scanProject surfaces a WARN (no silent
// truncation) when pagination hits the page cap.
func TestPoller_ReleasePageCapWarns(t *testing.T) {
	now := mustTime(t)
	capH := &capturingHandler{}
	src := &fakeSource{
		forcePages: true, // ListReleases always returns a next cursor
		releases:   []Release{{Version: "v", DateCreated: now.Add(-time.Hour), DeployCount: 0}},
		deploys:    map[string][]Deploy{},
	}
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	p := NewPoller(src, st, PollerConfig{
		BaseURL: "https://sentry.io", Org: "acme", Projects: []string{"checkout"},
		InitialLookback: time.Hour, ReleaseScanHorizon: 365 * 24 * time.Hour, RetentionDays: 30,
	}, slog.New(capH))
	p.now = func() time.Time { return now }
	if err := p.pollOnce(context.Background()); err != nil {
		t.Fatalf("pollOnce: %v", err)
	}
	if src.releaseCallCount() != maxReleasePages {
		t.Errorf("ListReleases called %d times, want the %d-page cap", src.releaseCallCount(), maxReleasePages)
	}
	if !capH.contains("page cap") {
		t.Errorf("expected a page-cap WARN; captured: %v", capH.messages())
	}
}

// TestPoller_StopCancelsInFlightCycle proves Stop aborts a slow in-flight cycle
// even when the parent context is still live (the error-driven shutdown path):
// ListReleases blocks until the cycle context is cancelled by Stop.
func TestPoller_StopCancelsInFlightCycle(t *testing.T) {
	now := mustTime(t)
	src := &blockingSource{entered: make(chan struct{}, 1)}
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	p := NewPoller(src, st, PollerConfig{
		BaseURL: "https://sentry.io", Org: "acme", Projects: []string{"checkout"},
		PollInterval: time.Hour, InitialLookback: time.Hour, ReleaseScanHorizon: 30 * 24 * time.Hour,
	}, slog.New(slog.DiscardHandler))
	p.now = func() time.Time { return now }

	// Parent context stays live; only Stop's internal cancel can unblock the cycle.
	p.Start(context.Background())
	select {
	case <-src.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("poll cycle never entered ListReleases")
	}

	done := make(chan struct{})
	go func() { p.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return; in-flight cycle was not cancelled")
	}
}

// blockingSource.ListReleases blocks until its context is cancelled.
type blockingSource struct {
	entered chan struct{}
}

func (b *blockingSource) ListReleases(ctx context.Context, _ []string, _ string) ([]Release, string, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, "", ctx.Err()
}

func (b *blockingSource) ListDeploys(_ context.Context, _, _ string) ([]Deploy, error) {
	return nil, nil
}

// capturingHandler is a minimal slog.Handler that records log messages for
// assertions.
type capturingHandler struct {
	mu   sync.Mutex
	msgs []string
}

func (h *capturingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *capturingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.msgs = append(h.msgs, r.Message)
	return nil
}

func (h *capturingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *capturingHandler) WithGroup(string) slog.Handler      { return h }

func (h *capturingHandler) contains(sub string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.msgs {
		if strings.Contains(m, sub) {
			return true
		}
	}
	return false
}

func (h *capturingHandler) messages() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.msgs...)
}
