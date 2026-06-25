// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/store"
)

// fakeSource is a no-HTTP releaseSource the poller tests drive directly. Fields
// are mutated between cycles to simulate new deploys arriving.
type fakeSource struct {
	mu          sync.Mutex
	releases    []Release
	deploys     map[string][]Deploy
	releasesErr error
	deploysErr  error
	relCalls    int
	depCalls    []string
}

func (f *fakeSource) ListReleases(_ context.Context, _ []string, _ string) ([]Release, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.relCalls++
	if f.releasesErr != nil {
		return nil, "", f.releasesErr
	}
	return f.releases, "", nil
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

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	tm, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("parse time %q: %v", s, err)
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	p := NewPoller(src, st, cfg, logger)
	p.now = func() time.Time { return now }
	return p, st
}

func wideWindow(now time.Time) (time.Time, time.Time) {
	return now.Add(-90 * 24 * time.Hour), now.Add(time.Hour)
}

func TestPoller_AE1_NewDeployEmittedAndWatermarkAdvances(t *testing.T) {
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
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
	now := mustTime(t, t0)
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

func TestPoller_AE5_ReleaseWithoutDeployEmitsReleaseChange(t *testing.T) {
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
	// Persist a watermark 10m old; the release's lastDeploy is 20m old (older).
	seed := `{"last_emitted_at":"` + now.Add(-10*time.Minute).Format(time.RFC3339Nano) + `","boundary_deploy_ids":[]}`
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
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
	now := mustTime(t, t0)
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
