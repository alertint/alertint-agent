// SPDX-License-Identifier: FSL-1.1-ALv2

// Capture: the feedback & verdict write-back engine (ADR-0027/0028). All
// writes land in AlertINT's own SQLite + audit chain — never in operator
// infrastructure. MCP handlers validate transport args and delegate here.

package acutetriage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// captureActor is the audit actor for operator write-backs over MCP.
const captureActor = "mcp"

// CaptureEngine wraps the triage Skill: the persist phase uses its store /
// auditor / notifier; the grade phase replays through its pipeline config
// ("current triage").
//
// Every operation runs on an MCP request goroutine that http.Server.Shutdown
// neither cancels nor reliably joins (its drain is bounded and gives up), so
// the engine owns that lifecycle itself. Two owners depend on it: the store,
// which closes only after no operation can still write to it, and the LLM
// health runner, whose final pass must run after no grade — a real
// generation, hence an LLM capability producer (ADR-0046) — can still report.
// Close therefore refuses every operation that begins after it, cancels only
// the grade phase of those in progress (the persist phase completes: the
// operator's verdict lands), and returns once every registered operation
// has left.
type CaptureEngine struct {
	sk *Skill

	mu      sync.Mutex
	closed  bool
	ops     sync.WaitGroup // every operation, from before its first store access
	closeCh chan struct{}  // closed once by Close; cancels every grade ctx
}

func NewCaptureEngine(sk *Skill) *CaptureEngine {
	return &CaptureEngine{sk: sk, closeCh: make(chan struct{})}
}

// ErrCaptureClosed is returned by every operation that begins once Close has
// begun: nothing of it was persisted, and the caller should retry after the
// agent is back.
var ErrCaptureClosed = errors.New("acutetriage: capture: agent shutting down — nothing persisted, retry after restart")

// Close refuses new operations, cancels grades in progress — their LLM calls
// end in a shutdown-driven cancellation, which the health tracker ignores
// (H1) — and waits for every operation already begun to return, bounded by
// ctx. A ctx error means an operation is still running: the owner must not
// treat the store or the health runner as free of this producer.
func (e *CaptureEngine) Close(ctx context.Context) error {
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		close(e.closeCh)
	}
	e.mu.Unlock()
	done := make(chan struct{})
	go func() {
		e.ops.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// enter registers one operation before it touches the store and returns its
// release func. It fails once Close has begun, so the WaitGroup can never be
// added to while Close waits on it.
func (e *CaptureEngine) enter() (func(), error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil, ErrCaptureClosed
	}
	e.ops.Add(1)
	return e.ops.Done, nil
}

// gradeContext derives the grade phase's ctx: bounded by gradeDeadline and
// canceled by Close. It reports closed when Close has already begun, so a
// grade never starts against a shutting-down runner.
func (e *CaptureEngine) gradeContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return nil, nil, ErrCaptureClosed
	}
	gctx, cancel := context.WithTimeout(ctx, gradeDeadline)
	go func() {
		select {
		case <-e.closeCh:
			cancel()
		case <-gctx.Done():
		}
	}()
	return gctx, cancel, nil
}

type AnnotateRequest struct {
	IncidentID string
	Kind       string // correction | observation
	Note       string
}

type AnnotateResult struct {
	AnnotationID int64
	Demoted      bool
}

// Annotate stores a kind+note annotation, audits, and fans out the annotation
// event (Slack thread reply + stdout line). Notes speak to the next
// investigator only (channel split, ADR-0028 as amended): an annotation pulls
// no lever — no recall demotion, no marks floor. Machine effect belongs to
// verdict capture. The finding row is never touched.
func (e *CaptureEngine) Annotate(ctx context.Context, req AnnotateRequest) (*AnnotateResult, error) {
	if req.Kind != "correction" && req.Kind != "observation" {
		return nil, fmt.Errorf("acutetriage: annotate: kind %q not in {correction, observation} (confirmation is written by capture only)", req.Kind)
	}
	release, err := e.enter()
	if err != nil {
		return nil, err
	}
	defer release()
	inc, err := e.sk.st.GetIncidentByID(ctx, req.IncidentID)
	if err != nil {
		return nil, fmt.Errorf("acutetriage: annotate: load incident: %w", err)
	}
	if inc == nil {
		return nil, fmt.Errorf("acutetriage: annotate: incident %q not found", req.IncidentID)
	}
	ann, err := e.sk.st.InsertIncidentAnnotation(ctx, req.IncidentID, req.Kind, req.Note)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("acutetriage: annotate: incident %q not found", req.IncidentID)
		}
		return nil, fmt.Errorf("acutetriage: annotate: %w", err)
	}
	if e.sk.auditor != nil {
		if err := e.sk.auditor.Append(ctx, captureActor, "incident.annotated", map[string]any{
			"incident_id": req.IncidentID, "kind": req.Kind, "note": req.Note,
		}); err != nil {
			return nil, fmt.Errorf("acutetriage: annotate: audit: %w", err)
		}
	}
	e.notifyAnnotation(ctx, inc, req.Kind, req.Note, 0)
	return &AnnotateResult{AnnotationID: ann.ID, Demoted: false}, nil
}

// notifyAnnotation fans the event out when the notifier supports it.
// Best-effort: a sink failure never fails the write that already landed.
func (e *CaptureEngine) notifyAnnotation(ctx context.Context, inc *store.Incident, kind, note string, verdictVersion int) {
	sink, ok := e.sk.notifier.(interface {
		OnAnnotation(ctx context.Context, ev notify.AnnotationEvent) error
	})
	if !ok || e.sk.notifier == nil {
		return
	}
	drill := false
	if alerts, err := e.sk.st.GetIncidentAlerts(ctx, inc.ID); err == nil {
		drill = isDrill(alerts)
	}
	_ = sink.OnAnnotation(ctx, notify.AnnotationEvent{
		IncidentID: inc.ID, GroupKey: inc.GroupKey, Kind: kind, Note: note,
		VerdictVersion: verdictVersion, Drill: drill,
	})
}

// maxWidenQueries bounds one capture call's live widening fetches (D10).
const maxWidenQueries = 10

// gradeDeadline bounds the grade phase (two live LLM calls); on expiry the
// capture is already persisted and the response reports replay_failed (D9).
const gradeDeadline = 3 * time.Minute

type CaptureRequest struct {
	IncidentID    string
	Verdict       string // correction | confirmation
	Expectation   json.RawMessage
	Note          string
	WidenQueries  []string
	CauseCategory string
}

type CaptureResult struct {
	VerdictID      int64
	Version        int
	Grade          string // "green" | "red" | "" when replay failed
	Layer          string // "evidence_selection" | "synthesis" | ""
	ReplayFidelity string // "" when stage 2 did not run
	ReplayFailed   bool
	Warnings       []string
}

// CaptureVerdict is the single-call capture (D7): persist phase (verdict
// version + annotation + demotion + audit + widening) strictly before the
// grade phase (D9). A repeat call with an unchanged expectation and no new
// widen queries skips persist/widen and re-grades.
func (e *CaptureEngine) CaptureVerdict(ctx context.Context, req CaptureRequest) (*CaptureResult, error) {
	if req.Verdict != "correction" && req.Verdict != "confirmation" {
		return nil, fmt.Errorf("acutetriage: capture: verdict %q not in {correction, confirmation}", req.Verdict)
	}
	exp, err := parseExpectation(req.Expectation)
	if err != nil {
		return nil, err
	}
	if len(req.WidenQueries) > maxWidenQueries {
		return nil, fmt.Errorf("acutetriage: capture: %d widen_queries exceeds the cap of %d", len(req.WidenQueries), maxWidenQueries)
	}
	release, err := e.enter()
	if err != nil {
		return nil, err
	}
	defer release()
	inc, err := e.sk.st.GetIncidentByID(ctx, req.IncidentID)
	if err != nil {
		return nil, fmt.Errorf("acutetriage: capture: load incident: %w", err)
	}
	if inc == nil {
		return nil, fmt.Errorf("acutetriage: capture: incident %q not found", req.IncidentID)
	}
	if inc.OutputJSON == "" {
		return nil, fmt.Errorf("acutetriage: capture: incident %q has no finding to grade — use alertint_incident_annotate instead", req.IncidentID)
	}

	expJSON := canonicalExpectationJSON(exp)
	latest, err := e.sk.st.LatestIncidentVerdict(ctx, req.IncidentID)
	if err != nil {
		return nil, fmt.Errorf("acutetriage: capture: latest verdict: %w", err)
	}
	priorWidened := decodeWidened(latest) // []VerificationQuery, nil-safe
	newExprs := exprsNotIn(req.WidenQueries, priorWidened)

	var warnings []string
	verdictRow := latest
	needsPersist := latest == nil || latest.ExpectationJSON != expJSON || latest.Verdict != req.Verdict || len(newExprs) > 0
	if needsPersist {
		v, persistWarnings, err := e.persistCapture(ctx, req, exp, expJSON, inc, priorWidened, newExprs)
		if err != nil {
			return nil, err
		}
		verdictRow = v
		warnings = append(warnings, persistWarnings...)
	}

	frozen := decodeFrozenEnvelope(inc.EnrichmentJSON)
	warnings = append(warnings, lintExpectationVerifiable(req.Verdict, exp, frozen, decodeWidened(verdictRow))...)

	res := &CaptureResult{VerdictID: verdictRow.ID, Version: verdictRow.Version, Warnings: warnings}
	gctx, cancel, err := e.gradeContext(ctx)
	if err != nil {
		// Close began during the persist phase: the verdict is persisted;
		// only the grade is refused.
		res.ReplayFailed = true
		res.Warnings = append(res.Warnings, "replay skipped: agent shutting down — verdict captured intact")
		return res, nil
	}
	defer cancel()
	e.grade(gctx, inc, exp, verdictRow, res)
	return res, nil
}

// persistCapture runs the persist phase (D7/D9): widen the not-yet-frozen
// exprs live once, merge with what's already frozen, write the verdict +
// annotation + demotion atomically, audit, and fan out the annotation event.
func (e *CaptureEngine) persistCapture(ctx context.Context, req CaptureRequest, exp Expectation, expJSON string,
	inc *store.Incident, priorWidened []VerificationQuery, newExprs []string,
) (*store.IncidentVerdict, []string, error) {
	fetched, warnings := e.widen(ctx, req.IncidentID, newExprs)
	merged := make([]VerificationQuery, 0, len(priorWidened)+len(fetched))
	merged = append(merged, priorWidened...)
	merged = append(merged, fetched...)
	widenedJSON := ""
	if len(merged) > 0 {
		b, err := json.Marshal(merged)
		if err != nil {
			return nil, nil, fmt.Errorf("acutetriage: capture: marshal widened: %w", err)
		}
		widenedJSON = string(b)
	}
	note := req.Note
	if note == "" {
		note = synthesizeNote(req.Verdict, exp)
	}
	demote := 0
	if req.Verdict == "correction" {
		demote = demotionThreshold
	}
	v, _, err := e.sk.st.PersistVerdictCapture(ctx, store.VerdictCapture{
		IncidentID: req.IncidentID, Verdict: req.Verdict,
		Source: store.VerdictSourceHuman, LabelConfidence: 1,
		ExpectationJSON: expJSON, WidenedJSON: widenedJSON,
		CauseCategory: req.CauseCategory, AnnotationNote: note,
		DemoteMarksFloor: demote,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("acutetriage: capture: persist: %w", err)
	}
	if e.sk.auditor != nil {
		if err := e.sk.auditor.Append(ctx, captureActor, "incident.verdict_captured", map[string]any{
			"incident_id": req.IncidentID, "verdict": req.Verdict, "version": v.Version,
			"cause_category": req.CauseCategory, "widened_count": len(fetched), "note": note,
		}); err != nil {
			return nil, nil, fmt.Errorf("acutetriage: capture: audit: %w", err)
		}
	}
	e.notifyAnnotation(ctx, inc, req.Verdict, note, v.Version)
	return v, warnings, nil
}

// grade runs the two-stage advisory grade (D8). It only ever writes into res
// — a grading failure cannot touch the already-persisted capture (D9).
func (e *CaptureEngine) grade(ctx context.Context, inc *store.Incident, exp Expectation, verdictRow *store.IncidentVerdict, res *CaptureResult) {
	frozen := decodeFrozenEnvelope(inc.EnrichmentJSON)
	alerts, err := e.sk.st.GetIncidentAlerts(ctx, inc.ID)
	if err != nil || len(alerts) == 0 {
		res.ReplayFailed = true
		res.Warnings = append(res.Warnings, "replay failed: could not load member alerts — verdict captured intact")
		return
	}

	// Stage 1 — deterministic expectation diff against the pack current rules
	// assemble. Absent discriminating evidence → red, evidence-selection, no
	// LLM call (a synthesis green over absent evidence would be
	// right-for-the-wrong-reason).
	d := diffExpectationAgainstPack(exp, e.sk.stage1Corpus(*inc, alerts, frozen))
	if len(d.MissingSeries) > 0 || len(d.MissingSubjects) > 0 {
		res.Grade = "red"
		res.Layer = "evidence_selection"
		for _, m := range d.MissingSeries {
			res.Warnings = append(res.Warnings, fmt.Sprintf("series %q is not in the evidence pack current rules assemble — the fix is a rule/check, not a prompt", m))
		}
		for _, m := range d.MissingSubjects {
			res.Warnings = append(res.Warnings, fmt.Sprintf("subject %q appears nowhere in the assembled evidence", m))
		}
		return
	}

	// Stage 2 — full-pipeline hermetic replay (current rules + prompts + live
	// LLM over frozen data, widened series servable).
	var frozenQueries []VerificationQuery
	if frozen.Verification != nil {
		for _, r := range frozen.Verification.Rounds {
			frozenQueries = append(frozenQueries, r.Queries...)
		}
	}
	frozenQueries = append(frozenQueries, decodeWidened(verdictRow)...)
	rep, err := e.sk.replayIncidentWith(ctx, *inc, alerts, frozen, frozenQueries)
	if err != nil {
		e.sk.logger.Warn("acutetriage: capture: replay failed; verdict captured intact",
			"incident", inc.ID, "err", err)
		res.ReplayFailed = true
		res.Warnings = append(res.Warnings, "replay failed — verdict captured intact")
		return
	}
	res.ReplayFidelity = rep.fidelity

	missing, bad, warns := diffExpectationAgainstFinding(exp, rep.resp)
	res.Warnings = append(res.Warnings, warns...)
	if len(missing) == 0 && len(bad) == 0 {
		res.Grade = "green"
		return
	}
	res.Grade = "red"
	res.Layer = "synthesis"
	for _, m := range missing {
		res.Warnings = append(res.Warnings, fmt.Sprintf("replayed finding does not mention %q", m))
	}
	for _, b := range bad {
		res.Warnings = append(res.Warnings, fmt.Sprintf("replayed finding still concludes %q", b))
	}
}

// widen runs the not-yet-frozen widen queries live, exactly once, freezing
// each as a VerificationQuery with source "capture" (D10). A failed fetch
// degrades the capture with a warning — never aborts the persist phase.
// The whole phase shares ONE QueryTimeoutSeconds-sized budget, sliced evenly
// across exprs (mirrors runVerificationWith's two-layer budget) — without
// this, up to maxWidenQueries sequential per-query timeouts could each run
// the full QueryTimeoutSeconds, reintroducing the unbounded-phase-latency
// class of bug already fixed once for the main verification path.
func (e *CaptureEngine) widen(ctx context.Context, incidentID string, exprs []string) ([]VerificationQuery, []string) {
	if len(exprs) == 0 {
		return nil, nil
	}
	budget := time.Duration(e.sk.cfg.Verification.QueryTimeoutSeconds) * time.Second
	if budget <= 0 {
		budget = 10 * time.Second
	}
	phaseCtx, phaseCancel := context.WithTimeout(ctx, budget)
	defer phaseCancel()
	perQuery := budget / time.Duration(len(exprs))
	maxSeries := e.sk.cfg.Verification.MaxSeries
	now := time.Now().UTC()
	prom := e.sk.promQuerier()
	var out []VerificationQuery
	var warnings []string
	for _, expr := range exprs {
		q := VerificationQuery{Kind: kindPromQL, Source: sourceCapture, Expr: expr,
			Why: "widened at capture"}
		qCtx, cancel := context.WithTimeout(phaseCtx, perQuery)
		runPromQL(qCtx, prom, &q, maxSeries, now, e.sk.logger, incidentID)
		cancel()
		if q.Outcome == OutcomeFailed || q.Outcome == OutcomeDegraded || q.Outcome == OutcomeInvalid {
			warnings = append(warnings, fmt.Sprintf("widening fetch failed for %q (%s) — capture degraded, verdict persisted", expr, q.Outcome))
		}
		out = append(out, q)
	}
	return out, warnings
}

// decodeWidened defensively decodes a verdict row's widened_json.
func decodeWidened(v *store.IncidentVerdict) []VerificationQuery {
	if v == nil || v.WidenedJSON == "" {
		return nil
	}
	var out []VerificationQuery
	_ = json.Unmarshal([]byte(v.WidenedJSON), &out)
	return out
}

// exprsNotIn returns the widen exprs not already frozen (dedup by Expr).
func exprsNotIn(exprs []string, frozen []VerificationQuery) []string {
	seen := make(map[string]bool, len(frozen))
	for _, q := range frozen {
		seen[q.Expr] = true
	}
	var out []string
	for _, e := range exprs {
		if e != "" && !seen[e] {
			seen[e] = true
			out = append(out, e)
		}
	}
	return out
}
