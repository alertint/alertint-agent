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
	"time"

	"github.com/alertint/alertint-agent/internal/notify"
	"github.com/alertint/alertint-agent/internal/store"
)

// captureActor is the audit actor for operator write-backs over MCP.
const captureActor = "mcp"

// CaptureEngine wraps the triage Skill: the persist phase uses its store /
// auditor / notifier; the grade phase replays through its pipeline config
// ("current triage").
type CaptureEngine struct {
	sk *Skill
}

func NewCaptureEngine(sk *Skill) *CaptureEngine { return &CaptureEngine{sk: sk} }

type AnnotateRequest struct {
	IncidentID string
	Kind       string // correction | observation
	Note       string
}

type AnnotateResult struct {
	AnnotationID int64
	Demoted      bool
}

// Annotate stores a kind+note annotation, demotes the finding from strong
// recall iff correction (D3), audits, and fans out the annotation event
// (Slack thread reply + stdout line). The finding row is never touched.
func (e *CaptureEngine) Annotate(ctx context.Context, req AnnotateRequest) (*AnnotateResult, error) {
	if req.Kind != "correction" && req.Kind != "observation" {
		return nil, fmt.Errorf("acutetriage: annotate: kind %q not in {correction, observation} (confirmation is written by capture only)", req.Kind)
	}
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
	demoted := false
	if req.Kind == "correction" {
		if err := e.sk.st.SetRefuteMarksFloor(ctx, req.IncidentID, demotionThreshold); err != nil {
			e.sk.logger.Warn("acutetriage: annotate: demotion failed (recall still demotes structurally)",
				"incident", req.IncidentID, "err", err)
		} else {
			demoted = true
		}
	}
	if e.sk.auditor != nil {
		if err := e.sk.auditor.Append(ctx, captureActor, "incident.annotated", map[string]any{
			"incident_id": req.IncidentID, "kind": req.Kind, "note": req.Note,
		}); err != nil {
			return nil, fmt.Errorf("acutetriage: annotate: audit: %w", err)
		}
	}
	e.notifyAnnotation(ctx, inc, req.Kind, req.Note, 0)
	return &AnnotateResult{AnnotationID: ann.ID, Demoted: demoted}, nil
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
	if latest == nil || latest.ExpectationJSON != expJSON || latest.Verdict != req.Verdict || len(newExprs) > 0 {
		// Widen: live, once, only the exprs not already frozen (D9/D10).
		fetched, wideWarns := e.widen(ctx, req.IncidentID, newExprs)
		warnings = append(warnings, wideWarns...)
		merged := append(priorWidened, fetched...)
		widenedJSON := ""
		if len(merged) > 0 {
			b, err := json.Marshal(merged)
			if err != nil {
				return nil, fmt.Errorf("acutetriage: capture: marshal widened: %w", err)
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
			ExpectationJSON: expJSON, WidenedJSON: widenedJSON,
			CauseCategory: req.CauseCategory, AnnotationNote: note,
			DemoteMarksFloor: demote,
		})
		if err != nil {
			return nil, fmt.Errorf("acutetriage: capture: persist: %w", err)
		}
		verdictRow = v
		if e.sk.auditor != nil {
			if err := e.sk.auditor.Append(ctx, captureActor, "incident.verdict_captured", map[string]any{
				"incident_id": req.IncidentID, "verdict": req.Verdict, "version": v.Version,
				"cause_category": req.CauseCategory, "widened_count": len(fetched), "note": note,
			}); err != nil {
				return nil, fmt.Errorf("acutetriage: capture: audit: %w", err)
			}
		}
		e.notifyAnnotation(ctx, inc, req.Verdict, note, v.Version)
	}

	frozen := decodeFrozenEnvelope(inc.EnrichmentJSON)
	warnings = append(warnings, lintExpectationVerifiable(exp, frozen, decodeWidened(verdictRow))...)

	res := &CaptureResult{VerdictID: verdictRow.ID, Version: verdictRow.Version, Warnings: warnings}
	res.ReplayFailed = true // grade phase lands in the next task
	return res, nil
}

// widen runs the not-yet-frozen widen queries live, exactly once, freezing
// each as a VerificationQuery with source "capture" (D10). A failed fetch
// degrades the capture with a warning — never aborts the persist phase.
func (e *CaptureEngine) widen(ctx context.Context, incidentID string, exprs []string) ([]VerificationQuery, []string) {
	if len(exprs) == 0 {
		return nil, nil
	}
	perQuery := time.Duration(e.sk.cfg.Verification.QueryTimeoutSeconds) * time.Second
	if perQuery <= 0 {
		perQuery = 10 * time.Second
	}
	maxSeries := e.sk.cfg.Verification.MaxSeries
	now := time.Now().UTC()
	prom := e.sk.promQuerier()
	var out []VerificationQuery
	var warnings []string
	for _, expr := range exprs {
		q := VerificationQuery{Kind: kindPromQL, Source: sourceCapture, Expr: expr,
			Why: "widened at capture"}
		qCtx, cancel := context.WithTimeout(ctx, perQuery)
		runPromQL(qCtx, prom, &q, maxSeries, now, e.sk.logger, incidentID)
		cancel()
		if q.Outcome == OutcomeFailed || q.Outcome == OutcomeDegraded {
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
