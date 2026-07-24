// SPDX-License-Identifier: FSL-1.1-ALv2

// Capture: the feedback & verdict write-back engine (ADR-0027/0028). All
// writes land in AlertINT's own SQLite + audit chain — never in operator
// infrastructure. MCP handlers validate transport args and delegate here.
package acutetriage

import (
	"context"
	"errors"
	"fmt"

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
