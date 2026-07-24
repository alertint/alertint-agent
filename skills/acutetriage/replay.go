// SPDX-License-Identifier: FSL-1.1-ALv2

// Hermetic replay (spec D8 stage 2): re-run the CURRENT triage pipeline —
// same skill entry, current rules and prompts, live LLM — over an incident's
// FROZEN inputs. No live data-source call is ever made: verification queries
// are served from the frozen snapshot (original round results + widened
// series), enrichment sections come from the persisted envelope. Nothing is
// persisted, notified, or bookkept — the would-be finding is returned for
// grading only.
package acutetriage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/alertint/alertint-agent/internal/store"
)

type replayRun struct {
	frozen frozenEnvelope
	exec   *snapshotExecutor
	out    replayOutcome
}

type replayOutcome struct {
	raw      json.RawMessage
	resp     llmResponse
	captured bool
}

// ReplayReport is what grading consumes: the replayed finding + fidelity.
type ReplayReport struct {
	resp     llmResponse
	raw      json.RawMessage
	fidelity string
}

// replayIncident runs the hermetic replay. It operates on a copy of the Skill
// with auditor and notifier stripped, so the pipeline's own nil-guards
// suppress incident audit rows and notifications (the LLM client's internal
// llm.request/llm.response audit rows still fire — an honest record of
// grading spend).
func (s *Skill) replayIncident(ctx context.Context, inc store.Incident) (*ReplayReport, error) {
	if inc.OutputJSON == "" {
		return nil, fmt.Errorf("acutetriage: replay: incident %q has no finding", inc.ID)
	}
	alerts, err := s.st.GetIncidentAlerts(ctx, inc.ID)
	if err != nil {
		return nil, fmt.Errorf("acutetriage: replay: load alerts: %w", err)
	}
	if len(alerts) == 0 {
		return nil, fmt.Errorf("acutetriage: replay: incident %q has no member alerts", inc.ID)
	}

	frozen := decodeFrozenEnvelope(inc.EnrichmentJSON)
	var frozenQueries []VerificationQuery
	if frozen.Verification != nil {
		for _, r := range frozen.Verification.Rounds {
			frozenQueries = append(frozenQueries, r.Queries...)
		}
	}
	// Widened entries (source "capture") are appended by the caller via
	// replayIncidentWith; the plain entry replays the envelope only.
	return s.replayIncidentWith(ctx, inc, alerts, frozen, frozenQueries)
}

// replayIncidentWith lets capture add widened entries to the servable set.
func (s *Skill) replayIncidentWith(ctx context.Context, inc store.Incident, alerts []store.Alert,
	frozen frozenEnvelope, frozenQueries []VerificationQuery,
) (*ReplayReport, error) {
	run := &replayRun{frozen: frozen, exec: newSnapshotExecutor(frozenQueries)}

	rs := *s // shallow copy: same store/llm/cfg, side effects stripped
	rs.auditor = nil
	rs.notifier = nil

	persist := func(ctx context.Context, incidentID, outputJSON, summary, rootCause string, confidence float64, enrichmentJSON string) error {
		var resp llmResponse
		if err := json.Unmarshal([]byte(outputJSON), &resp); err != nil {
			return fmt.Errorf("acutetriage: replay: parse replayed finding: %w", err)
		}
		resp.Confidence = confidence // the capped value, as production persists it
		run.out = replayOutcome{raw: json.RawMessage(outputJSON), resp: resp, captured: true}
		return nil
	}

	if err := rs.pipeline(ctx, inc, alerts, pipelineParams{
		spanStart: inc.FirstAlertAt,
		persist:   persist,
		replay:    run,
	}); err != nil {
		return nil, err
	}
	if !run.out.captured {
		return nil, errors.New("acutetriage: replay: pipeline produced no finding")
	}
	return &ReplayReport{resp: run.out.resp, raw: run.out.raw, fidelity: run.exec.fidelity()}, nil
}
