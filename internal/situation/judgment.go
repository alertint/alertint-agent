// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/situation/model"
)

// ValidateJudgmentRequest checks a confirmed operator write before any
// Situation-specific coverage is attached. Free text cannot steer: only the
// closed Judgment/Basis enums and an asserted, non-blank confirming operator
// carry authority.
func ValidateJudgmentRequest(req model.JudgmentRequest) error {
	if !req.OperatorConfirmed {
		return errors.New("situation: judgment requires explicit operator confirmation")
	}
	if strings.TrimSpace(req.ConfirmedBy) == "" {
		return errors.New("situation: judgment requires an asserted confirming operator")
	}
	if strings.TrimSpace(req.Situation) == "" {
		return errors.New("situation: judgment requires a target situation")
	}
	switch req.Judgment {
	case model.JudgmentExpectedThisEpisode, model.JudgmentUnexpected, model.JudgmentInconclusive:
	default:
		return fmt.Errorf("situation: judgment kind %q is invalid", req.Judgment)
	}
	switch req.Basis {
	case model.JudgmentBasisOperatorKnowledge, model.JudgmentBasisAlertintEvidence:
	default:
		return fmt.Errorf("situation: judgment basis %q is invalid", req.Basis)
	}
	if req.ValidUntil != nil && req.ValidUntil.IsZero() {
		return errors.New("situation: judgment valid_until must be a real instant when present")
	}
	return nil
}

// symptomCoverageIdentity is the exact structural identity a Judgment binds
// to for one currently active symptom: the stable symptom id, and — when
// present — its trigger version, so a trigger/template change on an
// otherwise-unchanged symptom id is its own distinct coverage entry rather
// than silently reusing prior coverage.
func symptomCoverageIdentity(s Symptom) string {
	if s.TriggerVersion == "" {
		return s.ID
	}
	return s.ID + "@" + s.TriggerVersion
}

// activeSymptomCoverage returns the exact coverage identities for every
// currently firing symptom in snap.
func activeSymptomCoverage(snap Snapshot) []string {
	out := make([]string, 0, len(snap.Symptoms))
	for _, s := range snap.Symptoms {
		if s.Lifecycle == model.DeliveryStatusFiring {
			out = append(out, symptomCoverageIdentity(s))
		}
	}
	return canonicalStrings(out)
}

// confirmedImpactCoverage returns the exact coverage identities for every
// currently confirmed impact in snap.
func confirmedImpactCoverage(snap Snapshot) []string {
	out := make([]string, 0, len(snap.Impact))
	for _, i := range snap.Impact {
		if i.Confirmed {
			out = append(out, i.Kind)
		}
	}
	return canonicalStrings(out)
}

// BuildJudgment stamps a confirmed request with snap's exact input version,
// material fact hash, and currently active symptom/impact coverage. The
// resulting Judgment grants no authority beyond this exact structural
// coverage: a broader or narrower Situation view is never silently assumed
// covered by it.
func BuildJudgment(id string, snap Snapshot, req model.JudgmentRequest, authenticatedAs string, now time.Time) (model.Judgment, error) {
	if err := ValidateJudgmentRequest(req); err != nil {
		return model.Judgment{}, err
	}
	if strings.TrimSpace(id) == "" {
		return model.Judgment{}, errors.New("situation: judgment requires an id")
	}
	if strings.TrimSpace(snap.SituationID) == "" || snap.InputVersion < 1 || strings.TrimSpace(snap.MaterialHash) == "" {
		return model.Judgment{}, errors.New("situation: judgment requires a built snapshot")
	}
	if strings.TrimSpace(authenticatedAs) == "" {
		return model.Judgment{}, errors.New("situation: judgment requires an authenticated trust domain")
	}
	if now.IsZero() {
		return model.Judgment{}, errors.New("situation: judgment requires a recording instant")
	}
	j := model.Judgment{
		ID: id, SituationID: snap.SituationID, JudgedInputVersion: snap.InputVersion, CoveredFactHash: snap.MaterialHash,
		CoveredSymptoms: activeSymptomCoverage(snap), CoveredImpact: confirmedImpactCoverage(snap),
		Judgment: req.Judgment, Basis: req.Basis, EvidenceRefs: []string{},
		AuthenticatedAs: authenticatedAs, AssertedOperator: strings.TrimSpace(req.ConfirmedBy), CreatedAt: now.UTC(),
	}
	if req.Workload != nil {
		workload := strings.TrimSpace(*req.Workload)
		j.Workload = &workload
	}
	if req.ValidUntil != nil {
		validUntil := req.ValidUntil.UTC()
		j.ValidUntil = &validUntil
	}
	return j, nil
}

// JudgmentSupersessionReason names why a previously recorded Judgment no
// longer covers a later Snapshot.
type JudgmentSupersessionReason string

const (
	// JudgmentStillApplicable means j continues to cover snap.
	JudgmentStillApplicable JudgmentSupersessionReason = ""
	// JudgmentSupersessionExpired means now has reached or passed j.ValidUntil.
	JudgmentSupersessionExpired JudgmentSupersessionReason = "expired"
	// JudgmentSupersessionOutOfScope means snap now carries an active symptom
	// or confirmed impact identity — including one produced purely by a
	// trigger-version change — outside j's recorded coverage.
	JudgmentSupersessionOutOfScope JudgmentSupersessionReason = "out_of_scope_fact"
)

// JudgmentApplicable reports whether j still covers snap. Expiry (now at or
// past ValidUntil) and any active symptom, confirmed impact, or trigger
// version outside j's recorded coverage supersede it. A later receipt
// timestamp alone never does: Situations replay normalized facts, not
// wall-clock arrival order, and MaterialFactHash already excludes receipt
// timing and presentation state from what "material" means.
func JudgmentApplicable(snap Snapshot, j model.Judgment, now time.Time) (bool, JudgmentSupersessionReason) {
	if j.ValidUntil != nil && !now.UTC().Before(j.ValidUntil.UTC()) {
		return false, JudgmentSupersessionExpired
	}
	covered := stringSet(j.CoveredSymptoms)
	for _, id := range activeSymptomCoverage(snap) {
		if !has(covered, id) {
			return false, JudgmentSupersessionOutOfScope
		}
	}
	coveredImpact := stringSet(j.CoveredImpact)
	for _, kind := range confirmedImpactCoverage(snap) {
		if !has(coveredImpact, kind) {
			return false, JudgmentSupersessionOutOfScope
		}
	}
	return true, JudgmentStillApplicable
}
