// SPDX-License-Identifier: FSL-1.1-ALv2

package correlator

import (
	"context"
	"fmt"

	"github.com/alertint/alertint-agent/internal/store"
)

// maybeAttachRetryingIncident implements R4: a firing Alert with no
// collecting Incident may join the newest same-group Incident that is
// durably retrying (ready + backoff, non-exhausted) instead of collapsing
// into a recurrence or minting a new Incident. An unjudged Incident stays
// collected until its first judgment (CONTEXT.md: Incident), so this adds
// membership only — no Occurrence, no recurrence notification — and never
// touches the triage schedule (R6: no retry acceleration). Store lookup
// errors fail safe to the existing new-Incident path.
func (c *Correlator) maybeAttachRetryingIncident(ctx context.Context, a store.Alert, groupKey string) (bool, error) {
	candidate, tri, err := c.st.GetBackoffIncidentByGroupKey(ctx, groupKey)
	if err == store.ErrNotFound {
		return false, nil
	}
	if err != nil {
		c.logger.Warn("correlator: backoff-incident lookup failed; treating as new incident", "err", err, "group_key", groupKey)
		return false, nil
	}

	// Load members once: they carry the candidate's Drill-ness, mirroring the
	// occurrence-attach invariant (no cross-Drill attach), and let us tell a
	// genuinely new member from an idempotent re-fire of an existing one
	// without a second query.
	members, err := c.st.GetIncidentAlerts(ctx, candidate.ID)
	if err != nil {
		c.logger.Warn("correlator: member lookup failed; treating as new incident", "err", err, "incident_id", candidate.ID)
		return false, nil
	}
	candidateDrill := false
	alreadyMember := false
	for _, m := range members {
		if store.IsDrillAlert(m) {
			candidateDrill = true
		}
		if m.Fingerprint == a.Fingerprint {
			alreadyMember = true
		}
	}
	if store.IsDrillAlert(a) != candidateDrill {
		return false, nil
	}

	if err := c.st.AddAlertToIncident(ctx, candidate.ID, a.ID, a.ReceivedAt); err != nil {
		return false, fmt.Errorf("correlator: attach retrying incident: %w", err)
	}

	if alreadyMember {
		// An idempotent re-fire of an already-attached fingerprint: no new
		// membership, so nothing meaningful happened — no log, no audit,
		// mirroring the occurrence-attach "repeat" short-circuit in attach.go.
		return true, nil
	}

	memberCount := len(members) + 1
	c.logger.Info("correlator: alert attached during triage backoff",
		"incident_id", candidate.ID, "group_key", groupKey, "alert_id", a.ID, "next_at", tri.NextAt, "member_count", memberCount)
	if c.auditor != nil {
		if err := c.auditor.Append(ctx, "correlator", "incident.triage_member_attached", map[string]any{
			"incident_id":  candidate.ID,
			"group_key":    groupKey,
			"alert_id":     a.ID,
			"member_count": memberCount,
		}); err != nil {
			c.logger.Warn("correlator: audit triage_member_attached failed", "err", err, "incident_id", candidate.ID)
		}
	}
	return true, nil
}
