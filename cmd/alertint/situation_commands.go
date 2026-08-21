// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	internalmcp "github.com/alertint/alertint-agent/internal/mcp"
	"github.com/alertint/alertint-agent/internal/semanticprofile"
	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// mcpTrustDomain is AlertINT's one MCP trust domain. Every Situation write
// records it as `authenticated_as` alongside the caller-asserted operator:
// the token proves the connection, the operator name is an assertion.
const mcpTrustDomain = "installation_mcp_token"

// situationCommands is the concrete confirmed-write surface behind the
// Situation MCP tools. Every write is additive local AlertINT state; nothing
// here can reach an operated system.
//
// It re-validates confirmation and attribution below the MCP handlers on
// purpose. The handlers check them too, but a command surface that trusts its
// caller to have checked is one refactor away from an unconfirmed write, and
// the store's audit row would then carry an empty operator.
type situationCommands struct {
	runtime  *store.SituationRuntime
	profiles *semanticprofile.Service
	auditor  *audit.Auditor
	clock    func() time.Time
	wake     func()
}

var _ internalmcp.SituationCommands = (*situationCommands)(nil)

func newSituationCommands(runtime *store.SituationRuntime, profiles *semanticprofile.Service, auditor *audit.Auditor, clock func() time.Time, wake func()) *situationCommands {
	if clock == nil {
		clock = func() time.Time { return time.Now().UTC() }
	}
	if wake == nil {
		wake = func() {}
	}
	return &situationCommands{runtime: runtime, profiles: profiles, auditor: auditor, clock: clock, wake: wake}
}

// Reassess schedules one elevated manual_reassessment attempt. It coalesces:
// repeated requests before the reassessment runs union into the same due
// reason rather than queueing extra work, and it cannot bypass scope,
// concurrency, safety floors, connector allowlists, or budgets — the
// controller still applies every one of those on the next pass.
func (c *situationCommands) Reassess(ctx context.Context, target string) error {
	sit, err := c.runtime.Store().GetSituation(ctx, target)
	if err != nil {
		return err
	}
	if sit.Lifecycle == model.LifecycleRecovered || sit.Lifecycle == model.LifecycleClosedUnknown {
		return errors.New("alertint: a terminal situation never reopens")
	}
	now := c.clock().UTC()
	if err := c.runtime.MarkDue(ctx, sit.ID, model.DueManualReassessment, now); err != nil {
		return err
	}
	c.audit(ctx, "situation.reassess_requested", map[string]any{
		"situation_id": sit.ID, "authenticated_as": mcpTrustDomain,
	})
	c.wake()
	return nil
}

// RecordJudgment stamps the operator's judgment onto the exact input/fact
// view they judged. The snapshot is rebuilt from durable state so a judgment
// can never be recorded against a view that no longer exists.
func (c *situationCommands) RecordJudgment(ctx context.Context, req model.JudgmentRequest) (*model.Judgment, error) {
	if err := requireConfirmedWrite(req.OperatorConfirmed, req.ConfirmedBy); err != nil {
		return nil, err
	}
	if err := situation.ValidateJudgmentRequest(req); err != nil {
		return nil, err
	}
	snap, err := c.snapshotFor(ctx, req.Situation)
	if err != nil {
		return nil, err
	}
	now := c.clock().UTC()
	events := []store.SituationPolicyAuditEvent{{
		Kind: "situation.judgment_recorded",
		Payload: map[string]any{
			"situation_id": snap.SituationID, "input_version": snap.InputVersion,
			"judgment": string(req.Judgment), "basis": string(req.Basis),
			"authenticated_as": mcpTrustDomain, "asserted_operator": req.ConfirmedBy,
		},
	}}
	j, err := c.runtime.Store().RecordJudgment(ctx, snap, req, mcpTrustDomain, now, c.auditor, events)
	if err != nil {
		return nil, err
	}
	c.wake()
	return j, nil
}

// ConfirmEnvelope promotes a recorded judgment into a reusable expected
// behaviour envelope.
func (c *situationCommands) ConfirmEnvelope(ctx context.Context, confirmation model.EnvelopeConfirmation) (*model.EnvelopeVersion, error) {
	if err := requireConfirmedWrite(confirmation.OperatorConfirmed, confirmation.ConfirmedBy); err != nil {
		return nil, err
	}
	now := c.clock().UTC()
	events := []store.SituationPolicyAuditEvent{{
		Kind: "expected_behavior.confirmed",
		Payload: map[string]any{
			"source_judgment_id": confirmation.SourceJudgmentID,
			"group_key":          confirmation.Scope.GroupKey,
			"authenticated_as":   mcpTrustDomain, "asserted_operator": confirmation.ConfirmedBy,
		},
	}}
	v, err := c.runtime.Store().ConfirmEnvelope(ctx, confirmation, mcpTrustDomain, now, c.auditor, events)
	if err != nil {
		return nil, err
	}
	c.wake()
	return v, nil
}

// RevokeEnvelope appends a revoked version; it never mutates history.
func (c *situationCommands) RevokeEnvelope(ctx context.Context, revocation model.EnvelopeRevocation) (*model.EnvelopeVersion, error) {
	if err := requireConfirmedWrite(revocation.OperatorConfirmed, revocation.ConfirmedBy); err != nil {
		return nil, err
	}
	now := c.clock().UTC()
	events := []store.SituationPolicyAuditEvent{{
		Kind: "expected_behavior.revoked",
		Payload: map[string]any{
			"envelope_id": revocation.EnvelopeID, "reason": revocation.Reason,
			"authenticated_as": mcpTrustDomain, "asserted_operator": revocation.ConfirmedBy,
		},
	}}
	v, err := c.runtime.Store().RevokeEnvelope(ctx, revocation, mcpTrustDomain, now, c.auditor, events)
	if err != nil {
		return nil, err
	}
	c.wake()
	return v, nil
}

// CorrectSemanticProfile appends an operator-confirmed advisory profile
// version. Profiles only ever widen evidence consideration; a correction
// carries no controller authority.
func (c *situationCommands) CorrectSemanticProfile(ctx context.Context, correction semanticprofile.Correction) (*profilemodel.ProfileVersion, error) {
	if err := requireConfirmedWrite(correction.Confirmed, correction.ConfirmedBy); err != nil {
		return nil, err
	}
	if c.profiles == nil {
		return nil, errors.New("alertint: semantic profile service is unavailable")
	}
	return c.profiles.Correct(ctx, correction)
}

// snapshotFor rebuilds the exact deterministic snapshot a Situation write is
// judged against, from durable state only.
func (c *situationCommands) snapshotFor(ctx context.Context, target string) (situation.Snapshot, error) {
	sit, err := c.runtime.Store().GetSituation(ctx, target)
	if err != nil {
		return situation.Snapshot{}, err
	}
	claim := situation.Claim{Situation: sit}
	in, _, err := c.runtime.LoadReconciliationInput(ctx, claim)
	if err != nil {
		return situation.Snapshot{}, err
	}
	in.Now = c.clock().UTC()
	return situation.BuildSnapshot(in)
}

func (c *situationCommands) audit(ctx context.Context, kind string, payload map[string]any) {
	if c.auditor == nil {
		return
	}
	_ = c.auditor.Append(ctx, "situationcommands", kind, payload)
}

// requireConfirmedWrite is the defense-in-depth gate below the MCP handlers:
// no Situation write proceeds without explicit human confirmation and an
// asserted operator to attribute it to.
func requireConfirmedWrite(confirmed bool, confirmedBy string) error {
	if !confirmed {
		return fmt.Errorf("alertint: this write requires explicit operator confirmation")
	}
	if strings.TrimSpace(confirmedBy) == "" {
		return errors.New("alertint: this write requires an asserted operator identity")
	}
	return nil
}
