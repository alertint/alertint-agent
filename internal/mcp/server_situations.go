// SPDX-License-Identifier: FSL-1.1-ALv2

// The two read-only Situation views: alertint_list_situations (Task 3) and
// alertint_get_situation (Task 3, extended by Task 9). Both expose exactly
// the durable foundation and controller state Tasks 1-9 built — one
// Situation per exact group, its lifecycle/attention/scheduling fields, its
// immutable member Incidents, and (Task 9) the current authoritative
// Assessment/derivation, current Operator contract, material/basis hashes,
// up to 20 bounded sanitized recent Assessment attempts, per-Incident
// Triage decision/phase/attempts/due/digests, and controller retry/park
// state. Neither tool creates a judgment, note, verdict, envelope,
// Assessment, or reassessment request, and neither is reachable from any
// write path: no rejected free-form proposal text, raw prompt/response,
// provider error body, secret, SQL text, or unbounded fact history is ever
// returned. A Situation with no controller cycle run against it yet
// legitimately renders assessment/operator_contract/hashes as explicit JSON
// null and recent_attempts as an empty array — not an error, just "no
// controller state exists yet for this Situation." Both tools are always
// registered when MCP is enabled — unlike the source tools in server.go,
// there is no connector to gate them on.

package mcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	mcplib "github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

func (s *Server) toolListSituations() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_list_situations",
		mcplib.WithDescription("List durable Situations, most recently updated first. A Situation is "+
			"the exact-group lineage that durably owns one or more Incidents. This is a bounded summary — "+
			"lifecycle/attention/scheduling fields and due reasons only, no Assessment or controller "+
			"detail (use alertint_get_situation for that) and no Slack presence."),
		mcplib.WithInteger("limit",
			mcplib.Description("Maximum number of situations to return (1-100, default 20)."),
		),
	)
	return tool, s.handleListSituations
}

func (s *Server) toolGetSituation() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_get_situation",
		mcplib.WithDescription("Get one Situation by id or public handle: its immutable member Incidents "+
			"(with each one's current Triage decision/phase/attempts/due time/covered digests), current "+
			"authoritative Assessment and derivation, current Operator contract, material/Assessment-basis "+
			"hashes, up to 20 bounded sanitized recent Assessment attempts, and controller retry/park "+
			"state. assessment/operator_contract/hashes render as explicit null, and recent_attempts as "+
			"an empty array, for a Situation no controller cycle has run against yet. Never returns a "+
			"rejected proposal, raw prompt/response, provider error body, or SQL text."),
		mcplib.WithString("id",
			mcplib.Description("Situation ID (from alertint_list_situations). Exactly one of id/handle is required."),
		),
		mcplib.WithString("handle",
			mcplib.Description("Situation public handle. Exactly one of id/handle is required."),
		),
	)
	return tool, s.handleGetSituation
}

// situationListRow is one row of alertint_list_situations' output — the
// Situation's identity, lifecycle/attention/scheduling state, and due
// reasons, without its member Incidents (a per-row Incident fetch would
// turn a bounded list into an N+1 query; alertint_get_situation carries
// that detail instead).
type situationListRow struct {
	ID                  string                     `json:"id"`
	PreviousSituationID *string                    `json:"previous_situation_id"`
	PublicHandle        *string                    `json:"public_handle"`
	GroupKey            string                     `json:"group_key"`
	Lifecycle           string                     `json:"lifecycle"`
	Attention           string                     `json:"attention"`
	InputVersion        int                        `json:"input_version"`
	DueReasons          []situationmodel.DueReason `json:"due_reasons"`
	OpenedAt            time.Time                  `json:"opened_at"`
	EffectiveStartedAt  time.Time                  `json:"effective_started_at"`
	FirstReceivedAt     time.Time                  `json:"first_received_at"`
	NextAssessmentAt    time.Time                  `json:"next_assessment_at"`
}

func situationListRowFrom(sit situationmodel.Situation) situationListRow {
	return situationListRow{
		ID:                  sit.ID,
		PreviousSituationID: sit.PreviousSituationID,
		PublicHandle:        sit.PublicHandle,
		GroupKey:            sit.GroupKey,
		Lifecycle:           string(sit.Lifecycle),
		Attention:           string(sit.Attention),
		InputVersion:        sit.InputVersion,
		DueReasons:          sit.DueReasons,
		OpenedAt:            sit.OpenedAt,
		EffectiveStartedAt:  sit.EffectiveStartedAt,
		FirstReceivedAt:     sit.FirstReceivedAt,
		NextAssessmentAt:    sit.NextAssessmentAt,
	}
}

func (s *Server) handleListSituations(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	limit := mcplib.ParseInt(req, "limit", 20)
	if limit < 1 {
		limit = 20
	}

	sits, err := s.st.ListSituations(ctx, limit)
	if err != nil {
		return errResult("failed to list situations"), nil
	}

	rows := make([]situationListRow, 0, len(sits))
	for _, sit := range sits {
		rows = append(rows, situationListRowFrom(sit))
	}

	result, err := mcplib.NewToolResultJSON(map[string]any{"situations": rows})
	if err != nil {
		return errResult("failed to serialize situations: " + err.Error()), nil
	}
	return result, nil
}

// situationIncidentRow is one member Incident's identity, status, and
// bounded current Triage state — decision, phase, attempts, due time, and
// the covered digests the decision was made against (Task 9's MCP brief:
// "Incident Triage decision, phase, attempts, due time, and covered
// digests") — in attachment order. A caller wanting full Incident detail
// (Finding prose, alerts) follows up with alertint_get_incident.
type situationIncidentRow struct {
	ID                  string     `json:"id"`
	Status              string     `json:"status"`
	TriagePhase         string     `json:"triage_phase"`
	TriageDecision      *string    `json:"triage_decision"`
	TriageAttempts      int        `json:"triage_attempts"`
	TriageDueAt         *time.Time `json:"triage_due_at"`
	MembershipDigest    *string    `json:"membership_digest"`
	IncidentInputDigest *string    `json:"incident_input_digest"`
}

// sanitizedAssessmentAttemptRow is one bounded, sanitized entry in
// alertint_get_situation's "recent_attempts" array (Task 9's MCP brief:
// "bounded recent Assessment attempts with sanitized status/error codes") —
// the exact JSON-facing shape of store.SanitizedAssessmentAttempt. It never
// carries a raw proposal, validated content, or a provider response body —
// only the bounded typed identity/status/error-code columns
// GetSituationControllerView itself already sanitizes at the Store
// boundary.
type sanitizedAssessmentAttemptRow struct {
	ID                     string                                `json:"id"`
	Sequence               int                                   `json:"sequence"`
	InputVersion           int                                   `json:"input_version"`
	RetryEpoch             int                                   `json:"retry_epoch"`
	WorkAttempt            int                                   `json:"work_attempt"`
	Status                 string                                `json:"status"`
	Derivation             *situationmodel.AssessmentDerivation  `json:"derivation"`
	ProviderRequestStarted situationmodel.ProviderRequestStarted `json:"provider_request_started"`
	ValidationErrorCodes   []string                              `json:"validation_error_codes"`
	CreatedAt              time.Time                             `json:"created_at"`
	CompletedAt            time.Time                             `json:"completed_at"`
}

func sanitizedAssessmentAttemptRowFrom(a store.SanitizedAssessmentAttempt) sanitizedAssessmentAttemptRow {
	return sanitizedAssessmentAttemptRow{
		ID: a.ID, Sequence: a.Sequence, InputVersion: a.InputVersion, RetryEpoch: a.RetryEpoch,
		WorkAttempt: a.WorkAttempt, Status: a.Status, Derivation: a.Derivation,
		ProviderRequestStarted: a.ProviderRequestStarted, ValidationErrorCodes: a.ValidationErrorCodes,
		CreatedAt: a.CreatedAt, CompletedAt: a.CompletedAt,
	}
}

// controllerStateRow is alertint_get_situation's "controller_state" object —
// Task 9's MCP brief: "controller retry/park state" — read straight off
// store.ControllerRetryState.
type controllerStateRow struct {
	RetryEpoch     int        `json:"retry_epoch"`
	WorkAttempts   int        `json:"work_attempts"`
	ParkedAt       *time.Time `json:"parked_at"`
	ParkedReason   *string    `json:"parked_reason"`
	RetryAt        *time.Time `json:"retry_at"`
	LastErrorClass *string    `json:"last_error_class"`
}

func controllerStateRowFrom(r store.ControllerRetryState) controllerStateRow {
	return controllerStateRow{
		RetryEpoch: r.RetryEpoch, WorkAttempts: r.WorkAttempts, ParkedAt: r.ParkedAt,
		ParkedReason: r.ParkedReason, RetryAt: r.RetryAt, LastErrorClass: r.LastErrorClass,
	}
}

// handleGetSituation resolves a Situation by exactly one of id/handle and
// renders the exact response shape Step 1 of this task's plan specifies,
// including the two explicit nulls (assessment, operator_contract) that
// make the foundation honest: neither exists until a later plan builds the
// Situation controller and its operator surface. Every failure path returns
// a fixed, generic message — never a wrapped store/SQL error — so a lookup
// failure can never leak driver or query text to an MCP client.
func (s *Server) handleGetSituation(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	sit, failed := s.resolveSituation(ctx, req)
	if failed != nil {
		return failed, nil
	}

	members, err := s.st.ListSituationIncidents(ctx, sit.ID)
	if err != nil {
		return errResult("failed to get situation incidents"), nil
	}

	// view carries the bounded controller-derived state Task 9 adds:
	// current authoritative Assessment/derivation, current Operator
	// contract, material/basis hashes, the eligible reason candidate set,
	// up to 20 sanitized recent attempts, per-Incident Triage state, and
	// controller retry/park state. A
	// never-reconciled Situation (no controller cycle has run against it
	// yet) legitimately renders every one of these as null/empty — the
	// same "no controller state yet" honesty the original two explicit
	// nulls documented, now backed by real controller state once it exists.
	view, err := s.st.GetSituationControllerView(ctx, sit.ID)
	if err != nil {
		return errResult("failed to get situation controller state"), nil
	}

	triageByIncident := make(map[string]store.IncidentTriageView, len(view.Triage))
	for _, tv := range view.Triage {
		triageByIncident[tv.IncidentID] = tv
	}
	incidentRows := make([]situationIncidentRow, 0, len(members))
	for _, m := range members {
		row := situationIncidentRow{ID: m.IncidentID, Status: m.Status}
		if tv, ok := triageByIncident[m.IncidentID]; ok {
			row.TriagePhase = tv.Phase
			row.TriageDecision = tv.Decision
			row.TriageAttempts = tv.Attempts
			row.TriageDueAt = tv.NextAt
			row.MembershipDigest = tv.MembershipDigest
			row.IncidentInputDigest = tv.IncidentInputDigest
		}
		incidentRows = append(incidentRows, row)
	}

	attemptRows := make([]sanitizedAssessmentAttemptRow, 0, len(view.RecentAttempts))
	for _, a := range view.RecentAttempts {
		attemptRows = append(attemptRows, sanitizedAssessmentAttemptRowFrom(a))
	}

	// assessment, assessment_derivation, and operator_contract are plain map
	// entries (not struct fields with omitempty) precisely so a nil Go value
	// still renders as JSON null instead of being dropped — never a
	// rejected proposal, raw prompt/response, or provider error body (Task
	// 9's own MCP brief).
	payload := map[string]any{
		"id":                    sit.ID,
		"previous_situation_id": sit.PreviousSituationID,
		"public_handle":         sit.PublicHandle,
		"group_key":             sit.GroupKey,
		"lifecycle":             string(sit.Lifecycle),
		"attention":             string(sit.Attention),
		"input_version":         sit.InputVersion,
		"due_reasons":           sit.DueReasons,
		"opened_at":             sit.OpenedAt,
		"effective_started_at":  sit.EffectiveStartedAt,
		"first_received_at":     sit.FirstReceivedAt,
		"next_assessment_at":    sit.NextAssessmentAt,
		"incidents":             incidentRows,
		"assessment":            view.CurrentAssessment,
		"assessment_derivation": view.CurrentDerivation,
		"operator_contract":     view.CurrentActionContract,
		"material_fact_hash":    view.CurrentMaterialFactHash,
		"assessment_basis_hash": view.CurrentAssessmentBasisHash,
		// eligible_reasons is the full eligible Sufficient-reason candidate
		// set the last commit derived — identity, code, catalog/predicate
		// versions, evidence references, deterministic-floor flag — not only
		// the one the Assessment accepted (sufficient_reason inside
		// "assessment"). Empty array until the first reconcile.
		"eligible_reasons": view.EligibleReasons,
		"recent_attempts":  attemptRows,
		"controller_state": controllerStateRowFrom(view.Retry),
	}

	// Plan 3 Task 9: the durable operator history and Slack presence. episode
	// is an explicit null for a Situation with no Transition yet — history is
	// never reconstructed from current state — and slack_delivery always
	// answers, saying "published: false" with no effects for a Situation that
	// warranted no Slack at all.
	episode, delivery, err := s.situationHistoryFor(ctx, sit.ID)
	if err != nil {
		return errResult("failed to get situation history"), nil
	}
	if episode == nil {
		payload["episode"] = nil
	} else {
		payload["episode"] = episode
	}
	payload["slack_delivery"] = delivery

	result, err := mcplib.NewToolResultJSON(payload)
	if err != nil {
		return errResult("failed to serialize situation: " + err.Error()), nil
	}
	return result, nil
}

// ----------------------------------------------------------------------
// Plan 3 Task 9: bounded read-only history and delivery views.
//
// Three additions, all read-only and all reading ONLY Task 5's coherent
// Store views (internal/store/situation_views.go) — never a raw ledger
// join, never a reconstruction of history from current state:
//
//   - alertint_get_situation gains "episode" (the current Episode summary
//     read in one snapshot with the exact Transition it was folded from) and
//     "slack_delivery" (the current root coordinates plus every durable
//     effect's status, including the withheld/superseded/delayed decisions
//     that are durable rows rather than absent ones);
//   - alertint_list_situation_transitions pages the immutable Transition
//     journal by a stable (sequence, id) cursor; and
//   - alertint_get_delivery_state exposes the installation-level Slack
//     delivery snapshot: gap generation/status/age, replay backlog, retries
//     by effect class, uncertain outcomes, and the blocked backlog.
//
// None of them returns a claim owner, claim token, lease, bot token, raw
// Slack response, provider error body, or SQL text. The last of those is the
// reason every failure path returns a fixed generic message.
// ----------------------------------------------------------------------

func (s *Server) toolListSituationTransitions() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_list_situation_transitions",
		mcplib.WithDescription("Page one Situation's immutable Transition journal, oldest first. A Transition "+
			"is one authoritative material change: its lifecycle/attention, operator contract, transition reason, "+
			"journal kind and bounded journal entry, evidence references, actor, and drill marker. History is never "+
			"reconstructed from current state — a Situation with no Transition yet returns an empty array. Page with "+
			"the returned next_cursor; it is stable across concurrent commits because it names a (sequence, id) "+
			"position, not an offset."),
		mcplib.WithString("id", mcplib.Description("Situation ID. Exactly one of id/handle is required.")),
		mcplib.WithString("handle", mcplib.Description("Situation public handle. Exactly one of id/handle is required.")),
		mcplib.WithInteger("limit", mcplib.Description("Maximum transitions to return (1-100, default 50).")),
		mcplib.WithInteger("cursor_sequence", mcplib.Description("Resume strictly after this Transition sequence (from next_cursor).")),
		mcplib.WithString("cursor_id", mcplib.Description("Resume strictly after this Transition id at cursor_sequence (from next_cursor).")),
	)
	return tool, s.handleListSituationTransitions
}

func (s *Server) toolGetDeliveryState() (mcplib.Tool, mcpserver.ToolHandlerFunc) {
	tool := mcplib.NewTool("alertint_get_delivery_state",
		mcplib.WithDescription("Get the installation-level Situation Slack delivery state: the continuous-failure "+
			"window, the durable Slack configuration generation and how many effects are blocked on it, the current "+
			"Delivery-gap generation with its status/age and replay backlog, retries and outcomes by effect class, "+
			"how many outcomes Slack never confirmed either way, and the stdout Transition-stream backlog. Counts "+
			"and closed codes only — never a token, a Slack response, or a provider error body."),
	)
	return tool, s.handleGetDeliveryState
}

// situationTransitionRow is one immutable Transition as MCP renders it:
// identity, closed codes, hashes, the bounded journal entry, and instants.
type situationTransitionRow struct {
	ID                   string                        `json:"id"`
	Sequence             int                           `json:"sequence"`
	InputVersion         int                           `json:"input_version"`
	Lifecycle            string                        `json:"lifecycle"`
	Attention            string                        `json:"attention"`
	Reason               string                        `json:"reason"`
	JournalKind          string                        `json:"journal_kind"`
	Journal              situationmodel.JournalData    `json:"journal"`
	ActionContract       situationmodel.ActionContract `json:"action_contract"`
	MaterialFactHash     string                        `json:"material_fact_hash"`
	AssessmentID         *string                       `json:"assessment_id"`
	SufficientReasonID   *string                       `json:"sufficient_reason_id"`
	InterruptionPriority *string                       `json:"interruption_priority"`
	EvidenceRefs         []string                      `json:"evidence_refs"`
	Actor                string                        `json:"actor"`
	Drill                bool                          `json:"drill"`
	CreatedAt            time.Time                     `json:"created_at"`
}

func situationTransitionRowFrom(t situationmodel.Transition) situationTransitionRow {
	row := situationTransitionRow{
		ID: t.ID, Sequence: t.Sequence, InputVersion: t.InputVersion,
		Lifecycle: string(t.Lifecycle), Attention: string(t.Attention),
		Reason: string(t.Reason), JournalKind: string(t.JournalKind), Journal: t.Journal,
		ActionContract: t.ActionContract, MaterialFactHash: t.MaterialFactHash,
		AssessmentID: t.AssessmentID, SufficientReasonID: t.SufficientReasonID,
		EvidenceRefs: t.EvidenceRefs, Actor: string(t.Actor), Drill: t.Drill, CreatedAt: t.CreatedAt,
	}
	if row.EvidenceRefs == nil {
		row.EvidenceRefs = []string{}
	}
	if t.InterruptionPriority != nil {
		p := string(*t.InterruptionPriority)
		row.InterruptionPriority = &p
	}
	return row
}

// situationEpisodeRow is the current Episode-summary projection together
// with the exact Transition it was folded from. The two ALWAYS travel
// together: showing a summary beside a source Transition a caller cannot
// see is exactly the incoherence Task 5's snapshot read exists to prevent.
type situationEpisodeRow struct {
	Version                  int                    `json:"version"`
	SourceTransitionSequence int                    `json:"source_transition_sequence"`
	PublicHandle             string                 `json:"public_handle,omitempty"`
	Title                    string                 `json:"title"`
	InitialPublicationReason string                 `json:"initial_publication_reason,omitempty"`
	LatestMaterialReason     string                 `json:"latest_material_reason,omitempty"`
	EvidenceConclusion       string                 `json:"evidence_conclusion,omitempty"`
	ImpactSummary            string                 `json:"impact_summary,omitempty"`
	InvestigationWork        []string               `json:"investigation_work"`
	InvestigationStarted     bool                   `json:"investigation_started"`
	CurrentAttention         string                 `json:"current_attention"`
	PeakAttention            string                 `json:"peak_attention"`
	RecordedOperatorContext  []string               `json:"recorded_operator_context"`
	EffectiveStartedAt       time.Time              `json:"effective_started_at"`
	RecoveryObservedAt       *time.Time             `json:"recovery_observed_at"`
	TerminalAt               *time.Time             `json:"terminal_at"`
	DurationSeconds          *int64                 `json:"duration_seconds"`
	RecurrenceCount          int                    `json:"recurrence_count"`
	FinalOutcome             string                 `json:"final_outcome,omitempty"`
	RemainingUncertainty     string                 `json:"remaining_uncertainty,omitempty"`
	UpdatedAt                time.Time              `json:"updated_at"`
	SourceTransition         situationTransitionRow `json:"source_transition"`
}

func situationEpisodeRowFrom(view store.SituationEpisodeView) situationEpisodeRow {
	s := view.Summary
	row := situationEpisodeRow{
		Version: s.Version, SourceTransitionSequence: s.SourceTransitionSequence,
		PublicHandle: s.PublicHandle, Title: s.Title,
		InitialPublicationReason: s.InitialPublicationReason, LatestMaterialReason: s.LatestMaterialReason,
		EvidenceConclusion: s.EvidenceConclusion, ImpactSummary: s.ImpactSummary,
		InvestigationWork: s.InvestigationWork, InvestigationStarted: s.InvestigationStarted,
		CurrentAttention: string(s.CurrentAttention), PeakAttention: string(s.PeakAttention),
		RecordedOperatorContext: s.RecordedOperatorContext, EffectiveStartedAt: s.EffectiveStartedAt,
		RecoveryObservedAt: s.RecoveryObservedAt, TerminalAt: s.TerminalAt, DurationSeconds: s.DurationSeconds,
		RecurrenceCount: s.RecurrenceCount, FinalOutcome: s.FinalOutcome,
		RemainingUncertainty: s.RemainingUncertainty, UpdatedAt: s.UpdatedAt,
		SourceTransition: situationTransitionRowFrom(view.SourceTransition),
	}
	if row.InvestigationWork == nil {
		row.InvestigationWork = []string{}
	}
	if row.RecordedOperatorContext == nil {
		row.RecordedOperatorContext = []string{}
	}
	return row
}

// situationEffectRow is one durable notification intent as MCP renders it.
// Deliberately absent: claim_owner, claim_token, lease_expires_at, and the
// idempotency/client message identities — a delivery obligation's operator
// meaning is its class, subject, status, priority, reason, and where it
// actually landed, never who currently holds its lease.
type situationEffectRow struct {
	EffectClass          string     `json:"effect_class"`
	Status               string     `json:"status"`
	TransitionID         *string    `json:"transition_id"`
	TransitionSequence   *int       `json:"transition_sequence"`
	SummaryVersion       *int       `json:"summary_version"`
	MainChannelPoke      bool       `json:"main_channel_poke"`
	InterruptionPriority *string    `json:"interruption_priority"`
	RequiresRoot         bool       `json:"requires_root"`
	ContractDeadlineAt   *time.Time `json:"contract_deadline_at"`
	AttemptCount         int        `json:"attempt_count"`
	LastErrorClass       *string    `json:"last_error_class"`
	RetryAt              *time.Time `json:"retry_at"`
	SupersessionReason   *string    `json:"supersession_reason"`
	DeliveredAs          *string    `json:"delivered_as"`
	Channel              *string    `json:"channel"`
	MessageTS            *string    `json:"message_ts"`
	CreatedAt            time.Time  `json:"created_at"`
	DeliveredAt          *time.Time `json:"delivered_at"`
}

func situationEffectRowFrom(n situationmodel.NotificationIntent) situationEffectRow {
	row := situationEffectRow{
		EffectClass: string(n.EffectClass), Status: string(n.Status),
		TransitionID: n.TransitionID, TransitionSequence: n.TransitionSequence,
		SummaryVersion: n.SummaryVersion, MainChannelPoke: n.MainChannelPoke,
		RequiresRoot: n.RequiresRoot, ContractDeadlineAt: n.ContractDeadlineAt,
		AttemptCount: n.AttemptCount, LastErrorClass: n.LastErrorClass, RetryAt: n.RetryAt,
		SupersessionReason: n.SupersessionReason, DeliveredAs: n.DeliveredAs,
		Channel: n.Channel, MessageTS: n.MessageTS, CreatedAt: n.CreatedAt, DeliveredAt: n.DeliveredAt,
	}
	if n.InterruptionPriority != nil {
		p := string(*n.InterruptionPriority)
		row.InterruptionPriority = &p
	}
	return row
}

// situationDeliveryRow is one Situation's whole Slack presence: whether a
// root is durably published, where it lives, and every durable effect.
type situationDeliveryRow struct {
	Published     bool                 `json:"published"`
	Channel       string               `json:"channel,omitempty"`
	RootMessageTS string               `json:"root_message_ts,omitempty"`
	Effects       []situationEffectRow `json:"effects"`
}

// situationHistoryFor reads one Situation's Episode view and Slack delivery
// state through Task 5's bounded readers. A Situation with no Transition yet
// legitimately has no episode at all: that renders as an explicit null, never
// as history reconstructed from current state.
func (s *Server) situationHistoryFor(ctx context.Context, situationID string) (*situationEpisodeRow, situationDeliveryRow, error) {
	delivery := situationDeliveryRow{Effects: []situationEffectRow{}}

	channel, messageTS, published, err := s.st.GetSituationRootCoordinates(ctx, situationID)
	if err != nil {
		return nil, delivery, err
	}
	delivery.Published = published
	if published {
		delivery.Channel = channel
		delivery.RootMessageTS = messageTS
	}
	intents, err := s.st.ListSituationNotificationIntents(ctx, situationID, 0)
	if err != nil {
		return nil, delivery, err
	}
	for _, intent := range intents {
		delivery.Effects = append(delivery.Effects, situationEffectRowFrom(intent))
	}

	view, err := s.st.GetSituationEpisodeView(ctx, situationID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, delivery, nil
	}
	if err != nil {
		return nil, delivery, err
	}
	episode := situationEpisodeRowFrom(view)
	return &episode, delivery, nil
}

// transitionCursorRow is the stable page position a caller resumes from.
type transitionCursorRow struct {
	Sequence int    `json:"sequence"`
	ID       string `json:"id"`
}

func (s *Server) handleListSituationTransitions(ctx context.Context, req mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	sit, failed := s.resolveSituation(ctx, req)
	if failed != nil {
		return failed, nil
	}
	limit := mcplib.ParseInt(req, "limit", 50)
	if limit < 1 {
		limit = 50
	}
	cursor := store.TransitionCursor{
		Sequence: mcplib.ParseInt(req, "cursor_sequence", 0),
		ID:       mcplib.ParseString(req, "cursor_id", ""),
	}
	transitions, err := s.st.ListSituationTransitions(ctx, sit.ID, cursor, limit)
	if err != nil {
		return errResult("failed to list situation transitions"), nil
	}
	rows := make([]situationTransitionRow, 0, len(transitions))
	for _, t := range transitions {
		rows = append(rows, situationTransitionRowFrom(t))
	}
	payload := map[string]any{"situation_id": sit.ID, "transitions": rows, "next_cursor": nil}
	// A full page is the only reason to hand back a cursor: a short page has
	// nothing after it, and claiming otherwise would make a caller poll
	// forever.
	if len(rows) == limit && len(rows) > 0 {
		last := rows[len(rows)-1]
		payload["next_cursor"] = transitionCursorRow{Sequence: last.Sequence, ID: last.ID}
	}
	result, err := mcplib.NewToolResultJSON(payload)
	if err != nil {
		return errResult("failed to serialize situation transitions: " + err.Error()), nil
	}
	return result, nil
}

func (s *Server) handleGetDeliveryState(ctx context.Context, _ mcplib.CallToolRequest) (*mcplib.CallToolResult, error) {
	now := time.Now().UTC()
	state, err := s.st.GetSlackDeliveryState(ctx)
	if err != nil {
		return errResult("failed to get slack delivery state"), nil
	}
	stats, err := s.st.GetNotificationDeliveryStats(ctx, now)
	if err != nil {
		return errResult("failed to get notification delivery stats"), nil
	}
	payload := map[string]any{
		"slack": map[string]any{
			// first_failure_at anchors the CONTINUOUS failure window a gap
			// opens after five minutes of; a nil value means Slack delivery
			// is currently healthy.
			"first_failure_at":            state.FirstFailureAt,
			"last_success_at":             state.LastSuccessAt,
			"open_gap_generation":         state.OpenGapGeneration,
			"open_gap_status":             state.OpenGapStatus,
			"configuration_generation":    state.ConfigurationGeneration,
			"blocked_configuration_count": state.BlockedConfigurationCount,
			"updated_at":                  state.UpdatedAt,
		},
		"delivery": stats,
	}
	result, err := mcplib.NewToolResultJSON(payload)
	if err != nil {
		return errResult("failed to serialize delivery state: " + err.Error()), nil
	}
	return result, nil
}

// resolveSituation resolves exactly one of id/handle, returning a ready
// error result rather than an error when the request is unusable.
func (s *Server) resolveSituation(ctx context.Context, req mcplib.CallToolRequest) (situationmodel.Situation, *mcplib.CallToolResult) {
	id := mcplib.ParseString(req, "id", "")
	handle := mcplib.ParseString(req, "handle", "")
	if (id == "") == (handle == "") {
		return situationmodel.Situation{}, errResult("exactly one of id or handle is required")
	}
	var (
		sit situationmodel.Situation
		err error
	)
	if id != "" {
		sit, err = s.st.GetSituation(ctx, id)
	} else {
		sit, err = s.st.GetSituationByHandle(ctx, handle)
	}
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			if id != "" {
				return situationmodel.Situation{}, errResult(fmt.Sprintf("situation %q not found", id))
			}
			return situationmodel.Situation{}, errResult(fmt.Sprintf("situation with handle %q not found", handle))
		}
		return situationmodel.Situation{}, errResult("failed to get situation")
	}
	return sit, nil
}
