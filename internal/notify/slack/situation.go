// SPDX-License-Identifier: FSL-1.1-ALv2

package slack

// situation.go is Plan 3's pure Situation-owned Slack renderer: roots,
// immutable journal entries, and the one installation Delivery-gap
// recovery notice. It makes no publication decision, no Slack call, and no
// Store read — every function here is total over its arguments and reads
// nothing else (Task 6 brief Step 3: "Render a root only from the selected
// Episode-summary version, a journal only from its referenced Transition,
// and a recovery notice only from its gap generation").

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	slacklib "github.com/slack-go/slack"

	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

// Bounded rendering limits. maxSectionChars mirrors Slack's own Block Kit
// text-object limit (block_object.go's TextBlockObject.Validate: "text
// cannot be longer than 3000 characters") so a render never produces a
// payload Slack itself would reject. maxRenderedListEntries and
// truncationMarker back this file's own compactness choice — a card stays
// scannable — never a silent drop (Step 3: "Apply bounded truncation with
// a visible marker").
const (
	maxSectionChars        = 3000
	maxRenderedListEntries = 5
	truncationMarker       = "… [truncated]"
)

// RenderedMessage is one fully rendered Slack payload: the plain-text
// fallback Slack requires (and a client without Block Kit support shows —
// a mobile push notification, a screen reader) plus the Block Kit body.
// Blocks is nil for the one plain-text-only surface (the installation gap
// notice mirrors PostSystemMessage's own plain-text convention).
type RenderedMessage struct {
	Text   string
	Blocks []slacklib.Block
}

// ----------------------------------------------------------------------
// Root
// ----------------------------------------------------------------------

// SituationRootInput is everything RenderSituationRoot needs: the selected,
// coherent Episode-summary/source-Transition pair (Task 5's
// GetSituationEpisodeView reads exactly this pair in one snapshot), the
// delivering root_sync intent's own committed contract deadline (R4 —
// rendered here, never read from the Episode summary), and the render-time
// instant used for the ceil-rounded countdown / overdue comparison.
//
// RecoveryEverObserved answers a question the source Transition alone
// cannot always answer: whether a recovery_pending Transition occurred
// anywhere earlier in this Situation's Transition ledger. It changes the
// rendered chain only when SourceTransition is itself a closed_unknown
// Transition reached directly from `active` with no recovery observation
// of its OWN (Projection.RecoveryObservedAt nil) — a refire clears that
// field on every Transition after it (internal/situation/controller.go's
// resolveLifecycle, EventRefired branch), so a closed_unknown that follows
// a refire cannot see the earlier recovery_pending phase through the
// source Transition alone. DeriveOrientation's own doc comment names this
// gap: "whether a closed_unknown chain includes Monitoring at all...
// additionally needs the Situation's Transition history, which the Slack
// renderer reads." Every other orientation decides the chain from
// SourceTransition alone, so a caller may safely pass false when it has
// not needed to scan the ledger (e.g. SourceTransition.Projection.
// RecoveryObservedAt is already non-nil, or the Transition is not a
// closed_unknown at all).
type SituationRootInput struct {
	Summary              model.EpisodeSummary
	SourceTransition     model.Transition
	ContractDeadlineAt   *time.Time
	Now                  time.Time
	RecoveryEverObserved bool
}

// RenderSituationRoot renders one Situation's root card from exactly the
// selected Episode-summary version and its source Transition — never a
// second, newer read of either.
func RenderSituationRoot(in SituationRootInput) (RenderedMessage, error) {
	if err := validateRootInput(in); err != nil {
		return RenderedMessage{}, err
	}

	orientation := situation.DeriveOrientation(in.Summary, in.SourceTransition)
	recoveryEverObserved := in.RecoveryEverObserved || in.SourceTransition.Projection.RecoveryObservedAt != nil
	terminal := in.SourceTransition.Lifecycle.Terminal()

	blocks := []slacklib.Block{
		headerBlock(in.Summary, in.SourceTransition.Drill),
		orientationBlock(orientation, recoveryEverObserved),
	}

	if terminal {
		blocks = append(blocks, terminalBodyBlocks(in.Summary, in.SourceTransition)...)
	} else {
		// "The line immediately below [the orientation] renders the
		// Operator contract in compact prose" (spec.md "Root and journal
		// rendering") — the contract/deadline line sits directly under the
		// orientation chain, before the other nonterminal sections.
		contractAndDeadline, err := contractAndDeadlineBlock(orientation, in.Summary.ActionContract, in.ContractDeadlineAt, in.Now)
		if err != nil {
			return RenderedMessage{}, err
		}
		blocks = append(blocks, contractAndDeadline)
		blocks = append(blocks, nonterminalBodyBlocks(in.Summary, in.SourceTransition)...)
	}
	blocks = append(blocks, handleBlock(in.Summary))

	return RenderedMessage{
		Text:   rootFallback(in.Summary, orientation, in.SourceTransition.Drill),
		Blocks: blocks,
	}, nil
}

func validateRootInput(in SituationRootInput) error {
	if err := in.Summary.Validate(); err != nil {
		return fmt.Errorf("slack: render situation root: %w", err)
	}
	if err := in.SourceTransition.Validate(); err != nil {
		return fmt.Errorf("slack: render situation root: %w", err)
	}
	if in.Summary.SituationID != in.SourceTransition.SituationID {
		return fmt.Errorf("slack: render situation root: summary situation %q does not match transition situation %q",
			in.Summary.SituationID, in.SourceTransition.SituationID)
	}
	if in.Summary.SourceTransitionSequence != in.SourceTransition.Sequence {
		return fmt.Errorf("slack: render situation root: summary source sequence %d does not match transition sequence %d",
			in.Summary.SourceTransitionSequence, in.SourceTransition.Sequence)
	}
	if in.Now.IsZero() {
		return errors.New("slack: render situation root: now is required")
	}
	terminal := in.SourceTransition.Lifecycle.Terminal()
	switch {
	case terminal && in.ContractDeadlineAt != nil:
		return errors.New("slack: render situation root: a terminal root must not carry a contract deadline")
	case !terminal && in.ContractDeadlineAt == nil:
		return errors.New("slack: render situation root: a nonterminal root requires the delivering intent's contract deadline (R4)")
	}
	return nil
}

func headerBlock(s model.EpisodeSummary, drill bool) slacklib.Block {
	return sectionBlock(drillPrefix(drill) + "*" + s.Title + "*")
}

func orientationBlock(o situation.Orientation, recoveryEverObserved bool) slacklib.Block {
	return contextBlock(renderOrientationChain(o, recoveryEverObserved))
}

// renderOrientationChain renders the compact phase chain with exactly one
// current phase emphasized (spec.md "Root and journal rendering"). The
// nonterminal chains always preview the full roadmap — Monitoring and the
// generic "Outcome" placeholder included — since an active Situation has
// not yet learned whether it will ever be observed recovering. A terminal
// chain instead reports what actually happened: Recovered always implies
// Monitoring (AdvanceLifecycle only reaches `recovered` from
// `recovery_pending`); closed_unknown includes Monitoring only when
// recoveryEverObserved says the episode passed through it.
func renderOrientationChain(o situation.Orientation, recoveryEverObserved bool) string {
	const (
		phaseObserved      = "Observed"
		phaseInvestigating = "Investigating"
		phaseMonitoring    = "Monitoring"
		phasePlaceholder   = "Outcome"
	)

	outcome := phasePlaceholder
	var bold string
	showMonitoring := true

	switch o {
	case situation.OrientationObserved:
		bold = phaseObserved
	case situation.OrientationInvestigating:
		bold = phaseInvestigating
	case situation.OrientationMonitoring:
		bold = phaseMonitoring
	case situation.OrientationRecovered:
		outcome = "Recovered"
		bold = outcome
	case situation.OrientationClosedUncertain:
		outcome = "Closed uncertain"
		bold = outcome
		showMonitoring = recoveryEverObserved
	default:
		bold = phaseObserved
	}

	phases := []string{phaseObserved, phaseInvestigating}
	if showMonitoring {
		phases = append(phases, phaseMonitoring)
	}
	phases = append(phases, outcome)

	rendered := make([]string, len(phases))
	for i, p := range phases {
		if p == bold {
			rendered[i] = "*" + p + "*"
		} else {
			rendered[i] = p
		}
	}
	return strings.Join(rendered, " → ")
}

// contractAndDeadlineBlock renders who acts next and what happens next and
// by when, as one compact line, e.g. "AlertINT is running Acute Triage ·
// update by 10:00:15" — the delivering intent's own ContractDeadlineAt
// (R4), never the Episode summary.
func contractAndDeadlineBlock(o situation.Orientation, c model.ActionContract, deadline *time.Time, now time.Time) (slacklib.Block, error) {
	if deadline == nil {
		return nil, errors.New("slack: render situation root: nonterminal root requires a contract deadline (R4)")
	}
	return contextBlock(contractLine(o, c) + " · " + RenderDeadline(*deadline, now)), nil
}

// nonterminalBodyBlocks renders the still-open root's remaining required
// sections: what is happening, why current Attention is warranted, and
// what AlertINT checked or is checking.
func nonterminalBodyBlocks(s model.EpisodeSummary, t model.Transition) []slacklib.Block {
	var blocks []slacklib.Block
	if line := whatIsHappeningLine(s); line != "" {
		blocks = append(blocks, sectionBlock(line))
	}
	if line := attentionLine(s, t); line != "" {
		blocks = append(blocks, sectionBlock(line))
	}
	if line := investigationLine(s); line != "" {
		blocks = append(blocks, sectionBlock(line))
	}
	if line := recurrenceLine(s); line != "" {
		blocks = append(blocks, contextBlock(line))
	}
	return blocks
}

// terminalBodyBlocks renders the closed root's required sections: final
// outcome, what AlertINT investigated/concluded, duration and peak
// Attention, and recorded operator involvement. It never renders
// ActionContract.NextActor (a terminal contract's own next_actor is not
// the operator-involvement question the spec asks for), so it can never
// collapse to the literal "Actor: none" the spec forbids; FinalOutcome
// already carries Task 4's exact "no recorded operator intervention"
// wording when RecordedOperatorContext is empty.
func terminalBodyBlocks(s model.EpisodeSummary, t model.Transition) []slacklib.Block {
	var blocks []slacklib.Block
	if line := impactAndOutcomeLine(s); line != "" {
		blocks = append(blocks, sectionBlock(line))
	}
	if line := investigationLine(s); line != "" {
		blocks = append(blocks, sectionBlock(line))
	}
	if s.EvidenceConclusion != "" {
		blocks = append(blocks, sectionBlock("*Evidence conclusion:* "+s.EvidenceConclusion))
	}
	if cl := causalityLine(t.Projection.Assessment); cl != "" {
		blocks = append(blocks, sectionBlock(cl))
	}
	blocks = append(blocks, sectionBlock(durationPeakLine(s)))
	if s.RecoveryObservedAt != nil {
		blocks = append(blocks, contextBlock("Recovery observed "+SlackDateToken(*s.RecoveryObservedAt, "{date_short} {time}")))
	}
	if line := recurrenceLine(s); line != "" {
		blocks = append(blocks, contextBlock(line))
	}
	if len(s.RecordedOperatorContext) > 0 {
		blocks = append(blocks, sectionBlock("*Recorded operator context:*\n"+boundedList(s.RecordedOperatorContext)))
	}
	if s.RemainingUncertainty != "" {
		blocks = append(blocks, sectionBlock("*Remaining uncertainty:* "+s.RemainingUncertainty))
	}
	return blocks
}

// recurrenceLine reports how many times this Situation's condition has
// recurred, from durable local Store facts alone. Empty when it has never
// recurred.
func recurrenceLine(s model.EpisodeSummary) string {
	if s.RecurrenceCount <= 0 {
		return ""
	}
	return fmt.Sprintf(":repeat: recurred ×%d", s.RecurrenceCount)
}

// impactAndOutcomeLine renders the terminal root's required "what happened
// and the final outcome" section: the recorded impact alongside Task 4's
// own FinalOutcome text (already carrying the exact "recovered without
// recorded operator intervention" wording — spec.md "Root and journal
// rendering" — when no operator context was recorded).
func impactAndOutcomeLine(s model.EpisodeSummary) string {
	parts := []string{}
	if s.ImpactSummary != "" {
		parts = append(parts, s.ImpactSummary)
	}
	if s.FinalOutcome != "" {
		parts = append(parts, s.FinalOutcome)
	}
	if len(parts) == 0 {
		return ""
	}
	return "*Outcome:* " + strings.Join(parts, " — ")
}

func whatIsHappeningLine(s model.EpisodeSummary) string {
	parts := []string{}
	if label := reasonLabel(s.LatestMaterialReason); label != "" {
		parts = append(parts, label)
	}
	if s.ImpactSummary != "" {
		parts = append(parts, s.ImpactSummary)
	}
	if len(parts) == 0 {
		return ""
	}
	return "*What's happening:* " + strings.Join(parts, " — ")
}

func attentionLine(s model.EpisodeSummary, t model.Transition) string {
	parts := []string{"*Attention:* " + humanizeAttention(s.CurrentAttention)}
	if s.EvidenceConclusion != "" {
		parts = append(parts, s.EvidenceConclusion)
	}
	if cl := causalityLine(t.Projection.Assessment); cl != "" {
		parts = append(parts, cl)
	}
	return strings.Join(parts, " — ")
}

func investigationLine(s model.EpisodeSummary) string {
	if len(s.InvestigationWork) == 0 {
		return ""
	}
	return "*AlertINT checked:*\n" + boundedList(s.InvestigationWork)
}

func durationPeakLine(s model.EpisodeSummary) string {
	duration := "unknown"
	if s.DurationSeconds != nil {
		duration = (time.Duration(*s.DurationSeconds) * time.Second).String()
	}
	return fmt.Sprintf("*Duration:* %s · *Peak attention:* %s", duration, humanizeAttention(s.PeakAttention))
}

// causalityLine reports what the evidence supports without ever
// overclaiming: unknown causality is rendered as "reporting observed
// symptoms and checks only," never as a root-cause conclusion (Step 2:
// "Unknown causality must stay observed symptoms/checks and never render
// as root cause").
func causalityLine(a *model.AssessmentConclusion) string {
	if a == nil {
		return ""
	}
	switch a.Causality { //nolint:exhaustive // CausalityUnknown (and any unrecognized value) is the intentional default below.
	case model.CausalitySupported:
		return "Evidence supports a specific cause."
	case model.CausalityCorrelated:
		return "Evidence correlates with a candidate cause, not yet confirmed."
	case model.CausalityOperatorConfirmed:
		return "Operator confirmed the cause."
	case model.CausalityContradicted:
		return "Evidence contradicts the suspected cause."
	default: // CausalityUnknown and any unrecognized value.
		return "Cause not established — reporting observed symptoms and checks only."
	}
}

func handleBlock(s model.EpisodeSummary) slacklib.Block {
	handle := s.PublicHandle
	if handle == "" {
		handle = s.SituationID
	}
	return contextBlock(fmt.Sprintf(":robot_face: Situation `%s` · `get situation %s using alertint`", handle, handle))
}

func rootFallback(s model.EpisodeSummary, o situation.Orientation, drill bool) string {
	return fmt.Sprintf("%s%s — %s", drillPlainPrefix(drill), s.Title, string(o))
}

func drillPlainPrefix(drill bool) string {
	if drill {
		return "🧪 DRILL — "
	}
	return ""
}

// ----------------------------------------------------------------------
// Journal
// ----------------------------------------------------------------------

// RenderSituationJournal renders one immutable journal entry from its
// referenced Transition alone. Delayed/NoLongerCurrent are read straight
// off t.Journal: Task 4's BuildTransitions never sets either (a Transition
// cannot know at creation time whether a later delivery attempt will find
// its handoff stale), so a caller that has determined at delivery time
// that a broadcast handoff is no longer current renders from a local copy
// of t with those two fields set — the stored ledger row itself is never
// mutated.
func RenderSituationJournal(t model.Transition) (RenderedMessage, error) {
	if err := t.Validate(); err != nil {
		return RenderedMessage{}, fmt.Errorf("slack: render situation journal: %w", err)
	}
	if t.JournalKind == model.JournalNone {
		return RenderedMessage{}, errors.New("slack: render situation journal: transition carries no journal entry")
	}

	prefix := drillPrefix(t.Drill)
	headline := prefix + "*" + t.Journal.Headline + "*"
	blocks := []slacklib.Block{sectionBlock(headline)}
	if t.Journal.Detail != "" {
		blocks = append(blocks, sectionBlock(t.Journal.Detail))
	}

	var markers []string
	if t.Journal.NoLongerCurrent {
		markers = append(markers, "no longer current")
	}
	if t.Journal.Delayed {
		markers = append(markers, "delayed")
	}
	if len(markers) > 0 {
		blocks = append(blocks, contextBlock(":clock3: "+strings.Join(markers, " · ")))
	}
	blocks = append(blocks, contextBlock(SlackDateToken(t.Journal.OccurredAt, "{date_short} {time}")))

	return RenderedMessage{
		Text:   prefix + t.Journal.Headline,
		Blocks: blocks,
	}, nil
}

// ----------------------------------------------------------------------
// Installation Delivery-gap recovery notice
// ----------------------------------------------------------------------

// GapNoticeInput is the exact durable gap generation
// RenderDeliveryGapNotice renders one installation_gap_recovery notice
// from — opened_at, recovered_at, and the affected/delayed counts
// recorded on the gap generation (spec.md "Recovery replay": "reports the
// gap interval, affected Situation count, delayed effect count, and
// backlog delivery status").
type GapNoticeInput struct {
	GapID                  string
	OpenedAt               time.Time
	RecoveredAt            time.Time
	AffectedSituationCount int
	DelayedEffectCount     int
}

// RenderDeliveryGapNotice renders the one bounded ADR-0042 System message
// that precedes backlog replay. It is plain text, matching
// PostSystemMessage's own convention for an installation-level notice —
// this is not a Situation card and carries no Block Kit body.
func RenderDeliveryGapNotice(in GapNoticeInput) (RenderedMessage, error) {
	if strings.TrimSpace(in.GapID) == "" {
		return RenderedMessage{}, errors.New("slack: render delivery gap notice: gap id is required")
	}
	if in.OpenedAt.IsZero() {
		return RenderedMessage{}, errors.New("slack: render delivery gap notice: opened_at is required")
	}
	if in.RecoveredAt.IsZero() {
		return RenderedMessage{}, errors.New("slack: render delivery gap notice: recovered_at is required")
	}
	if in.RecoveredAt.Before(in.OpenedAt) {
		return RenderedMessage{}, errors.New("slack: render delivery gap notice: recovered_at precedes opened_at")
	}
	if in.AffectedSituationCount < 0 || in.DelayedEffectCount < 0 {
		return RenderedMessage{}, errors.New("slack: render delivery gap notice: counts must be >= 0")
	}
	duration := in.RecoveredAt.Sub(in.OpenedAt).Round(time.Second)
	text := fmt.Sprintf(
		":warning: AlertINT's Slack delivery was interrupted from %s to %s (%s). %d Situation(s) affected, %d delayed effect(s). Replaying the backlog now.",
		SlackDateToken(in.OpenedAt, "{date_short} {time}"),
		SlackDateToken(in.RecoveredAt, "{date_short} {time}"),
		duration, in.AffectedSituationCount, in.DelayedEffectCount)
	return RenderedMessage{Text: text}, nil
}

// ----------------------------------------------------------------------
// Small rendering helpers
// ----------------------------------------------------------------------

func drillPrefix(drill bool) string {
	if drill {
		return ":test_tube: *DRILL* — "
	}
	return ""
}

func humanizeAttention(a model.Attention) string {
	switch a {
	case model.AttentionObserve:
		return "observe"
	case model.AttentionInvestigate:
		return "investigate"
	case model.AttentionUrgent:
		return "urgent"
	default:
		return string(a)
	}
}

// reasonLabel humanizes a closed TransitionReason code for the "what's
// happening" line. It never invents facts beyond the code itself.
func reasonLabel(reason string) string {
	switch model.TransitionReason(reason) {
	case model.ReasonFirstAuthoritativeState:
		return "Situation published"
	case model.ReasonMaterialAssessmentChanged:
		return "Assessment changed"
	case model.ReasonAttentionChanged:
		return "Attention changed"
	case model.ReasonOperatorContractChanged:
		return "Operator contract changed"
	case model.ReasonInvestigationStarted:
		return "Investigation started"
	case model.ReasonInvestigationConcluded:
		return "Investigation concluded"
	case model.ReasonRecoveryObserved:
		return "Recovery observed"
	case model.ReasonRecoveryFailed:
		return "Recovery did not hold"
	case model.ReasonRecovered:
		return "Recovered"
	case model.ReasonClosedUnknown:
		return "Closed with uncertainty"
	case model.ReasonRecurrenceMilestone:
		return "Recurrence milestone"
	case model.ReasonTriageStateChanged:
		return "Acute Triage state changed"
	case model.ReasonOperatorArtifactRecorded:
		return "Operator context recorded"
	default:
		return ""
	}
}

// contractLine renders the compact Operator-contract action, e.g. "AlertINT
// is running Acute Triage" or "Watching for sustained recovery." Monitoring
// always reads as watching for recovery regardless of the underlying
// contract's own fields — the phase itself already says why.
func contractLine(o situation.Orientation, c model.ActionContract) string {
	if o == situation.OrientationMonitoring {
		return "Watching for sustained recovery"
	}
	switch {
	case c.OperatorActionRequired != nil:
		return "Operator action required: " + humanizeOperatorAction(*c.OperatorActionRequired)
	case c.AlertINTAction != nil:
		return humanizeAlertINTAction(*c.AlertINTAction, c.AlertINTStatus)
	default:
		return "No action currently required"
	}
}

func humanizeOperatorAction(a model.OperatorAction) string {
	switch a {
	case model.OperatorActionInvestigateSituation:
		return "investigate this Situation"
	default:
		return string(a)
	}
}

func humanizeAlertINTAction(a model.AlertINTAction, status *model.AlertINTStatus) string {
	verb := "is running"
	if status != nil {
		switch *status {
		case model.AlertINTStatusPlanned:
			verb = "will run"
		case model.AlertINTStatusRunning:
			verb = "is running"
		case model.AlertINTStatusWaiting:
			verb = "is waiting on"
		case model.AlertINTStatusBlocked:
			verb = "is blocked on"
		case model.AlertINTStatusExhausted:
			verb = "has exhausted its attempts at"
		case model.AlertINTStatusComplete:
			verb = "has completed"
		}
	}
	return fmt.Sprintf("AlertINT %s %s", verb, humanizeAlertINTActionLabel(a))
}

func humanizeAlertINTActionLabel(a model.AlertINTAction) string {
	switch a {
	case model.AlertINTActionRunAcuteTriage:
		return "Acute Triage"
	case model.AlertINTActionRetrySituationAssessment:
		return "its assessment"
	case model.AlertINTActionMonitorSituation:
		return "monitoring"
	case model.AlertINTActionVerifyRecovery:
		return "recovery verification"
	default:
		return string(a)
	}
}

// sectionBlock and contextBlock both apply the same bounded truncation with
// a visible marker (Step 3) rather than exceeding Slack's own per-block
// text limit.
func sectionBlock(text string) slacklib.Block {
	return slacklib.NewSectionBlock(
		slacklib.NewTextBlockObject(slacklib.MarkdownType, truncateText(text), false, false),
		nil, nil)
}

func contextBlock(text string) slacklib.Block {
	return slacklib.NewContextBlock("",
		slacklib.NewTextBlockObject(slacklib.MarkdownType, truncateText(text), false, false))
}

func truncateText(s string) string {
	if len(s) <= maxSectionChars {
		return s
	}
	cut := maxSectionChars - len(truncationMarker) - 1
	if cut < 0 {
		cut = 0
	}
	return boundedRunes(s, cut) + " " + truncationMarker
}

// boundedRunes truncates s to at most limit bytes without splitting a rune
// (mirrors internal/situation/history.go's own boundedText, unexported
// there).
func boundedRunes(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := s[:limit]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut
}

// boundedList renders the most recent maxRenderedListEntries of entries as
// a bullet list, oldest of the shown entries first, with a leading visible
// marker naming how many earlier entries were not shown — never a silent
// drop.
func boundedList(entries []string) string {
	shown := entries
	omitted := 0
	if len(entries) > maxRenderedListEntries {
		omitted = len(entries) - maxRenderedListEntries
		shown = entries[omitted:]
	}
	lines := make([]string, 0, len(shown)+1)
	if omitted > 0 {
		lines = append(lines, fmt.Sprintf("… %d earlier %s not shown", omitted, pluralize(omitted, "entry", "entries")))
	}
	for _, e := range shown {
		lines = append(lines, "• "+e)
	}
	return strings.Join(lines, "\n")
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}
