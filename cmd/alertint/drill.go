// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/logging"
	"github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// drillHTTPTimeout bounds every drill-side HTTP call. Explicit and non-zero:
// a zero deadline would expire every request.
const drillHTTPTimeout = 15 * time.Second

// drillTriageGrace is the bounded budget the drill gives the controller to
// raise a Situation (and, with --resolve, to observe it move through
// recovery_pending to recovered) on top of the correlation window.
const drillTriageGrace = 75 * time.Second

// drillPollInterval paces every post-window Situation poll. Each poll is one
// cheap MCP call; a run ends as soon as the awaited state appears instead of
// sleeping out the full grace.
const drillPollInterval = 5 * time.Second

// drillOpts are the parsed `alertint drill` flags.
type drillOpts struct {
	cfgPath         string
	target          string
	scenario        string
	result          string
	colorMode       string
	yes             bool
	fresh           bool
	allowInsecure   bool
	resolve         bool
	resolveWait     bool
	viaAlertmanager string
}

// drillCmd carries the flow's dependencies; tests replace the injectable ones.
type drillCmd struct {
	cfg    *config.Config
	opts   drillOpts
	stdout io.Writer
	color  bool

	http     *http.Client
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
	confirm  func(prompt string) (bool, error)
	pause    func(prompt string) error
	newRunID func() string
	grace    time.Duration
}

func runDrill(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint drill", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts drillOpts
	fs.StringVar(&opts.cfgPath, "config", "", "path to alertint YAML config (the same file serve reads)")
	fs.StringVar(&opts.target, "target", "", "base URL of a remote AlertINT instance (default: the local instance from config)")
	fs.StringVar(&opts.scenario, "scenario", "flagship", "scenario to fire: flagship | storm | db-outage")
	fs.StringVar(&opts.result, "result", "", "skip firing; fetch and print an existing Situation by id or public handle")
	fs.StringVar(&opts.colorMode, "color", "auto", "terminal color: auto | always | never")
	fs.BoolVar(&opts.yes, "yes", false, "skip the remote-target confirmation prompt")
	fs.BoolVar(&opts.fresh, "fresh", false, "always create a new drill incident; bypass recurrence collapse")
	fs.BoolVar(&opts.resolve, "resolve", false, "after the run, re-send the burst as resolved and watch the Situation reach recovery_pending then recovered")
	fs.BoolVar(&opts.resolveWait, "resolve-wait", false, "with --resolve, hold the drill incident open after the payoff and resolve on Enter")
	fs.BoolVar(&opts.allowInsecure, "allow-insecure-http", false, "allow sending bearer tokens to a plain-http remote target")
	fs.StringVar(&opts.viaAlertmanager, "via-alertmanager", "", "fire the burst through your Alertmanager (base URL, v2 API) to validate AM→AlertINT routing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.cfgPath == "" {
		return fmt.Errorf("drill: --config is required (the same config file serve reads)")
	}
	color, err := resolveDrillColor(opts.colorMode, stdout)
	if err != nil {
		return err
	}

	// Offline load: the drill never opens the database, so the config's
	// sqlite path must not be probed on this machine.
	cfg, err := config.LoadOffline(opts.cfgPath)
	if err != nil {
		return err
	}

	d := &drillCmd{
		cfg:    cfg,
		opts:   opts,
		stdout: stdout,
		color:  color,
		http:   &http.Client{Timeout: drillHTTPTimeout},
		now:    func() time.Time { return time.Now().UTC() },
		sleep: func(ctx context.Context, dur time.Duration) error {
			t := time.NewTimer(dur)
			defer t.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
				return nil
			}
		},
		confirm:  stdinConfirm(stderr),
		pause:    stdinPause(stderr),
		newRunID: randomRunID,
		grace:    drillTriageGrace,
	}
	return d.run(context.Background())
}

func resolveDrillColor(mode string, stdout io.Writer) (bool, error) {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if _, disabled := os.LookupEnv("NO_COLOR"); disabled {
		switch mode {
		case "auto", "always", "never":
			return false, nil
		}
	}
	switch mode {
	case "auto":
		return logging.ColorEnabled(stdout), nil
	case "always":
		return true, nil
	case "never":
		return false, nil
	default:
		return false, fmt.Errorf("drill: --color must be auto, always, or never (got %q)", mode)
	}
}

func (d *drillCmd) run(ctx context.Context) error {
	mcpEndpoint, mcpToken, mcpErr := d.mcpEndpoint()

	if d.opts.result != "" && d.opts.resolve {
		return fmt.Errorf("drill: --resolve applies to a firing run, not --result (re-run the drill with --resolve instead)")
	}
	if d.opts.resolveWait && !d.opts.resolve {
		return fmt.Errorf("drill: --resolve-wait requires --resolve")
	}

	// --result: the re-check path. One fetch, one print, done.
	if d.opts.result != "" {
		return d.runResult(ctx, mcpEndpoint, mcpToken, mcpErr)
	}

	sc, ok := drillScenarios()[d.opts.scenario]
	if !ok {
		return fmt.Errorf("drill: unknown scenario %q (have: flagship, storm, db-outage)", d.opts.scenario)
	}

	// The burst enters through the Alertmanager receiver; without it there is
	// nothing to drill. This is a pre-fire config error, not a degraded run.
	if !d.cfg.Alertmanager.Enabled {
		return fmt.Errorf("drill: alertmanager receiver is disabled in the config; the drill needs it to ingest the burst (alertmanager.enabled: true)")
	}

	recvBase, err := d.receiverBase()
	if err != nil {
		return err
	}

	// Guards run before any request leaves this process (ADR-0014: the drill
	// fires real writes at a real instance). --via-alertmanager is a second
	// remote write surface and gets the same guard.
	if err := d.guardRemote(recvBase, len(sc.alerts)); err != nil {
		return err
	}
	if d.opts.viaAlertmanager != "" {
		if err := d.guardRemote(strings.TrimRight(d.opts.viaAlertmanager, "/"), len(sc.alerts)); err != nil {
			return err
		}
		d.printf("note: your Alertmanager routing will fan this burst out to every matching receiver")
		d.printf("      (PagerDuty, email catch-alls, ...) — make sure the drill labels route somewhere harmless.")
	}

	webhookToken, err := d.cfg.WebhookToken()
	if err != nil {
		return err
	}

	// Preflights: notify-and-continue, never hard-fail.
	mcpAvailable := d.printPreflights(sc, mcpErr)

	// Recurrence rerun: if a prior drill of this scenario is still inside the
	// collapse window, reuse its group salt so this fire lands on its exact
	// group key. The Situation controller's own identity rules then decide
	// what happens (spec: "Situation creation and public identity") — attach
	// while the owner is active/recovery_pending, or mint a fresh Situation
	// linked through previous_situation_id once it has gone terminal — so this
	// scan does not filter by lifecycle itself. It fires with FRESH
	// fingerprints so its alerts are a new firing episode (a distinct-
	// fingerprint attach), not an unchanged repeat.
	groupSalt := d.newRunID()
	fpSeed := groupSalt
	rerunID, rerunLifecycle := "", ""
	if mcpAvailable && !d.opts.fresh {
		if cands, cerr := d.fetchDrillCandidates(ctx, mcpEndpoint, mcpToken); cerr == nil {
			w := time.Duration(d.cfg.Memory.AttachWindowMinutes) * time.Minute
			if id, lifecycle, salt, ok := drillRerunSalt(cands, d.cfg.Correlator.GroupLabels, sc.key, d.now(), w); ok {
				groupSalt, fpSeed, rerunID, rerunLifecycle = salt, d.newRunID(), id, lifecycle
				d.printf("rerun: a prior drill (%s, lifecycle=%s) is inside the %dm collapse window — reusing its group key to exercise Situation identity", id, lifecycle, d.cfg.Memory.AttachWindowMinutes)
			}
		}
	}

	run, err := materializeScenario(sc, d.cfg.Correlator.GroupLabels, groupSalt, fpSeed, d.now())
	if err != nil {
		return err
	}

	d.printPhase("fire")
	if d.opts.fresh {
		d.printf("%s", d.style("1;35", "fresh: bypassing prior drill recurrence — this run creates a new incident"))
	}
	if err := d.fire(ctx, sc, run, recvBase, webhookToken); err != nil {
		return err
	}
	d.printf("")
	d.printPhase("correlate")

	// Rerun payoff: the fire attaches (or, past a terminal owner, links) on
	// receipt — no window wait. Poll for the outcome instead.
	if rerunID != "" {
		situationID := ""
		if mcpAvailable {
			situationID = d.pollRerunOutcome(ctx, mcpEndpoint, mcpToken, run.expectedGroupKey, rerunID, rerunLifecycle)
		} else {
			d.printf("fired the rerun; mcp is not usable from here — check the Situation card in Slack for the update.")
		}
		return d.maybeResolve(ctx, run, recvBase, webhookToken, mcpEndpoint, mcpToken, mcpAvailable, situationID)
	}

	// First run: wait out the correlation window — a server-side property of
	// the target's correlator (tune correlator.window_seconds to shorten it) —
	// then poll for the owning Situation during the bounded grace so the run
	// ends as soon as it appears.
	window := time.Duration(d.cfg.Correlator.WindowSeconds)*time.Second + correlator.DefaultTickInterval
	d.printf("waiting ~%ds for the correlation window…", int(window.Seconds()))
	if err := d.sleep(ctx, window); err != nil {
		return err
	}

	if !mcpAvailable {
		// Nothing to poll without MCP: give the controller its grace blind,
		// then point at the surfaces that can show the Situation.
		d.printf("window closed; giving the controller up to %ds to raise a Situation…", int(d.grace.Seconds()))
		if err := d.sleep(ctx, d.grace); err != nil {
			return err
		}
		d.printf("")
		d.printPhase("finding")
		d.printf("fired. mcp is not usable from here, so the Situation cannot be fetched — check:")
		if d.cfg.Notify.Slack.Enabled {
			d.printf("  · the Situation card in Slack channel %s", d.cfg.Notify.Slack.Channel)
		}
		d.printf("  · the Situation stdout line in serve logs (group %s)", run.expectedGroupKey)
		d.printf("then hand it to your agent: investigate the latest drill situation using alertint")
		return d.maybeResolve(ctx, run, recvBase, webhookToken, mcpEndpoint, mcpToken, mcpAvailable, "")
	}
	d.printf("window closed; polling for the owning Situation (up to %ds)…", int(d.grace.Seconds()))
	snap, found, err := d.fetchSituationPayoff(ctx, mcpEndpoint, mcpToken, run.expectedGroupKey)
	if err != nil {
		return err
	}
	situationID := ""
	if found {
		situationID = snap.ID
	}
	return d.maybeResolve(ctx, run, recvBase, webhookToken, mcpEndpoint, mcpToken, mcpAvailable, situationID)
}

// runResult fetches and prints one existing Situation by id or public
// handle. The transport guard applies here too — this path carries the MCP
// bearer token.
func (d *drillCmd) runResult(ctx context.Context, mcpEndpoint, mcpToken string, mcpErr error) error {
	if !d.cfg.MCPEnabled() {
		return fmt.Errorf("drill: --result needs mcp enabled — set %s (mcp turns on automatically) or remove mcp.enabled: false", orDefault(d.cfg.MCP.TokenEnv, "ALERTINT_MCP_TOKEN"))
	}
	if mcpErr != nil {
		return mcpErr
	}
	if err := d.guardInsecureTransport(mcpEndpoint); err != nil {
		return err
	}
	client := newMCPOneShotClient(mcpEndpoint, mcpToken, d.http)
	if err := client.initialize(ctx); err != nil {
		return err
	}
	snap, err := d.getSituationSnapshot(ctx, client, d.opts.result)
	if err != nil {
		return fmt.Errorf("drill: fetch situation %s: %w", d.opts.result, err)
	}
	d.printSituationPayoff(snap)
	return nil
}

// maybeResolve fires the run's burst again as resolved when --resolve is set:
// same door, same token, same fingerprints — the instance closes the Drill
// through the production resolution path (Slack cards update in place) — then
// watches the owning Situation move through recovery_pending to recovered.
// Warn-and-continue: the payoff has already been delivered, and a failed
// resolution just leaves a firing Drill.
func (d *drillCmd) maybeResolve(ctx context.Context, run drillRun, recvBase, webhookToken, mcpEndpoint, mcpToken string, mcpAvailable bool, situationID string) error {
	if !d.opts.resolve {
		return nil
	}
	d.printf("")
	d.printPhase("resolve")
	if d.opts.resolveWait {
		if err := d.pause("press Enter to resolve the drill incident… "); err != nil {
			d.printf("note: stdin unavailable (%v) — resolving immediately", err)
		}
	}
	payload := resolvedPayload(run, d.now())
	if d.opts.viaAlertmanager != "" {
		d.printf("resolving the drill via your Alertmanager (delivery rides AM's group_interval)…")
		if err := d.postAlertmanagerV2(ctx, payload); err != nil {
			d.printf("warning: alertmanager rejected the resolution: %v — the drill Situation stays active", err)
			return nil
		}
	} else {
		d.printf("%s", d.style("1;92", fmt.Sprintf("alerts: %d resolved", len(payload.Alerts))))
		d.printf("%s", d.style("2", "group: "+run.expectedGroupKey))
		if err := d.postJSON(ctx, recvBase+"/webhook/alertmanager", webhookToken, payload); err != nil {
			d.printf("warning: resolution not accepted: %v — the drill Situation stays active", err)
			return nil
		}
	}
	if !mcpAvailable || situationID == "" {
		d.printSlackFallback(run.expectedGroupKey)
		return nil
	}
	return d.pollRecoveryThenRecovered(ctx, mcpEndpoint, mcpToken, situationID)
}

// pollRecoveryThenRecovered watches the visible recovery path: it first waits
// for the Situation to show recovery_pending (the grace window watching for a
// clean recovery), then for it to reach the terminal recovered state, each
// bounded by the drill's grace. A bounded timeout at either stage points at
// --result rather than failing the run — the payoff already printed.
func (d *drillCmd) pollRecoveryThenRecovered(ctx context.Context, mcpEndpoint, mcpToken, situationID string) error {
	client := newMCPOneShotClient(mcpEndpoint, mcpToken, d.http)
	if err := client.initialize(ctx); err != nil {
		d.printf("warning: could not reach MCP to confirm recovery: %v", err)
		return nil
	}

	d.printf("waiting for the Situation to show recovery pending (up to %ds)…", int(d.grace.Seconds()))
	pending, ok, err := d.pollUntilLifecycle(ctx, client, situationID, string(model.LifecycleRecoveryPending))
	if err != nil {
		return err
	}
	if !ok {
		d.printf("the Situation has not shown recovery pending yet; re-check with:")
		d.printf("  alertint drill --config %s%s --result %s", d.opts.cfgPath, d.targetFlagSuffix(), situationID)
		return nil
	}
	d.printf("%s", d.style("1;92", fmt.Sprintf("recovery pending: %s — attention=%s (grace window watching for a clean recovery)", situationTarget(pending), pending.Attention)))

	d.printf("waiting for the Situation to recover (up to %ds)…", int(d.grace.Seconds()))
	recovered, ok, err := d.pollUntilLifecycle(ctx, client, situationID, string(model.LifecycleRecovered))
	if err != nil {
		return err
	}
	if !ok {
		d.printf("the Situation has not recovered yet; re-check with:")
		d.printf("  alertint drill --config %s%s --result %s", d.opts.cfgPath, d.targetFlagSuffix(), situationID)
		return nil
	}
	d.printf("%s", d.style("1;92", fmt.Sprintf("recovered: %s closed cleanly", situationTarget(recovered))))
	return nil
}

// pollUntilLifecycle polls one Situation until its lifecycle equals want or
// the drill's grace runs out. Polling is paced by d.sleep so the loop is
// deterministic under test clocks.
func (d *drillCmd) pollUntilLifecycle(ctx context.Context, client *mcpOneShotClient, situationID, want string) (situationSnapshot, bool, error) {
	polls := int(d.grace / drillPollInterval)
	if polls < 1 {
		polls = 1
	}
	for attempt := 0; ; attempt++ {
		snap, err := d.getSituationSnapshot(ctx, client, situationID)
		if err == nil && snap.Lifecycle == want {
			return snap, true, nil
		}
		if attempt >= polls {
			return situationSnapshot{}, false, nil
		}
		if err := d.sleep(ctx, drillPollInterval); err != nil {
			return situationSnapshot{}, false, err
		}
	}
}

// printPreflights emits the notify-and-continue setup notes and resolves
// whether MCP is usable from here.
func (d *drillCmd) printPreflights(sc drillScenario, mcpErr error) (mcpAvailable bool) {
	mcpAvailable = d.cfg.MCPEnabled() && mcpErr == nil
	if d.cfg.MCPEnabled() && mcpErr != nil {
		d.printf("note: mcp is enabled but not usable from here (%v) — the drill will fire, but", mcpErr)
		d.printf("      cannot fetch the Situation when it is ready; fix the token/addr and use --result.")
	}
	if sc.change != nil && !d.cfg.Changes.Ingress.Enabled {
		d.printf("note: changes.ingress is disabled, so the planted deploy will be skipped — the Situation")
		d.printf("      forms from alert evidence alone. enable it in %s and re-run for the causal deploy evidence:", d.opts.cfgPath)
		d.printf("        changes:")
		d.printf("          ingress:")
		d.printf("            enabled: true")
		d.printf("            webhook_token_env: %s", orDefault(d.cfg.Changes.Ingress.WebhookTokenEnv, "ALERTINT_CHANGES_WEBHOOK_TOKEN"))
	}
	if !d.cfg.MCPEnabled() {
		d.printf("note: mcp is disabled, so the drill cannot fetch the Situation when it is ready.")
		if d.cfg.MCP.Enabled != nil && !*d.cfg.MCP.Enabled {
			d.printf("      mcp.enabled is false in %s — remove that line to complete the loop.", d.opts.cfgPath)
		} else {
			d.printf("      set %s to a long random secret and mcp turns on automatically.", orDefault(d.cfg.MCP.TokenEnv, "ALERTINT_MCP_TOKEN"))
		}
	}
	return mcpAvailable
}

// fire POSTs the planted change event (when enabled) and the burst.
func (d *drillCmd) fire(ctx context.Context, sc drillScenario, run drillRun, recvBase, webhookToken string) error {
	if d.cfg.Changes.Ingress.Enabled && sc.change != nil {
		token, err := d.cfg.ChangesWebhookToken()
		if err != nil {
			return err
		}
		d.printf("planting change event: %s (%s ago)", run.change.Title, sc.change.occurredAgo)
		if err := d.postJSON(ctx, recvBase+"/webhook/change", token, run.change); err != nil {
			d.printf("warning: change event not accepted: %v — continuing without it", err)
			d.printf("         (check the %s env var; the deploy evidence will be missing without it)", orDefault(d.cfg.Changes.Ingress.WebhookTokenEnv, "ALERTINT_CHANGES_WEBHOOK_TOKEN"))
		}
	}

	if d.opts.viaAlertmanager != "" {
		d.printf("firing %d drill alerts via your Alertmanager at %s", len(run.alerts.Alerts), d.opts.viaAlertmanager)
		d.printf("note: delivery now depends on your AM routing matching these labels (group %s)", run.expectedGroupKey)
		d.printf("      and on AM's group_wait/group_interval; if the fetch below comes up empty, re-check later.")
		if err := d.postAlertmanagerV2(ctx, run.alerts); err != nil {
			d.printf("warning: alertmanager rejected the burst: %v", err)
		}
		return nil
	}
	d.printf("%s", d.style("1", fmt.Sprintf("scenario: %s — %s", sc.key, sc.description)))
	d.printf("%s", d.style("1;33", fmt.Sprintf("alerts: %d firing", len(run.alerts.Alerts))))
	d.printf("%s", d.style("2", "group: "+run.expectedGroupKey))
	if err := d.postJSON(ctx, recvBase+"/webhook/alertmanager", webhookToken, run.alerts); err != nil {
		return fmt.Errorf("drill: firing alerts: %w", err)
	}
	return nil
}

// -----------------------------------------------------------------------------
// Situation discovery, snapshot, and payoff rendering
// -----------------------------------------------------------------------------

// situationSnapshot is the drill's flattened view of one alertint_situation_get
// response — exactly the fields the payoff print, the recovery poll, and the
// rerun-linkage check consume.
type situationSnapshot struct {
	ID                        string
	PublicHandle              string
	GroupKey                  string
	Lifecycle                 string
	Attention                 string
	Drill                     bool
	TerminalBanner            string
	PreviousSituationID       *string
	NextActor                 string
	ActionStatus              string
	OperatorActionRequired    string
	OperatorJudgmentRequested string
	WaitReason                string
	Incidents                 []situationMemberIncident
	Notifications             []situationNotificationRow
}

// situationMemberIncident is one Situation member's L1 acute-analysis gate
// state — evidence, reported independent of the Situation payoff above it.
type situationMemberIncident struct {
	ID                 string
	AcuteFindingStatus string
	AcuteFindingReason string
}

type situationNotificationRow struct {
	Kind            string
	MainChannelPoke bool
	Status          string
}

// decodeSituationSnapshot unmarshals one alertint_situation_get response into
// a situationSnapshot.
func decodeSituationSnapshot(raw json.RawMessage) (situationSnapshot, error) {
	var payload struct {
		TerminalBanner    string `json:"terminal_banner"`
		ID                string `json:"id"`
		PreviousSituation *struct {
			ID string `json:"id"`
		} `json:"previous_situation"`
		GroupKey     string  `json:"group_key"`
		PublicHandle *string `json:"public_handle"`
		Lifecycle    string  `json:"lifecycle"`
		Attention    string  `json:"attention"`
		Drill        bool    `json:"drill"`
		Incidents    []struct {
			ID                 string `json:"id"`
			AcuteFindingStatus string `json:"acute_finding_status"`
			AcuteFindingReason string `json:"acute_finding_reason"`
		} `json:"incidents"`
		CurrentAssessment *struct {
			ActionContract struct {
				NextActor                 string `json:"next_actor"`
				ActionStatus              string `json:"action_status"`
				OperatorActionRequired    string `json:"operator_action_required"`
				OperatorJudgmentRequested string `json:"operator_judgment_requested"`
				WaitReason                string `json:"wait_reason"`
			} `json:"action_contract"`
		} `json:"current_assessment"`
		Notifications []struct {
			Kind            string `json:"kind"`
			MainChannelPoke bool   `json:"main_channel_poke"`
			Status          string `json:"status"`
		} `json:"notifications"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return situationSnapshot{}, fmt.Errorf("drill: decode situation: %w", err)
	}
	snap := situationSnapshot{
		ID: payload.ID, GroupKey: payload.GroupKey, Lifecycle: payload.Lifecycle, Attention: payload.Attention,
		Drill: payload.Drill, TerminalBanner: payload.TerminalBanner,
	}
	if payload.PublicHandle != nil {
		snap.PublicHandle = *payload.PublicHandle
	}
	if payload.PreviousSituation != nil {
		id := payload.PreviousSituation.ID
		snap.PreviousSituationID = &id
	}
	if payload.CurrentAssessment != nil {
		ac := payload.CurrentAssessment.ActionContract
		snap.NextActor, snap.ActionStatus = ac.NextActor, ac.ActionStatus
		snap.OperatorActionRequired = ac.OperatorActionRequired
		snap.OperatorJudgmentRequested = ac.OperatorJudgmentRequested
		snap.WaitReason = ac.WaitReason
	}
	for _, m := range payload.Incidents {
		snap.Incidents = append(snap.Incidents, situationMemberIncident{
			ID: m.ID, AcuteFindingStatus: m.AcuteFindingStatus, AcuteFindingReason: m.AcuteFindingReason,
		})
	}
	for _, n := range payload.Notifications {
		snap.Notifications = append(snap.Notifications, situationNotificationRow{
			Kind: n.Kind, MainChannelPoke: n.MainChannelPoke, Status: n.Status,
		})
	}
	return snap, nil
}

func (d *drillCmd) getSituationSnapshot(ctx context.Context, client *mcpOneShotClient, id string) (situationSnapshot, error) {
	raw, err := client.callTool(ctx, "alertint_situation_get", map[string]any{"situation": id})
	if err != nil {
		return situationSnapshot{}, err
	}
	return decodeSituationSnapshot(raw)
}

// findSituationByGroupKey matches the run's salted group key on the
// Situation list. limit 200: most-recently-updated first, and a busy
// instance must not page the drill out. When the exact key is absent (local
// config drifted from the target's), it falls back to the newest Situation
// whose group key still looks like a drill's and reports drifted=true.
func (d *drillCmd) findSituationByGroupKey(ctx context.Context, client *mcpOneShotClient, groupKey string) (id string, drifted bool, err error) {
	raw, err := client.callTool(ctx, "alertint_situation_list", map[string]any{"limit": 200})
	if err != nil {
		return "", false, err
	}
	var payload struct {
		Situations []struct {
			ID       string `json:"id"`
			GroupKey string `json:"group_key"`
		} `json:"situations"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", false, fmt.Errorf("drill: decode situation list: %w", err)
	}
	for _, s := range payload.Situations {
		if s.GroupKey == groupKey {
			return s.ID, false, nil
		}
	}
	for _, s := range payload.Situations {
		if looksLikeDrillGroupKey(s.GroupKey, d.cfg.Correlator.GroupLabels) {
			return s.ID, true, nil
		}
	}
	return "", false, nil
}

// fetchDrillCandidates lists the target's Situations over MCP and distills
// them to the fields the rerun-salt matcher needs. Best-effort: any error
// means "no candidates" (mint a fresh salt), never a failed drill.
func (d *drillCmd) fetchDrillCandidates(ctx context.Context, mcpEndpoint, mcpToken string) ([]drillSituationCandidate, error) {
	client := newMCPOneShotClient(mcpEndpoint, mcpToken, d.http)
	if err := client.initialize(ctx); err != nil {
		return nil, err
	}
	raw, err := client.callTool(ctx, "alertint_situation_list", map[string]any{"limit": 200})
	if err != nil {
		return nil, err
	}
	var payload struct {
		Situations []struct {
			ID                  string    `json:"id"`
			PreviousSituationID *string   `json:"previous_situation_id"`
			GroupKey            string    `json:"group_key"`
			Lifecycle           string    `json:"lifecycle"`
			UpdatedAt           time.Time `json:"updated_at"`
		} `json:"situations"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("drill: decode situation list: %w", err)
	}
	out := make([]drillSituationCandidate, 0, len(payload.Situations))
	for _, s := range payload.Situations {
		out = append(out, drillSituationCandidate{
			ID: s.ID, GroupKey: s.GroupKey, Lifecycle: s.Lifecycle,
			PreviousSituationID: s.PreviousSituationID, UpdatedAt: s.UpdatedAt,
		})
	}
	return out, nil
}

// fetchSituationPayoff is the post-window payoff: initialize, then poll the
// Situation list until the owning Situation appears (or the grace runs out),
// fetch its full detail, and print it. Every published nonterminal Situation
// is reported as-is — a silent non-critical run is not a failure, it is the
// controller correctly keeping Slack quiet.
func (d *drillCmd) fetchSituationPayoff(ctx context.Context, mcpEndpoint, mcpToken, groupKey string) (situationSnapshot, bool, error) {
	client := newMCPOneShotClient(mcpEndpoint, mcpToken, d.http)
	if err := client.initialize(ctx); err != nil {
		d.printf("warning: could not reach MCP at %s: %v", mcpEndpoint, err)
		d.printSlackFallback(groupKey)
		return situationSnapshot{}, false, nil
	}
	polls := int(d.grace / drillPollInterval)
	var id string
	var drifted bool
	for attempt := 0; ; attempt++ {
		var err error
		id, drifted, err = d.findSituationByGroupKey(ctx, client, groupKey)
		if err != nil {
			d.printf("warning: could not list situations: %v", err)
			d.printSlackFallback(groupKey)
			return situationSnapshot{}, false, nil
		}
		if id != "" {
			break
		}
		if attempt >= polls {
			d.printf("no Situation for group %s yet — the window may still be collecting.", groupKey)
			d.printSlackFallback(groupKey)
			return situationSnapshot{}, false, nil
		}
		if err := d.sleep(ctx, drillPollInterval); err != nil {
			return situationSnapshot{}, false, err
		}
	}
	if drifted {
		d.printDrift(groupKey)
	}
	snap, err := d.getSituationSnapshot(ctx, client, id)
	if err != nil {
		d.printf("warning: could not fetch situation %s: %v", id, err)
		return situationSnapshot{}, false, nil
	}
	d.printSituationPayoff(snap)
	return snap, true, nil
}

// pollRerunOutcome polls for the Situation owning the reused group key and
// classifies the outcome: a collapse into the same prior Situation (no new
// Situation minted — a plain rerun during recovery grace), or a fresh
// Situation correctly linked to a terminal prior through
// previous_situation_id (spec: "a rerun after terminal recovery creates a
// new linked Drill Situation"). It returns the observed Situation id, or ""
// on timeout.
func (d *drillCmd) pollRerunOutcome(ctx context.Context, mcpEndpoint, mcpToken, groupKey, priorID, priorLifecycle string) string {
	client := newMCPOneShotClient(mcpEndpoint, mcpToken, d.http)
	if err := client.initialize(ctx); err != nil {
		d.printf("warning: could not reach MCP to confirm the rerun outcome: %v", err)
		return ""
	}
	d.printf("rerun fired; polling for the owning Situation (up to %ds)…", int(d.grace.Seconds()))
	polls := int(d.grace / drillPollInterval)
	if polls < 1 {
		polls = 1
	}
	prior := drillSituation(priorID, priorLifecycle, "")
	for i := 0; i < polls; i++ {
		id, _, err := d.findSituationByGroupKey(ctx, client, groupKey)
		if err == nil && id != "" {
			if snap, gerr := d.getSituationSnapshot(ctx, client, id); gerr == nil {
				switch {
				case id == priorID:
					d.printf("%s", d.style("1;92", fmt.Sprintf("collapsed: situation %s absorbed the rerun — lifecycle=%s attention=%s (no new Situation minted)", situationTarget(snap), snap.Lifecycle, snap.Attention)))
					return id
				case isNewLinkedDrill(prior, drillSituation(id, snap.Lifecycle, stringOrEmpty(snap.PreviousSituationID))):
					d.printf("%s", d.style("1;92", fmt.Sprintf("new linked situation: %s links back to the terminal %s via previous_situation_id — lifecycle=%s attention=%s", situationTarget(snap), priorID, snap.Lifecycle, snap.Attention)))
					return id
				}
			}
		}
		if i < polls-1 {
			if err := d.sleep(ctx, drillPollInterval); err != nil {
				return ""
			}
		}
	}
	d.printf("the rerun has not settled yet; check the Situation card, or re-run with --result %s", priorID)
	return ""
}

// printSituationPayoff prints the Situation as the payoff: handle,
// lifecycle/Attention, the operator contract, and the notification outcome,
// then — independently, never gating the payoff above — each member
// Incident's L1 acute-analysis gate state.
func (d *drillCmd) printSituationPayoff(snap situationSnapshot) {
	d.printf("")
	d.printPhase("finding")
	if snap.Drill {
		d.printf("%s", d.style("1;35", fmt.Sprintf("🧪 DRILL — synthetic Situation (%s=%s)", store.DrillMarkerLabel, store.DrillMarkerValue)))
	}
	if snap.TerminalBanner != "" {
		d.printf("%s", d.style("1;33", sanitizeTerm(snap.TerminalBanner)))
	}
	handle := "(not yet published — Situation is still silent)"
	if snap.PublicHandle != "" {
		handle = snap.PublicHandle
	}
	d.printf("%s", d.style("1", "handle: "+sanitizeTerm(handle)))
	d.printf("lifecycle: %s · attention: %s", snap.Lifecycle, snap.Attention)
	d.printf("%s", d.style("2", operatorContractLine(snap)))
	d.printf("%s", notificationOutcomeLine(snap))
	if len(snap.Incidents) == 0 {
		d.printf("L1 gate: no member incidents yet")
	} else {
		d.printf("L1 gate (evidence, independent of the Situation payoff above):")
		for _, m := range snap.Incidents {
			line := fmt.Sprintf("  • %s: %s", m.ID, m.AcuteFindingStatus)
			if m.AcuteFindingReason != "" {
				line += " (" + sanitizeTerm(m.AcuteFindingReason) + ")"
			}
			d.printf("%s", line)
		}
	}
	if d.cfg.Notify.Slack.Enabled && snap.PublicHandle != "" {
		d.printf("%s", d.style("36", "slack: the Situation card is in "+d.cfg.Notify.Slack.Channel))
	}
	d.printf("")
	d.printPhase("investigate")
	d.printf("in your MCP-connected agent, run:")
	d.printf("%s", d.style("1;34", "  investigate situation "+sanitizeTerm(situationTarget(snap))+" using alertint"))
}

// situationTarget picks the identifier to hand to an operator or agent: the
// public handle once published, the raw id while still silent.
func situationTarget(snap situationSnapshot) string {
	if snap.PublicHandle != "" {
		return snap.PublicHandle
	}
	return snap.ID
}

// operatorContractLine renders the Situation's current action contract —
// who acts next and why — from its current Assessment.
func operatorContractLine(snap situationSnapshot) string {
	parts := []string{"next_actor=" + orDefault(snap.NextActor, "unknown"), "action_status=" + orDefault(snap.ActionStatus, "unknown")}
	if snap.OperatorActionRequired != "" {
		parts = append(parts, "operator_action_required="+sanitizeTerm(snap.OperatorActionRequired))
	}
	if snap.OperatorJudgmentRequested != "" {
		parts = append(parts, "operator_judgment_requested="+sanitizeTerm(snap.OperatorJudgmentRequested))
	}
	if snap.WaitReason != "" {
		parts = append(parts, "wait_reason="+sanitizeTerm(snap.WaitReason))
	}
	return "operator contract: " + strings.Join(parts, " · ")
}

// notificationOutcomeLine summarizes the Situation's most recent
// main-channel-poke notification. No such notification is not a failure —
// it is the controller honestly reporting a silent, non-critical Situation.
func notificationOutcomeLine(snap situationSnapshot) string {
	var last *situationNotificationRow
	for i := range snap.Notifications {
		if snap.Notifications[i].MainChannelPoke {
			last = &snap.Notifications[i]
		}
	}
	if last == nil {
		return "notification: Situation created; controller kept Slack quiet"
	}
	switch last.Status {
	case "delivered":
		return fmt.Sprintf("notification: published to Slack (%s)", last.Kind)
	case "withheld_by_operator_slack_floor":
		return fmt.Sprintf("notification: withheld by the operator Slack floor (%s)", last.Kind)
	case "pending":
		return fmt.Sprintf("notification: queued for delivery (%s)", last.Kind)
	case "failed":
		return fmt.Sprintf("notification: delivery failed (%s) — check serve logs", last.Kind)
	default:
		return fmt.Sprintf("notification: %s (%s)", last.Status, last.Kind)
	}
}

// looksLikeDrillGroupKey reports whether a group key's salted label carries
// the canned drill prefix — the drift-fallback's safety net when no exact
// key match exists, without needing a Drill boolean on the Situation list
// row (that view carries none; only alertint_situation_get does).
func looksLikeDrillGroupKey(gk string, groupLabels []string) bool {
	labels := parseGroupKey(gk)
	saltedKey := firstGroupLabel(effectiveDrillGroupLabels(groupLabels))
	if saltedKey == "" {
		return false
	}
	v, ok := labels[saltedKey]
	return ok && strings.HasPrefix(v, cannedGroupValue(saltedKey)+"-")
}

func (d *drillCmd) printDrift(groupKey string) {
	d.printf("note: no Situation matched group %s — the target's group_labels likely differ", groupKey)
	d.printf("      from this config file (config drift). Showing the newest drill Situation instead.")
}

func (d *drillCmd) printSlackFallback(groupKey string) {
	if d.cfg.Notify.Slack.Enabled {
		d.printf("check Slack channel %s for the Situation card (group %s).", d.cfg.Notify.Slack.Channel, groupKey)
	} else {
		d.printf("check the Situation stdout line in serve logs (group %s).", groupKey)
	}
}

func stringOrEmpty(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// ---------------------------------------------------------------------------
// Endpoint derivation and guards
// ---------------------------------------------------------------------------

// receiverBase resolves where the webhooks go: --target verbatim, otherwise
// the local instance on the port from receivers.address.
func (d *drillCmd) receiverBase() (string, error) {
	if d.opts.target != "" {
		u, err := url.Parse(d.opts.target)
		if err != nil || u.Scheme == "" || u.Host == "" {
			return "", fmt.Errorf("drill: --target must be a base URL like https://alertint.example:9911 (got %q)", d.opts.target)
		}
		return strings.TrimRight(d.opts.target, "/"), nil
	}
	port, err := portOf(d.cfg.Receivers.Address)
	if err != nil {
		return "", fmt.Errorf("drill: receivers.address: %w", err)
	}
	return "http://127.0.0.1:" + port, nil
}

// targetSchemeHost resolves the scheme/host every derived endpoint (MCP)
// shares with the fire target: --target's when set, loopback otherwise.
func (d *drillCmd) targetSchemeHost() (scheme, host string) {
	scheme, host = "http", "127.0.0.1"
	if d.opts.target != "" {
		if u, err := url.Parse(d.opts.target); err == nil && u.Hostname() != "" {
			scheme, host = u.Scheme, u.Hostname()
		}
	}
	return scheme, host
}

// mcpEndpoint resolves the MCP URL from config, keeping the --target host
// (and scheme) when firing remotely: MCP listens on its own port next to the
// receivers.
func (d *drillCmd) mcpEndpoint() (endpoint, token string, err error) {
	if !d.cfg.MCPEnabled() {
		return "", "", nil
	}
	token, err = d.cfg.MCPToken()
	if err != nil {
		return "", "", err
	}
	port, err := portOf(d.cfg.MCP.Addr)
	if err != nil {
		return "", "", fmt.Errorf("drill: mcp.addr: %w", err)
	}
	scheme, host := d.targetSchemeHost()
	return fmt.Sprintf("%s://%s/mcp", scheme, net.JoinHostPort(host, port)), token, nil
}

// guardInsecureTransport refuses to attach a bearer token to a plain-HTTP
// request leaving the machine, unless explicitly overridden. Applies to every
// token-carrying path, including --result's MCP fetch.
func (d *drillCmd) guardInsecureTransport(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("drill: parse target: %w", err)
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	if u.Scheme != "https" && !d.opts.allowInsecure {
		return fmt.Errorf("drill: %s is remote and plain http — bearer tokens would travel unencrypted; pass --allow-insecure-http to override", rawURL)
	}
	return nil
}

// guardRemote enforces the ADR-0014 guards before anything is sent: an
// explicit confirmation for non-loopback targets and an explicit override
// before anything travels over plain HTTP.
func (d *drillCmd) guardRemote(base string, alertCount int) error {
	if err := d.guardInsecureTransport(base); err != nil {
		return err
	}
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("drill: parse target: %w", err)
	}
	if isLoopbackHost(u.Hostname()) || d.opts.yes {
		return nil
	}
	ok, err := d.confirm(fmt.Sprintf("fire %d synthetic alerts at %s? [y/N] ", alertCount, base))
	if err != nil {
		return fmt.Errorf("drill: remote target needs confirmation (pass --yes in non-interactive runs): %w", err)
	}
	if !ok {
		return fmt.Errorf("drill: aborted by user")
	}
	return nil
}

func (d *drillCmd) targetFlagSuffix() string {
	if d.opts.target == "" {
		return ""
	}
	return " --target " + d.opts.target
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------

// postJSON fires one webhook POST. The receivers answer 204 on success and
// never 5xx for ingest errors, so anything else is reported to the user as a
// warning by callers rather than trusted as pipeline truth.
func (d *drillCmd) postJSON(ctx context.Context, url, token string, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("http %d: %s", resp.StatusCode, snippet(raw))
	}
	return nil
}

// amPostableAlert is Alertmanager's v2 postable alert: no fingerprint or
// status fields (AM derives both — an endsAt in the past marks the alert
// resolved), so run-uniqueness in --via-alertmanager mode rides entirely on
// the salted labels.
type amPostableAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	EndsAt      *time.Time        `json:"endsAt,omitempty"`
}

func (d *drillCmd) postAlertmanagerV2(ctx context.Context, payload ingress.AlertmanagerPayload) error {
	alerts := make([]amPostableAlert, 0, len(payload.Alerts))
	for _, a := range payload.Alerts {
		pa := amPostableAlert{Labels: a.Labels, Annotations: a.Annotations, StartsAt: a.StartsAt}
		if !a.EndsAt.IsZero() {
			t := a.EndsAt
			pa.EndsAt = &t
		}
		alerts = append(alerts, pa)
	}
	base := strings.TrimRight(d.opts.viaAlertmanager, "/")
	return d.postJSON(ctx, base+"/api/v2/alerts", "", alerts)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

func (d *drillCmd) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(d.stdout, format+"\n", args...)
}

func (d *drillCmd) printPhase(phase string) {
	var line, color string
	switch phase {
	case "fire":
		line, color = "── fire ────────────────────────────────────────────", "33"
	case "correlate":
		line, color = "── correlate ───────────────────────────────────────", "36"
	case "finding":
		line, color = "── finding ─────────────────────────────────────────", "32"
	case "investigate":
		line, color = "── investigate ─────────────────────────────────────", "34"
	case "resolve":
		line, color = "── resolve ─────────────────────────────────────────", "92"
	default:
		line = "── " + phase
	}
	if d.color && color != "" {
		line = "\x1b[1;" + color + "m" + line + "\x1b[0m"
	}
	d.printf("%s", line)
}

func (d *drillCmd) style(code, text string) string {
	if !d.color {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func portOf(addr string) (string, error) {
	_, port, err := net.SplitHostPort(strings.TrimSpace(addr))
	if err != nil {
		return "", fmt.Errorf("cannot derive port from %q: %w", addr, err)
	}
	if port == "" {
		return "", fmt.Errorf("no port in %q", addr)
	}
	return port, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return def
}

// sanitizeTerm strips C0/C1 control characters (keeping \n and \t) from text
// printed to the terminal, so annotation- or model-sourced strings cannot
// smuggle escape sequences.
func sanitizeTerm(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' {
			return r
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return -1
		}
		return r
	}, s)
}

func randomRunID() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a clock-derived id; uniqueness across runs is what
		// matters, not unpredictability.
		return fmt.Sprintf("%06x", time.Now().UnixNano()&0xffffff)
	}
	return hex.EncodeToString(b[:])
}

// readPromptLine echoes prompt to stderr, then reads one line from stdin —
// shared by stdinConfirm and stdinPause so the prompt never mixes into stdout.
func readPromptLine(stderr io.Writer, prompt string) (string, error) {
	_, _ = fmt.Fprint(stderr, prompt)
	return bufio.NewReader(os.Stdin).ReadString('\n')
}

// stdinConfirm reads one y/N line from stdin, echoing the prompt to stderr so
// it never mixes into stdout output.
func stdinConfirm(stderr io.Writer) func(string) (bool, error) {
	return func(prompt string) (bool, error) {
		line, err := readPromptLine(stderr, prompt)
		if err != nil {
			return false, err
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "y" || answer == "yes", nil
	}
}

// stdinPause blocks until Enter (or stdin error), echoing the prompt to
// stderr so it never mixes into stdout output.
func stdinPause(stderr io.Writer) func(string) error {
	return func(prompt string) error {
		_, err := readPromptLine(stderr, prompt)
		return err
	}
}
