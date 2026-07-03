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
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/ingress"
	"github.com/alertint/alertint-agent/internal/store"
	"github.com/alertint/alertint-agent/skills/acutetriage"
)

// drillHTTPTimeout bounds every drill-side HTTP call. Explicit and non-zero:
// a zero deadline would expire every request.
const drillHTTPTimeout = 15 * time.Second

// drillTriageGrace is the bounded LLM-triage budget added on top of the
// correlation window: the drill polls for the finding until it is ready or
// this budget runs out.
const drillTriageGrace = 75 * time.Second

// drillPollInterval paces the post-window finding polls. Each poll is one
// cheap MCP list call; the run ends as soon as triage does instead of
// sleeping out the full grace.
const drillPollInterval = 5 * time.Second

// drillOpts are the parsed `alertint drill` flags.
type drillOpts struct {
	cfgPath         string
	target          string
	scenario        string
	result          string
	yes             bool
	allowInsecure   bool
	resolve         bool
	viaAlertmanager string
}

// drillCmd carries the flow's dependencies; tests replace the injectable ones.
type drillCmd struct {
	cfg    *config.Config
	opts   drillOpts
	stdout io.Writer

	http     *http.Client
	now      func() time.Time
	sleep    func(context.Context, time.Duration) error
	confirm  func(prompt string) (bool, error)
	newRunID func() string
	grace    time.Duration
	// probePrometheus reports whether something answers on :9090 next to the
	// target — a heuristic that only shapes one hint line.
	probePrometheus func(scheme, host string) bool
}

func runDrill(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("alertint drill", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var opts drillOpts
	fs.StringVar(&opts.cfgPath, "config", "", "path to alertint YAML config (the same file serve reads)")
	fs.StringVar(&opts.target, "target", "", "base URL of a remote AlertINT instance (default: the local instance from config)")
	fs.StringVar(&opts.scenario, "scenario", "flagship", "scenario to fire: flagship | storm")
	fs.StringVar(&opts.result, "result", "", "skip firing; fetch and print the finding for an incident id")
	fs.BoolVar(&opts.yes, "yes", false, "skip the remote-target confirmation prompt")
	fs.BoolVar(&opts.resolve, "resolve", false, "after the run, re-send the burst as resolved so the drill incident closes")
	fs.BoolVar(&opts.allowInsecure, "allow-insecure-http", false, "allow sending bearer tokens to a plain-http remote target")
	fs.StringVar(&opts.viaAlertmanager, "via-alertmanager", "", "fire the burst through your Alertmanager (base URL, v2 API) to validate AM→AlertINT routing")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if opts.cfgPath == "" {
		return fmt.Errorf("drill: --config is required (the same config file serve reads)")
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
		confirm:         stdinConfirm(stderr),
		newRunID:        randomRunID,
		grace:           drillTriageGrace,
		probePrometheus: probePrometheusDefault,
	}
	return d.run(context.Background())
}

func (d *drillCmd) run(ctx context.Context) error {
	mcpEndpoint, mcpToken, mcpErr := d.mcpEndpoint()

	if d.opts.result != "" && d.opts.resolve {
		return fmt.Errorf("drill: --resolve applies to a firing run, not --result (re-run the drill with --resolve instead)")
	}

	// --result: the re-check path. One fetch, one print, done. The transport
	// guard applies here too — this path carries the MCP bearer token.
	if d.opts.result != "" {
		if !d.cfg.MCP.Enabled {
			return fmt.Errorf("drill: --result needs mcp.enabled: true in the target config")
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
		return d.fetchAndPrintIncident(ctx, client, d.opts.result, capHintNone, true)
	}

	sc, ok := drillScenarios()[d.opts.scenario]
	if !ok {
		return fmt.Errorf("drill: unknown scenario %q (have: flagship, storm)", d.opts.scenario)
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
	mcpAvailable, capHint := d.printPreflights(sc, mcpErr)

	run, err := materializeScenario(sc, d.cfg.Correlator.GroupLabels, d.newRunID(), d.now())
	if err != nil {
		return err
	}

	capHint, err = d.fire(ctx, sc, run, recvBase, webhookToken, capHint)
	if err != nil {
		return err
	}

	// Wait out the correlation window — a server-side property of the
	// target's correlator (tune correlator.window_seconds to shorten it) —
	// then poll for the finding during the bounded triage grace so the run
	// ends as soon as triage does.
	window := time.Duration(d.cfg.Correlator.WindowSeconds)*time.Second + correlator.DefaultTickInterval
	d.printf("waiting ~%ds for the correlation window…", int(window.Seconds()))
	if err := d.sleep(ctx, window); err != nil {
		return err
	}

	if !mcpAvailable {
		// Nothing to poll without MCP: give triage its grace blind, then
		// point at the surfaces that can show the finding.
		d.printf("window closed; giving the LLM triage up to %ds…", int(d.grace.Seconds()))
		if err := d.sleep(ctx, d.grace); err != nil {
			return err
		}
		d.printf("")
		d.printf("fired. mcp is not usable from here, so the finding cannot be fetched — check:")
		if d.cfg.Notify.Slack.Enabled {
			d.printf("  · the DRILL card in Slack channel %s", d.cfg.Notify.Slack.Channel)
		}
		d.printf("  · the `finding` summary line in serve logs (group %s)", run.expectedGroupKey)
		d.printf("then hand the incident to your agent: investigate the latest drill incident using alertint")
		return d.maybeResolve(ctx, run, recvBase, webhookToken)
	}
	d.printf("window closed; polling for the finding (up to %ds)…", int(d.grace.Seconds()))
	if err := d.fetchPayoff(ctx, mcpEndpoint, mcpToken, run.expectedGroupKey, capHint); err != nil {
		return err
	}
	return d.maybeResolve(ctx, run, recvBase, webhookToken)
}

// maybeResolve fires the run's burst again as resolved when --resolve is set:
// same door, same token, same fingerprints — the instance closes the Drill
// through the production resolution path (Slack cards update in place).
// Warn-and-continue: the payoff has already been delivered, and a failed
// resolution just leaves a firing Drill.
func (d *drillCmd) maybeResolve(ctx context.Context, run drillRun, recvBase, webhookToken string) error {
	if !d.opts.resolve {
		return nil
	}
	payload := resolvedPayload(run, d.now())
	if d.opts.viaAlertmanager != "" {
		d.printf("resolving the drill via your Alertmanager (delivery rides AM's group_interval)…")
		if err := d.postAlertmanagerV2(ctx, payload); err != nil {
			d.printf("warning: alertmanager rejected the resolution: %v — the drill incident stays firing", err)
		}
		return nil
	}
	d.printf("resolving the drill: %d resolved alerts (group %s)", len(payload.Alerts), run.expectedGroupKey)
	if err := d.postJSON(ctx, recvBase+"/webhook/alertmanager", webhookToken, payload); err != nil {
		d.printf("warning: resolution not accepted: %v — the drill incident stays firing", err)
	}
	return nil
}

// printPreflights emits the notify-and-continue setup notes and resolves the
// capped-hint kind for this run.
func (d *drillCmd) printPreflights(sc drillScenario, mcpErr error) (mcpAvailable bool, capHint capHintKind) {
	mcpAvailable = d.cfg.MCP.Enabled && mcpErr == nil
	if d.cfg.MCP.Enabled && mcpErr != nil {
		d.printf("note: mcp is enabled but not usable from here (%v) — the drill will fire, but", mcpErr)
		d.printf("      cannot fetch the finding when it is ready; fix the token/addr and use --result.")
	}
	// The capped-finding hint's first remedy depends on WHY the deploy is
	// missing: never attempted (ingress disabled) vs attempted and rejected.
	capHint = capHintProbe
	if sc.change != nil && !d.cfg.Changes.Ingress.Enabled {
		capHint = capHintEnableChanges
		d.printf("note: changes.ingress is disabled, so the planted deploy will be skipped and the finding stays at the metadata-only confidence cap.")
		d.printf("      enable it in %s and re-run for the causal, uncapped drill:", d.opts.cfgPath)
		d.printf("        changes:")
		d.printf("          ingress:")
		d.printf("            enabled: true")
		d.printf("            webhook_token_env: %s", orDefault(d.cfg.Changes.Ingress.WebhookTokenEnv, "ALERTINT_CHANGES_WEBHOOK_TOKEN"))
	}
	if !d.cfg.MCP.Enabled {
		d.printf("note: mcp is disabled, so the drill cannot fetch the finding when it is ready.")
		d.printf("      enable it to complete the loop:")
		d.printf("        mcp:")
		d.printf("          enabled: true")
		d.printf("          token_env: %s", orDefault(d.cfg.MCP.TokenEnv, "ALERTINT_MCP_TOKEN"))
	}
	return mcpAvailable, capHint
}

// fire POSTs the planted change event (when enabled) and the burst, returning
// the possibly-adjusted capped-hint kind (a rejected deploy changes the honest
// remedy).
func (d *drillCmd) fire(ctx context.Context, sc drillScenario, run drillRun, recvBase, webhookToken string, capHint capHintKind) (capHintKind, error) {
	if d.cfg.Changes.Ingress.Enabled && sc.change != nil {
		token, err := d.cfg.ChangesWebhookToken()
		if err != nil {
			return capHint, err
		}
		d.printf("planting change event: %s (%s ago)", run.change.Title, sc.change.occurredAgo)
		if err := d.postJSON(ctx, recvBase+"/webhook/change", token, run.change); err != nil {
			d.printf("warning: change event not accepted: %v — continuing without it", err)
			d.printf("         (check the %s env var; the finding will stay capped without the deploy)", orDefault(d.cfg.Changes.Ingress.WebhookTokenEnv, "ALERTINT_CHANGES_WEBHOOK_TOKEN"))
			capHint = capHintChangeRejected
		}
	}

	if d.opts.viaAlertmanager != "" {
		d.printf("firing %d drill alerts via your Alertmanager at %s", len(run.alerts.Alerts), d.opts.viaAlertmanager)
		d.printf("note: delivery now depends on your AM routing matching these labels (group %s)", run.expectedGroupKey)
		d.printf("      and on AM's group_wait/group_interval; if the fetch below comes up empty, re-check later.")
		if err := d.postAlertmanagerV2(ctx, run.alerts); err != nil {
			d.printf("warning: alertmanager rejected the burst: %v", err)
		}
		return capHint, nil
	}
	d.printf("firing %d drill alerts (scenario %s — %s; group %s)", len(run.alerts.Alerts), sc.key, sc.description, run.expectedGroupKey)
	if err := d.postJSON(ctx, recvBase+"/webhook/alertmanager", webhookToken, run.alerts); err != nil {
		return capHint, fmt.Errorf("drill: firing alerts: %w", err)
	}
	return capHint, nil
}

// fetchPayoff is the post-wait payoff: initialize, then poll the incident
// list until the finding is analyzed or the triage grace runs out, and print
// the finding (or the degraded pointer — never empty-handed). Polling is
// paced by d.sleep so the loop is deterministic under test clocks.
func (d *drillCmd) fetchPayoff(ctx context.Context, mcpEndpoint, mcpToken, groupKey string, capHint capHintKind) error {
	client := newMCPOneShotClient(mcpEndpoint, mcpToken, d.http)
	if err := client.initialize(ctx); err != nil {
		d.printf("warning: could not reach MCP at %s: %v", mcpEndpoint, err)
		d.printSlackFallback(groupKey)
		return nil
	}
	polls := int(d.grace / drillPollInterval)
	var incidentID, state string
	var drifted bool
	for attempt := 0; ; attempt++ {
		var err error
		incidentID, state, drifted, err = d.findIncident(ctx, client, groupKey)
		if err != nil {
			d.printf("warning: could not list incidents: %v", err)
			d.printSlackFallback(groupKey)
			return nil
		}
		if incidentID != "" && state == "analyzed" {
			break
		}
		if attempt >= polls {
			// Grace exhausted: report the honest state and the re-check.
			if incidentID == "" {
				d.printf("no incident for group %s yet — the window may still be collecting.", groupKey)
				d.printSlackFallback(groupKey)
				return nil
			}
			if drifted {
				d.printDrift(groupKey)
			}
			d.printNotReady(incidentID, state)
			return nil
		}
		if err := d.sleep(ctx, drillPollInterval); err != nil {
			return err
		}
	}
	if drifted {
		d.printDrift(groupKey)
	}
	return d.fetchAndPrintIncident(ctx, client, incidentID, capHint, false)
}

func (d *drillCmd) printDrift(groupKey string) {
	d.printf("note: no incident matched group %s — the target's group_labels likely differ", groupKey)
	d.printf("      from this config file (config drift). Showing the newest drill incident instead.")
}

// findIncident matches the run's salted group key on the incident list.
// limit 100: newest-first, and a busy instance must not page the drill out.
// When the exact key is absent (local config drifted from the target's), it
// falls back to the newest drill-flagged incident and reports drifted=true.
func (d *drillCmd) findIncident(ctx context.Context, client *mcpOneShotClient, groupKey string) (id, state string, drifted bool, err error) {
	raw, err := client.callTool(ctx, "alertint_list_incidents", map[string]any{"limit": 100})
	if err != nil {
		return "", "", false, err
	}
	var payload struct {
		Incidents []struct {
			ID       string `json:"id"`
			GroupKey string `json:"group_key"`
			Status   string `json:"status"`
			Drill    bool   `json:"drill"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", "", false, fmt.Errorf("drill: decode incident list: %w", err)
	}
	for _, inc := range payload.Incidents {
		if inc.GroupKey == groupKey {
			return inc.ID, inc.Status, false, nil
		}
	}
	for _, inc := range payload.Incidents {
		if inc.Drill {
			return inc.ID, inc.Status, true, nil
		}
	}
	return "", "", false, nil
}

// capHintKind steers the capped-finding hint's first remedy: the honest fix
// differs between "the deploy was never attempted" (ingress disabled), "it
// was attempted and rejected" (token problem), and "evidence sources are the
// remedy" (probe).
type capHintKind int

const (
	capHintNone capHintKind = iota
	capHintProbe
	capHintEnableChanges
	capHintChangeRejected
)

// fetchAndPrintIncident is the payoff: one alertint_get_incident call printed
// as a console finding card. strict makes fetch errors fatal (--result mode:
// a wrong incident id must not exit 0 while advising to re-run itself).
func (d *drillCmd) fetchAndPrintIncident(ctx context.Context, client *mcpOneShotClient, incidentID string, capHint capHintKind, strict bool) error {
	raw, err := client.callTool(ctx, "alertint_get_incident", map[string]any{"incident_id": incidentID})
	if err != nil {
		if strict {
			return fmt.Errorf("drill: fetch incident %s: %w", incidentID, err)
		}
		d.printf("warning: could not fetch incident %s: %v", incidentID, err)
		d.printNotReady(incidentID, "unknown")
		return nil
	}
	var inc struct {
		ID         string  `json:"id"`
		Status     string  `json:"status"`
		Confidence float64 `json:"confidence"`
		Finding    struct {
			AnalysisName        string   `json:"analysis_name"`
			OverallIssue        string   `json:"overall_issue"`
			CorrelationFindings []string `json:"correlation_findings"`
			Severity            string   `json:"severity"`
		} `json:"finding"`
		Alerts []struct {
			Labels map[string]string `json:"labels"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(raw, &inc); err != nil {
		return fmt.Errorf("drill: decode incident: %w", err)
	}
	if inc.Status != "analyzed" {
		d.printNotReady(inc.ID, inc.Status)
		return nil
	}

	drill := false
	for _, a := range inc.Alerts {
		if a.Labels[store.DrillMarkerLabel] == store.DrillMarkerValue {
			drill = true
			break
		}
	}

	d.printf("")
	d.printf("── finding ─────────────────────────────────────────")
	if drill {
		d.printf("🧪 DRILL — synthetic incident (%s=%s)", store.DrillMarkerLabel, store.DrillMarkerValue)
	}
	// LLM-derived text (and, via --result, text from ANY incident) prints to
	// the operator's terminal — strip control characters so annotation or
	// model output cannot smuggle escape sequences.
	d.printf("%s", sanitizeTerm(inc.Finding.AnalysisName))
	d.printf("%s", sanitizeTerm(inc.Finding.OverallIssue))
	for _, cf := range inc.Finding.CorrelationFindings {
		d.printf("  • %s", sanitizeTerm(cf))
	}
	d.printf("severity: %s · confidence: %.0f%%", sanitizeTerm(inc.Finding.Severity), inc.Confidence*100)
	d.printCappedHint(inc.Confidence, capHint)
	if d.cfg.Notify.Slack.Enabled {
		d.printf("slack: the DRILL card is in %s", d.cfg.Notify.Slack.Channel)
	}
	d.printf("")
	d.printf("next: open your MCP-connected agent and paste:")
	d.printf("  investigate incident %s using alertint", inc.ID)
	return nil
}

// printCappedHint explains the metadata-only confidence cap and the cheapest
// way to lift it. The Prometheus promise is scoped to REAL incidents: drill
// labels are fictional, so a Prometheus-connected drill re-run stays capped.
func (d *drillCmd) printCappedHint(confidence float64, kind capHintKind) {
	if kind == capHintNone || math.Abs(confidence-acutetriage.MaxMetadataOnlyConfidence) > 1e-9 {
		return
	}
	d.printf("")
	d.printf("this finding is capped at %.0f%%: the triage saw only alert metadata, no live evidence.", acutetriage.MaxMetadataOnlyConfidence*100)
	switch kind {
	case capHintEnableChanges:
		d.printf("cheapest lift: enable changes.ingress (see the note above) and re-run — the planted")
		d.printf("deploy counts as live evidence and produces the causal, uncapped drill finding.")
		return
	case capHintChangeRejected:
		d.printf("cheapest lift: the planted deploy was rejected at the change webhook (see the warning")
		d.printf("above — check the token env var), so the causal evidence never landed; fix and re-run.")
		return
	case capHintNone, capHintProbe:
		// fall through to the probe wording below
	}
	scheme, host := d.probeBase()
	if d.probePrometheus(scheme, host) {
		d.printf("for real incidents, connect Prometheus (something is answering on %s:9090 — you", host)
		d.printf("almost certainly run it next to Alertmanager): https://alertint.com/docs/integrations/prometheus")
	} else {
		d.printf("for real incidents, connect an evidence source (Prometheus first if you have it):")
		d.printf("https://alertint.com/docs/integrations/prometheus — or get in touch and we'll add your stack.")
	}
	d.printf("note: drill alerts carry fictional labels, so evidence sources cannot uncap a drill re-run.")
}

func (d *drillCmd) printNotReady(incidentID, state string) {
	d.printf("")
	d.printf("incident %s is not analyzed yet (state: %s).", incidentID, state)
	d.printf("re-check with:")
	d.printf("  alertint drill --config %s%s --result %s", d.opts.cfgPath, d.targetFlagSuffix(), incidentID)
}

func (d *drillCmd) printSlackFallback(groupKey string) {
	if d.cfg.Notify.Slack.Enabled {
		d.printf("check Slack channel %s for the DRILL card (group %s).", d.cfg.Notify.Slack.Channel, groupKey)
	} else {
		d.printf("check the `finding` summary line in serve logs (group %s).", groupKey)
	}
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

// targetSchemeHost resolves the scheme/host every derived endpoint (MCP,
// Prometheus probe) shares with the fire target: --target's when set,
// loopback otherwise.
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
	if !d.cfg.MCP.Enabled {
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

// probeBase picks where the Prometheus heuristic probe points.
func (d *drillCmd) probeBase() (scheme, host string) {
	return d.targetSchemeHost()
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

// stdinConfirm reads one y/N line from stdin, echoing the prompt to stderr so
// it never mixes into stdout output.
func stdinConfirm(stderr io.Writer) func(string) (bool, error) {
	return func(prompt string) (bool, error) {
		_, _ = fmt.Fprint(stderr, prompt)
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return false, err
		}
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "y" || answer == "yes", nil
	}
}

// probePrometheusDefault answers the ":9090 heuristic" with a short GET.
func probePrometheusDefault(scheme, host string) bool {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(fmt.Sprintf("%s://%s:9090/-/ready", scheme, host)) //nolint:noctx // one-shot CLI probe, hard 1.5s client timeout
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode < 500
}
