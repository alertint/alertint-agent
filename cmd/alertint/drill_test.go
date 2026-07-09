// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/ingress"
)

// fakeInstance emulates a running AlertINT: the two webhook receivers and a
// streamable-HTTP MCP endpoint (initialize + tools/call, format-only session
// check — the contract verified against mcp-go v0.54.1).
type fakeInstance struct {
	mu           sync.Mutex
	changeBodies [][]byte
	alertBodies  [][]byte
	authSeen     []string

	listRows      []map[string]any
	listRowsSeq   [][]map[string]any // consumed first, one per list call
	incident      map[string]any
	getIncidentID []string

	receiver *httptest.Server
	mcp      *httptest.Server
}

func newFakeInstance(t *testing.T) *fakeInstance {
	t.Helper()
	f := &fakeInstance{}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook/change", func(w http.ResponseWriter, r *http.Request) {
		f.record(r, &f.changeBodies)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /webhook/alertmanager", func(w http.ResponseWriter, r *http.Request) {
		f.record(r, &f.alertBodies)
		w.WriteHeader(http.StatusNoContent)
	})
	f.receiver = httptest.NewServer(mux)
	t.Cleanup(f.receiver.Close)

	f.mcp = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer mcp-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req struct {
			ID     int    `json:"id"`
			Method string `json:"method"`
			Params struct {
				Name      string         `json:"name"`
				Arguments map[string]any `json:"arguments"`
			} `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "mcp-session-11111111-2222-3333-4444-555555555555")
			writeRPC(w, req.ID, map[string]any{"protocolVersion": "2025-03-26"})
		case "tools/call":
			if r.Header.Get("Mcp-Session-Id") == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			f.mu.Lock()
			var payload any
			switch req.Params.Name {
			case "alertint_list_incidents":
				if len(f.listRowsSeq) > 0 {
					payload = map[string]any{"incidents": f.listRowsSeq[0]}
					f.listRowsSeq = f.listRowsSeq[1:]
				} else {
					payload = map[string]any{"incidents": f.listRows}
				}
			case "alertint_get_incident":
				id, _ := req.Params.Arguments["incident_id"].(string)
				f.getIncidentID = append(f.getIncidentID, id)
				payload = f.incident
			}
			f.mu.Unlock()
			text, _ := json.Marshal(payload)
			writeRPC(w, req.ID, map[string]any{
				"content": []map[string]any{{"type": "text", "text": string(text)}},
				"isError": false,
			})
		default:
			writeRPC(w, req.ID, map[string]any{})
		}
	}))
	t.Cleanup(f.mcp.Close)
	return f
}

func (f *fakeInstance) record(r *http.Request, into *[][]byte) {
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r.Body)
	f.mu.Lock()
	defer f.mu.Unlock()
	*into = append(*into, buf.Bytes())
	f.authSeen = append(f.authSeen, r.Header.Get("Authorization"))
}

func writeRPC(w http.ResponseWriter, id int, result any) {
	if err := json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result}); err != nil {
		panic(err)
	}
}

// drillTestCmd builds a drillCmd wired to the fakes with instant sleeps.
func drillTestCmd(t *testing.T, f *fakeInstance, cfg *config.Config, opts drillOpts) (*drillCmd, *bytes.Buffer) {
	t.Helper()
	if opts.target == "" && f != nil {
		opts.target = f.receiver.URL
	}
	if f != nil {
		u, err := url.Parse(f.mcp.URL)
		if err != nil {
			t.Fatal(err)
		}
		cfg.MCP.Addr = u.Host
	}
	var out bytes.Buffer
	d := &drillCmd{
		cfg:    cfg,
		opts:   opts,
		stdout: &out,
		http:   &http.Client{Timeout: 5 * time.Second},
		now:    func() time.Time { return time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC) },
		sleep:  func(context.Context, time.Duration) error { return nil },
		confirm: func(string) (bool, error) {
			t.Fatal("confirm must not fire for loopback targets")
			return false, nil
		},
		newRunID:        func() string { return "t3st01" },
		grace:           time.Second,
		probePrometheus: func(string, string) bool { return false },
	}
	return d, &out
}

// boolPtr returns a pointer to b, for setting the tri-state Enabled fields.
func boolPtr(b bool) *bool { return &b }

func drillTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Alertmanager.WebhookTokenEnv = "DEMO_TEST_WH"
	cfg.Changes.Ingress.Enabled = true
	cfg.Changes.Ingress.WebhookTokenEnv = "DEMO_TEST_CH"
	cfg.MCP.Enabled = boolPtr(true)
	cfg.MCP.TokenEnv = "DEMO_TEST_MCP"
	cfg.LLM.APIKeyEnv = "DEMO_TEST_LLM"
	t.Setenv("DEMO_TEST_WH", "wh-token")
	t.Setenv("DEMO_TEST_CH", "ch-token")
	t.Setenv("DEMO_TEST_MCP", "mcp-token")
	return &cfg
}

func analyzedIncident(id string) map[string]any {
	return map[string]any{
		"id": id, "status": "analyzed", "confidence": 0.9,
		"finding": map[string]any{
			"analysis_name":        "Drill checkout regression",
			"overall_issue":        "The v2.3.1 deploy broke the payment handler",
			"correlation_findings": []string{"burst started minutes after the deploy"},
			"severity":             "high",
		},
		"alerts": []map[string]any{{"labels": map[string]string{"alertint_drill": "true"}}},
	}
}

// TestDrill_HappyPath: change then burst then one-shot fetch; the console
// carries the finding and the full-id CTA.
func TestDrill_HappyPath(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	groupKey := "cluster=drill-cluster-t3st01,namespace=drill-shop,service=drill-checkout"
	f.listRows = []map[string]any{
		{"id": "other", "group_key": "x=y", "status": "analyzed"},
		{"id": "inc-42", "group_key": groupKey, "status": "analyzed"},
	}
	f.incident = analyzedIncident("inc-42")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.changeBodies) != 1 || len(f.alertBodies) != 1 {
		t.Fatalf("posts = %d change, %d alert; want 1, 1", len(f.changeBodies), len(f.alertBodies))
	}
	if got := f.authSeen[0]; got != "Bearer ch-token" {
		t.Errorf("change auth = %q", got)
	}
	if got := f.authSeen[1]; got != "Bearer wh-token" {
		t.Errorf("alert auth = %q", got)
	}
	var envelope struct {
		Version string `json:"version"`
		Alerts  []struct {
			Fingerprint string `json:"fingerprint"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(f.alertBodies[0], &envelope); err != nil || envelope.Version != "4" || len(envelope.Alerts) == 0 {
		t.Errorf("alert envelope invalid: %v %+v", err, envelope)
	}
	s := out.String()
	for _, want := range []string{
		"Drill checkout regression",
		"investigate incident inc-42 using alertint",
		"DRILL",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "capped at 60%") {
		t.Errorf("uncapped finding must not print the cap hint:\n%s", s)
	}
}

// TestDrill_ChangesDisabled: no change POST, enable lines printed, burst still
// fired, and the capped hint names enabling change ingress as first remedy.
func TestDrill_ChangesDisabled(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	cfg.Changes.Ingress.Enabled = false
	cfg.Changes.Ingress.WebhookTokenEnv = "" // realistic: disabled feature, no env named
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	groupKey := "cluster=drill-cluster-t3st01,namespace=drill-shop,service=drill-checkout"
	f.listRows = []map[string]any{{"id": "inc-7", "group_key": groupKey, "status": "analyzed"}}
	capped := analyzedIncident("inc-7")
	capped["confidence"] = 0.6
	f.incident = capped

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.changeBodies) != 0 {
		t.Errorf("change POST fired despite disabled ingress")
	}
	if len(f.alertBodies) != 1 {
		t.Errorf("burst not fired: %d posts", len(f.alertBodies))
	}
	s := out.String()
	for _, want := range []string{
		"changes.ingress is disabled",
		"webhook_token_env: ALERTINT_CHANGES_WEBHOOK_TOKEN",
		"capped at 60%",
		"enable changes.ingress",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
}

// TestDrill_MCPDisabled: fires, prints enable lines and the serve-log pointer,
// never touches MCP, exits 0.
func TestDrill_MCPDisabled(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	cfg.MCP.Enabled = boolPtr(false)
	cfg.MCP.TokenEnv = "" // realistic: disabled feature, no env named
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.alertBodies) != 1 {
		t.Errorf("burst not fired")
	}
	s := out.String()
	for _, want := range []string{"mcp is disabled", "mcp.enabled is false in cfg.yaml", "`finding` summary line in serve logs"} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
}

// TestDrill_MCPOffByAbsence: enabled omitted and no token in env — the hint
// points at the token env var, not at a config edit.
func TestDrill_MCPOffByAbsence(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	cfg.MCP.Enabled = nil
	cfg.MCP.TokenEnv = "DEMO_TEST_MCP_ABSENT" // never set in env
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	for _, want := range []string{"mcp is disabled", "set DEMO_TEST_MCP_ABSENT to a long random secret"} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
}

// TestDrill_NotAnalyzedYet: a slow triage prints id, state, and the exact
// --result re-check command — never empty-handed, exit 0.
func TestDrill_NotAnalyzedYet(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	groupKey := "cluster=drill-cluster-t3st01,namespace=drill-shop,service=drill-checkout"
	f.listRows = []map[string]any{{"id": "inc-9", "group_key": groupKey, "status": "processing"}}

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	for _, want := range []string{"state: processing", "--result inc-9"} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
}

// TestDrill_ResultMode: --result fetches exactly one incident, list-free.
func TestDrill_ResultMode(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", result: "inc-42"})
	f.incident = analyzedIncident("inc-42")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.alertBodies)+len(f.changeBodies) != 0 {
		t.Error("--result must not fire anything")
	}
	if len(f.getIncidentID) != 1 || f.getIncidentID[0] != "inc-42" {
		t.Errorf("get_incident calls = %v, want exactly [inc-42]", f.getIncidentID)
	}
	if !strings.Contains(out.String(), "investigate incident inc-42 using alertint") {
		t.Errorf("stdout missing CTA:\n%s", out.String())
	}
}

// TestDrill_RemoteGuards: remote targets refuse before any request leaves —
// plain HTTP needs the explicit override, https needs confirmation.
func TestDrill_RemoteGuards(t *testing.T) {
	cfg := drillTestConfig(t)

	t.Run("plain http refused without override", func(t *testing.T) {
		d, _ := drillTestCmd(t, nil, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: "http://alertint.example:9911"})
		err := d.run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "--allow-insecure-http") {
			t.Fatalf("run = %v, want insecure-http refusal", err)
		}
	})

	t.Run("https refused when confirmation declined", func(t *testing.T) {
		d, _ := drillTestCmd(t, nil, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: "https://alertint.example:9911"})
		d.confirm = func(string) (bool, error) { return false, nil }
		err := d.run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "aborted") {
			t.Fatalf("run = %v, want user abort", err)
		}
	})

	t.Run("https with --yes proceeds past the guard", func(t *testing.T) {
		d, _ := drillTestCmd(t, nil, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: "https://alertint.example:9911", yes: true})
		d.http = &http.Client{Timeout: 50 * time.Millisecond}
		err := d.run(context.Background())
		// The guard passes; the unreachable host then fails the fire step.
		if err == nil || strings.Contains(err.Error(), "confirmation") || strings.Contains(err.Error(), "--allow-insecure-http") {
			t.Fatalf("run = %v, want a network error past the guards", err)
		}
	})
}

// TestDrill_MCPUnreachable: a post-fire MCP failure degrades to the fallback
// pointer and exits 0 (never exits empty-handed after firing).
func TestDrill_MCPUnreachable(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
	t.Setenv("DEMO_TEST_MCP", "wrong-token") // 401 at initialize

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v (post-fire MCP failures must not error)", err)
	}
	s := out.String()
	if !strings.Contains(s, "could not reach MCP") || !strings.Contains(s, "serve logs") {
		t.Errorf("stdout missing degraded pointers:\n%s", s)
	}
}

// TestDrill_StormScenario: storm fires more alerts, no change event.
func TestDrill_StormScenario(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "storm"})
	f.listRows = []map[string]any{}

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.changeBodies) != 0 {
		t.Error("storm must not plant a change event")
	}
	var envelope struct {
		Alerts []json.RawMessage `json:"alerts"`
	}
	if err := json.Unmarshal(f.alertBodies[0], &envelope); err != nil || len(envelope.Alerts) < 10 {
		t.Errorf("storm burst too small: %d alerts (%v)", len(envelope.Alerts), err)
	}
}

// TestDrill_ViaAlertmanager: the burst goes to AM's v2 API (no fingerprint
// fields there); the change event still posts direct.
func TestDrill_ViaAlertmanager(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)

	var amBodies [][]byte
	var amMu sync.Mutex
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/alerts" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		amMu.Lock()
		amBodies = append(amBodies, buf.Bytes())
		amMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(am.Close)

	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", viaAlertmanager: am.URL})
	f.listRows = []map[string]any{}

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.changeBodies) != 1 {
		t.Error("change event must still post direct to AlertINT")
	}
	if len(f.alertBodies) != 0 {
		t.Error("burst must not hit AlertINT directly in --via-alertmanager mode")
	}
	amMu.Lock()
	defer amMu.Unlock()
	if len(amBodies) != 1 {
		t.Fatalf("AM posts = %d, want 1", len(amBodies))
	}
	var alerts []map[string]any
	if err := json.Unmarshal(amBodies[0], &alerts); err != nil || len(alerts) == 0 {
		t.Fatalf("AM payload not a postable-alert array: %v", err)
	}
	if _, has := alerts[0]["fingerprint"]; has {
		t.Error("AM postable alerts must not carry a fingerprint field")
	}
	if !strings.Contains(out.String(), "AM routing") && !strings.Contains(out.String(), "group_wait") {
		t.Errorf("missing AM routing hint:\n%s", out.String())
	}
}

func TestDrill_RequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"drill"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--config is required") {
		t.Fatalf("run = %v, want config-required error", err)
	}
}

func TestDrill_UnknownScenario(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "nope"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown scenario") {
		t.Fatalf("run = %v, want unknown-scenario error", err)
	}
}

// TestDrill_ResultModeInsecureRemote: --result carries the MCP bearer token,
// so a plain-HTTP remote target needs the explicit override too.
func TestDrill_ResultModeInsecureRemote(t *testing.T) {
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, nil, cfg, drillOpts{cfgPath: "cfg.yaml", result: "inc-1", target: "http://alertint.example:9911"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--allow-insecure-http") {
		t.Fatalf("run = %v, want insecure-http refusal before any token is sent", err)
	}
}

// TestDrill_ViaAlertmanagerRemoteGuard: the AM URL is a second remote write
// surface and gets the same guard as the receiver target.
func TestDrill_ViaAlertmanagerRemoteGuard(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", viaAlertmanager: "https://am.example:9093"})
	d.confirm = func(string) (bool, error) { return false, nil }
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("run = %v, want user abort on remote AM", err)
	}
	if len(f.alertBodies)+len(f.changeBodies) != 0 {
		t.Error("nothing may fire when the AM guard aborts")
	}
}

// TestDrill_ViaAlertmanagerNoEmptyAuthHeader: no Authorization header goes to
// the user's Alertmanager (no token is involved).
func TestDrill_ViaAlertmanagerNoEmptyAuthHeader(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	var sawAuth []string
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(am.Close)
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", viaAlertmanager: am.URL})
	f.listRows = []map[string]any{}
	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sawAuth) != 0 {
		t.Fatalf("Alertmanager received Authorization headers: %v", sawAuth)
	}
}

// TestDrill_MCPMisconfigPreflight: MCP enabled but token env unset must be
// reported before firing, and the run degrades instead of erroring after the
// full wait.
func TestDrill_MCPMisconfigPreflight(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	cfg.MCP.TokenEnv = "DEMO_TEST_MCP_UNSET"
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v (mcp misconfig must degrade, not fail)", err)
	}
	if len(f.alertBodies) != 1 {
		t.Error("burst must still fire")
	}
	s := out.String()
	if !strings.Contains(s, "mcp is enabled but not usable") || !strings.Contains(s, "--result") {
		t.Errorf("missing preflight note:\n%s", s)
	}
}

// TestDrill_ChangePostRejected: an attempted-but-rejected planted deploy warns
// with the token hint and steers the capped hint to the rejected wording.
func TestDrill_ChangePostRejected(t *testing.T) {
	cfg := drillTestConfig(t)
	f := newFakeInstance(t)

	rejecting := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/webhook/change" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		f.record(r, &f.alertBodies)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(rejecting.Close)

	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: rejecting.URL})
	groupKey := "cluster=drill-cluster-t3st01,namespace=drill-shop,service=drill-checkout"
	f.listRows = []map[string]any{{"id": "inc-8", "group_key": groupKey, "status": "analyzed"}}
	capped := analyzedIncident("inc-8")
	capped["confidence"] = 0.6
	f.incident = capped

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	for _, want := range []string{"change event not accepted", "check the DEMO_TEST_CH env var", "rejected at the change webhook"} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "enable changes.ingress") {
		t.Errorf("rejected-POST run must not advise enabling already-enabled ingress:\n%s", s)
	}
}

// TestDrill_DriftFallback: when no incident matches the locally-computed group
// key, the newest drill incident is used with a config-drift caveat.
func TestDrill_DriftFallback(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	f.listRows = []map[string]any{
		{"id": "real-1", "group_key": "service=checkout", "status": "analyzed", "drill": false},
		{"id": "drill-9", "group_key": "team=drill-team-x", "status": "analyzed", "drill": true},
	}
	f.incident = analyzedIncident("drill-9")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "config drift") || !strings.Contains(s, "investigate incident drill-9 using alertint") {
		t.Errorf("drift fallback missing:\n%s", s)
	}
}

// TestDrill_ResultUnknownIncident: --result with a bad id must error (exit 1),
// not print a hint recommending the same doomed command.
func TestDrill_ResultUnknownIncident(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	f.mcp.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "mcp-session-x")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"incident \"nope\" not found"}]}}`))
	})
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", result: "nope"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("run = %v, want fetch error surfaced", err)
	}
}

// TestDrill_CappedHintProbeWording: with change ingress on and fired, the
// Prometheus probe steers the wording between detected and docs-link
// variants; both stay scoped to real incidents.
func TestDrill_CappedHintProbeWording(t *testing.T) {
	for name, probe := range map[string]bool{"probe hit": true, "probe miss": false} {
		t.Run(name, func(t *testing.T) {
			f := newFakeInstance(t)
			cfg := drillTestConfig(t)
			d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
			d.probePrometheus = func(string, string) bool { return probe }

			groupKey := "cluster=drill-cluster-t3st01,namespace=drill-shop,service=drill-checkout"
			f.listRows = []map[string]any{{"id": "inc-c", "group_key": groupKey, "status": "analyzed"}}
			capped := analyzedIncident("inc-c")
			capped["confidence"] = 0.6
			f.incident = capped

			if err := d.run(context.Background()); err != nil {
				t.Fatalf("run: %v", err)
			}
			s := out.String()
			if probe && !strings.Contains(s, "something is answering") {
				t.Errorf("probe-hit wording missing:\n%s", s)
			}
			if !probe && !strings.Contains(s, "get in touch") {
				t.Errorf("probe-miss wording missing:\n%s", s)
			}
			if !strings.Contains(s, "cannot uncap a drill re-run") {
				t.Errorf("real-incident scoping missing:\n%s", s)
			}
		})
	}
}

// TestDrill_SanitizesFindingText: control characters in MCP-sourced strings
// never reach the terminal.
func TestDrill_SanitizesFindingText(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", result: "inc-evil"})
	evil := analyzedIncident("inc-evil")
	finding, ok := evil["finding"].(map[string]any)
	if !ok {
		t.Fatal("fixture finding is not a map")
	}
	finding["analysis_name"] = "evil\x1b[31mred\x07bell"
	f.incident = evil

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if strings.ContainsRune(s, '\x1b') || strings.ContainsRune(s, '\x07') {
		t.Fatalf("control characters leaked to terminal output: %q", s)
	}
	if !strings.Contains(s, "evil[31mredbell") {
		t.Errorf("sanitized text mangled: %q", s)
	}
}

// TestDrill_AlertmanagerReceiverDisabled: the drill cannot ingest its burst
// without the alert receiver — a pre-fire config error.
func TestDrill_AlertmanagerReceiverDisabled(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	cfg.Alertmanager.Enabled = false
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "alertmanager receiver is disabled") {
		t.Fatalf("run = %v, want receiver-disabled error", err)
	}
	if len(f.alertBodies)+len(f.changeBodies) != 0 {
		t.Error("nothing may fire without the alert receiver")
	}
}

// TestDrill_ConfirmErrorPath: a failed confirmation read (non-TTY) refuses
// with the --yes instruction.
func TestDrill_ConfirmErrorPath(t *testing.T) {
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, nil, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: "https://alertint.example:9911"})
	d.confirm = func(string) (bool, error) { return false, io.EOF }
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("run = %v, want non-interactive instruction", err)
	}
}

// TestDrill_PollsUntilAnalyzed: with a multi-poll grace, the payoff returns
// as soon as a poll sees the analyzed state instead of sleeping out the full
// triage grace.
func TestDrill_PollsUntilAnalyzed(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
	d.grace = 4 * drillPollInterval // budget for four polls

	var sleeps []time.Duration
	d.sleep = func(_ context.Context, dur time.Duration) error {
		sleeps = append(sleeps, dur)
		return nil
	}

	groupKey := "cluster=drill-cluster-t3st01,namespace=drill-shop,service=drill-checkout"
	pending := []map[string]any{{"id": "inc-7", "group_key": groupKey, "status": "ready"}}
	// [0] answers the pre-fire rerun scan (no drill candidate → fresh salt); the
	// next two answer the finding polls.
	f.listRowsSeq = [][]map[string]any{{}, pending, pending}
	f.listRows = []map[string]any{{"id": "inc-7", "group_key": groupKey, "status": "analyzed"}}
	f.incident = analyzedIncident("inc-7")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "investigate incident inc-7 using alertint") {
		t.Errorf("missing finding CTA:\n%s", out.String())
	}
	var polls int
	for _, dur := range sleeps {
		if dur == drillPollInterval {
			polls++
		}
	}
	if polls != 2 {
		t.Errorf("poll sleeps = %d, want 2 (loop must stop as soon as the state is analyzed)", polls)
	}
}

// TestDrill_RerunCollapses: a second drill inside the collapse window reuses the
// prior incident's group salt, so the fire lands as an occurrence — no second
// triage, no window wait — and the payoff reports "recurred ×2".
func TestDrill_RerunCollapses(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	groupKey := "cluster=drill-cluster-priorsalt,namespace=drill-shop,service=drill-checkout"
	// A prior drill of this scenario, judged, active 5m ago (inside the 30m window).
	f.listRows = []map[string]any{{
		"id": "inc-9", "group_key": groupKey, "status": "analyzed",
		"drill": true, "last_alert_at": "2026-07-03T11:55:00Z",
	}}
	// After the re-fire the incident carries one collapsed occurrence.
	f.incident = map[string]any{"id": "inc-9", "status": "analyzed", "occurrences": 1}

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "reusing its group key") {
		t.Errorf("expected a rerun-detected note:\n%s", s)
	}
	if !strings.Contains(s, "recurred ×2") {
		t.Errorf("expected the collapsed payoff recurred ×2:\n%s", s)
	}
	if strings.Contains(s, "waiting ~") {
		t.Errorf("a rerun must skip the correlation-window wait:\n%s", s)
	}
	if len(f.getIncidentID) == 0 || f.getIncidentID[len(f.getIncidentID)-1] != "inc-9" {
		t.Errorf("expected a get_incident poll on inc-9, got %v", f.getIncidentID)
	}
}

// TestDrill_ResolveFlag: --resolve re-sends the burst as resolved after the
// payoff — same fingerprints so the rows overwrite, endsAt set, payload
// status resolved.
func TestDrill_ResolveFlag(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", resolve: true})

	groupKey := "cluster=drill-cluster-t3st01,namespace=drill-shop,service=drill-checkout"
	f.listRows = []map[string]any{{"id": "inc-42", "group_key": groupKey, "status": "analyzed"}}
	f.incident = analyzedIncident("inc-42")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.alertBodies) != 2 {
		t.Fatalf("alert posts = %d, want 2 (burst + resolution)", len(f.alertBodies))
	}
	var firing, resolved ingress.AlertmanagerPayload
	if err := json.Unmarshal(f.alertBodies[0], &firing); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(f.alertBodies[1], &resolved); err != nil {
		t.Fatal(err)
	}
	if resolved.Status != "resolved" {
		t.Errorf("resolution payload status = %q, want resolved", resolved.Status)
	}
	if len(resolved.Alerts) != len(firing.Alerts) {
		t.Fatalf("resolution alerts = %d, want %d", len(resolved.Alerts), len(firing.Alerts))
	}
	for i, a := range resolved.Alerts {
		if a.Status != "resolved" {
			t.Errorf("alert %d status = %q, want resolved", i, a.Status)
		}
		if a.EndsAt.IsZero() {
			t.Errorf("alert %d endsAt is zero", i)
		}
		if a.Fingerprint != firing.Alerts[i].Fingerprint {
			t.Errorf("alert %d fingerprint changed: %q vs %q — resolution must reuse the firing fingerprints", i, a.Fingerprint, firing.Alerts[i].Fingerprint)
		}
	}
	if !strings.Contains(out.String(), "resolving the drill") {
		t.Errorf("stdout missing resolution note:\n%s", out.String())
	}
}

// TestDrill_ResolveWithResultRejected: --resolve needs a firing run.
func TestDrill_ResolveWithResultRejected(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", result: "inc-1", resolve: true})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--resolve applies to a firing run") {
		t.Fatalf("run = %v, want resolve/result conflict error", err)
	}
}

// TestDrill_ResolveViaAlertmanager: in --via-alertmanager mode the resolution
// goes through AM too, as postable alerts with endsAt set.
func TestDrill_ResolveViaAlertmanager(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)

	var amBodies [][]byte
	var amMu sync.Mutex
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(r.Body)
		amMu.Lock()
		amBodies = append(amBodies, buf.Bytes())
		amMu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(am.Close)

	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", viaAlertmanager: am.URL, resolve: true})
	f.listRows = []map[string]any{}

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	amMu.Lock()
	defer amMu.Unlock()
	if len(amBodies) != 2 {
		t.Fatalf("AM posts = %d, want 2 (burst + resolution)", len(amBodies))
	}
	var alerts []map[string]any
	if err := json.Unmarshal(amBodies[1], &alerts); err != nil || len(alerts) == 0 {
		t.Fatalf("resolution payload not a postable-alert array: %v", err)
	}
	for i, a := range alerts {
		if _, has := a["endsAt"]; !has {
			t.Errorf("resolution alert %d missing endsAt", i)
		}
	}
	var burst []map[string]any
	_ = json.Unmarshal(amBodies[0], &burst)
	for i, a := range burst {
		if _, has := a["endsAt"]; has {
			t.Errorf("firing alert %d must not carry endsAt", i)
		}
	}
}
