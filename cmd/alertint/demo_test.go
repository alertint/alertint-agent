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
				payload = map[string]any{"incidents": f.listRows}
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

// demoTestCmd builds a demoCmd wired to the fakes with instant sleeps.
func demoTestCmd(t *testing.T, f *fakeInstance, cfg *config.Config, opts demoOpts) (*demoCmd, *bytes.Buffer) {
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
	d := &demoCmd{
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

func demoTestConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg := config.Defaults()
	cfg.Alertmanager.WebhookTokenEnv = "DEMO_TEST_WH"
	cfg.Changes.Ingress.Enabled = true
	cfg.Changes.Ingress.WebhookTokenEnv = "DEMO_TEST_CH"
	cfg.MCP.Enabled = true
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
			"analysis_name":        "Demo checkout regression",
			"overall_issue":        "The v2.3.1 deploy broke the payment handler",
			"correlation_findings": []string{"burst started minutes after the deploy"},
			"severity":             "high",
		},
		"alerts": []map[string]any{{"labels": map[string]string{"alertint_demo": "true"}}},
	}
}

// TestDemo_HappyPath: change then burst then one-shot fetch; the console
// carries the finding and the full-id CTA.
func TestDemo_HappyPath(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	groupKey := "cluster=demo-cluster-t3st01,namespace=demo-shop,service=demo-checkout"
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
		"Demo checkout regression",
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

// TestDemo_ChangesDisabled: no change POST, enable lines printed, burst still
// fired, and the capped hint names enabling change ingress as first remedy.
func TestDemo_ChangesDisabled(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	cfg.Changes.Ingress.Enabled = false
	cfg.Changes.Ingress.WebhookTokenEnv = "" // realistic: disabled feature, no env named
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	groupKey := "cluster=demo-cluster-t3st01,namespace=demo-shop,service=demo-checkout"
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

// TestDemo_MCPDisabled: fires, prints enable lines and the serve-log pointer,
// never touches MCP, exits 0.
func TestDemo_MCPDisabled(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	cfg.MCP.Enabled = false
	cfg.MCP.TokenEnv = "" // realistic: disabled feature, no env named
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.alertBodies) != 1 {
		t.Errorf("burst not fired")
	}
	s := out.String()
	for _, want := range []string{"mcp is disabled", "token_env: ALERTINT_MCP_TOKEN", "`finding` summary line in serve logs"} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
}

// TestDemo_NotAnalyzedYet: a slow triage prints id, state, and the exact
// --result re-check command — never empty-handed, exit 0.
func TestDemo_NotAnalyzedYet(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	groupKey := "cluster=demo-cluster-t3st01,namespace=demo-shop,service=demo-checkout"
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

// TestDemo_ResultMode: --result fetches exactly one incident, list-free.
func TestDemo_ResultMode(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", result: "inc-42"})
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

// TestDemo_RemoteGuards: remote targets refuse before any request leaves —
// plain HTTP needs the explicit override, https needs confirmation.
func TestDemo_RemoteGuards(t *testing.T) {
	cfg := demoTestConfig(t)

	t.Run("plain http refused without override", func(t *testing.T) {
		d, _ := demoTestCmd(t, nil, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: "http://alertint.example:9911"})
		err := d.run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "--allow-insecure-http") {
			t.Fatalf("run = %v, want insecure-http refusal", err)
		}
	})

	t.Run("https refused when confirmation declined", func(t *testing.T) {
		d, _ := demoTestCmd(t, nil, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: "https://alertint.example:9911"})
		d.confirm = func(string) (bool, error) { return false, nil }
		err := d.run(context.Background())
		if err == nil || !strings.Contains(err.Error(), "aborted") {
			t.Fatalf("run = %v, want user abort", err)
		}
	})

	t.Run("https with --yes proceeds past the guard", func(t *testing.T) {
		d, _ := demoTestCmd(t, nil, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: "https://alertint.example:9911", yes: true})
		d.http = &http.Client{Timeout: 50 * time.Millisecond}
		err := d.run(context.Background())
		// The guard passes; the unreachable host then fails the fire step.
		if err == nil || strings.Contains(err.Error(), "confirmation") || strings.Contains(err.Error(), "--allow-insecure-http") {
			t.Fatalf("run = %v, want a network error past the guards", err)
		}
	})
}

// TestDemo_MCPUnreachable: a post-fire MCP failure degrades to the fallback
// pointer and exits 0 (never exits empty-handed after firing).
func TestDemo_MCPUnreachable(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
	t.Setenv("DEMO_TEST_MCP", "wrong-token") // 401 at initialize

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v (post-fire MCP failures must not error)", err)
	}
	s := out.String()
	if !strings.Contains(s, "could not reach MCP") || !strings.Contains(s, "serve logs") {
		t.Errorf("stdout missing degraded pointers:\n%s", s)
	}
}

// TestDemo_StormScenario: storm fires more alerts, no change event.
func TestDemo_StormScenario(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, _ := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "storm"})
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

// TestDemo_ViaAlertmanager: the burst goes to AM's v2 API (no fingerprint
// fields there); the change event still posts direct.
func TestDemo_ViaAlertmanager(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)

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

	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship", viaAlertmanager: am.URL})
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

func TestDemo_RequiresConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"demo"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "--config is required") {
		t.Fatalf("run = %v, want config-required error", err)
	}
}

func TestDemo_UnknownScenario(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, _ := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "nope"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unknown scenario") {
		t.Fatalf("run = %v, want unknown-scenario error", err)
	}
}

// TestDemo_ResultModeInsecureRemote: --result carries the MCP bearer token,
// so a plain-HTTP remote target needs the explicit override too.
func TestDemo_ResultModeInsecureRemote(t *testing.T) {
	cfg := demoTestConfig(t)
	d, _ := demoTestCmd(t, nil, cfg, demoOpts{cfgPath: "cfg.yaml", result: "inc-1", target: "http://alertint.example:9911"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--allow-insecure-http") {
		t.Fatalf("run = %v, want insecure-http refusal before any token is sent", err)
	}
}

// TestDemo_ViaAlertmanagerRemoteGuard: the AM URL is a second remote write
// surface and gets the same guard as the receiver target.
func TestDemo_ViaAlertmanagerRemoteGuard(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, _ := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship", viaAlertmanager: "https://am.example:9093"})
	d.confirm = func(string) (bool, error) { return false, nil }
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Fatalf("run = %v, want user abort on remote AM", err)
	}
	if len(f.alertBodies)+len(f.changeBodies) != 0 {
		t.Error("nothing may fire when the AM guard aborts")
	}
}

// TestDemo_ViaAlertmanagerNoEmptyAuthHeader: no Authorization header goes to
// the user's Alertmanager (no token is involved).
func TestDemo_ViaAlertmanagerNoEmptyAuthHeader(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	var sawAuth []string
	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := r.Header["Authorization"]; ok {
			sawAuth = append(sawAuth, r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(am.Close)
	d, _ := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship", viaAlertmanager: am.URL})
	f.listRows = []map[string]any{}
	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(sawAuth) != 0 {
		t.Fatalf("Alertmanager received Authorization headers: %v", sawAuth)
	}
}

// TestDemo_MCPMisconfigPreflight: MCP enabled but token env unset must be
// reported before firing, and the run degrades instead of erroring after the
// full wait.
func TestDemo_MCPMisconfigPreflight(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	cfg.MCP.TokenEnv = "DEMO_TEST_MCP_UNSET"
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

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

// TestDemo_ChangePostRejected: an attempted-but-rejected planted deploy warns
// with the token hint and steers the capped hint to the rejected wording.
func TestDemo_ChangePostRejected(t *testing.T) {
	cfg := demoTestConfig(t)
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

	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: rejecting.URL})
	groupKey := "cluster=demo-cluster-t3st01,namespace=demo-shop,service=demo-checkout"
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

// TestDemo_DriftFallback: when no incident matches the locally-computed group
// key, the newest drill incident is used with a config-drift caveat.
func TestDemo_DriftFallback(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	f.listRows = []map[string]any{
		{"id": "real-1", "group_key": "service=checkout", "status": "analyzed", "drill": false},
		{"id": "drill-9", "group_key": "team=demo-team-x", "status": "analyzed", "drill": true},
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

// TestDemo_ResultUnknownIncident: --result with a bad id must error (exit 1),
// not print a hint recommending the same doomed command.
func TestDemo_ResultUnknownIncident(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	f.mcp.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "mcp-session-x")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"incident \"nope\" not found"}]}}`))
	})
	d, _ := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", result: "nope"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("run = %v, want fetch error surfaced", err)
	}
}

// TestDemo_CappedHintProbeWording: with change ingress on and fired, the
// Prometheus probe steers the wording between detected and docs-link
// variants; both stay scoped to real incidents.
func TestDemo_CappedHintProbeWording(t *testing.T) {
	for name, probe := range map[string]bool{"probe hit": true, "probe miss": false} {
		t.Run(name, func(t *testing.T) {
			f := newFakeInstance(t)
			cfg := demoTestConfig(t)
			d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
			d.probePrometheus = func(string, string) bool { return probe }

			groupKey := "cluster=demo-cluster-t3st01,namespace=demo-shop,service=demo-checkout"
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
			if !strings.Contains(s, "cannot uncap a demo re-run") {
				t.Errorf("real-incident scoping missing:\n%s", s)
			}
		})
	}
}

// TestDemo_SanitizesFindingText: control characters in MCP-sourced strings
// never reach the terminal.
func TestDemo_SanitizesFindingText(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	d, out := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", result: "inc-evil"})
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

// TestDemo_AlertmanagerReceiverDisabled: the demo cannot ingest its burst
// without the alert receiver — a pre-fire config error.
func TestDemo_AlertmanagerReceiverDisabled(t *testing.T) {
	f := newFakeInstance(t)
	cfg := demoTestConfig(t)
	cfg.Alertmanager.Enabled = false
	d, _ := demoTestCmd(t, f, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "alertmanager receiver is disabled") {
		t.Fatalf("run = %v, want receiver-disabled error", err)
	}
	if len(f.alertBodies)+len(f.changeBodies) != 0 {
		t.Error("nothing may fire without the alert receiver")
	}
}

// TestDemo_ConfirmErrorPath: a failed confirmation read (non-TTY) refuses
// with the --yes instruction.
func TestDemo_ConfirmErrorPath(t *testing.T) {
	cfg := demoTestConfig(t)
	d, _ := demoTestCmd(t, nil, cfg, demoOpts{cfgPath: "cfg.yaml", scenario: "flagship", target: "https://alertint.example:9911"})
	d.confirm = func(string) (bool, error) { return false, io.EOF }
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("run = %v, want non-interactive instruction", err)
	}
}
