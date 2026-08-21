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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/ingress"
)

// fakeInstance emulates a running AlertINT: the two webhook receivers and a
// streamable-HTTP MCP endpoint (initialize + tools/call, format-only session
// check — the contract verified against mcp-go v0.54.1) serving the two
// Situation read tools the drill consumes.
type fakeInstance struct {
	mu           sync.Mutex
	changeBodies [][]byte
	alertBodies  [][]byte
	authSeen     []string

	listRows    []map[string]any   // alertint_situation_list rows
	listRowsSeq [][]map[string]any // consumed first, one per list call

	situation      map[string]any // fallback single alertint_situation_get fixture
	situationSeq   [][]byte       // FIFO of raw alertint_situation_get responses; consumed before the fallback
	getSituationID []string       // every id/handle alertint_situation_get was called with

	// situationID/groupKey/situationHandle: the fixed identity queueSituation
	// builds its canned responses around.
	situationID     string
	groupKey        string
	situationHandle string

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
			case "alertint_situation_list":
				if len(f.listRowsSeq) > 0 {
					payload = map[string]any{"situations": f.listRowsSeq[0]}
					f.listRowsSeq = f.listRowsSeq[1:]
				} else {
					payload = map[string]any{"situations": f.listRows}
				}
			case "alertint_situation_get":
				id, _ := req.Params.Arguments["situation"].(string)
				f.getSituationID = append(f.getSituationID, id)
				if len(f.situationSeq) > 0 {
					var raw json.RawMessage = f.situationSeq[0]
					f.situationSeq = f.situationSeq[1:]
					f.mu.Unlock()
					writeRPC(w, req.ID, map[string]any{
						"content": []map[string]any{{"type": "text", "text": string(raw)}},
						"isError": false,
					})
					return
				}
				payload = f.situation
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

// queueSituation appends one canned alertint_situation_get response — built
// around the fake's fixed situationID/groupKey/situationHandle — to the FIFO
// consumed by the next alertint_situation_get call. actionStatus is the
// current Assessment's action_contract.action_status (e.g. "planned",
// "running", "complete").
func (f *fakeInstance) queueSituation(lifecycle, actionStatus string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body := map[string]any{
		"id": f.situationID, "group_key": f.groupKey, "public_handle": f.situationHandle,
		"lifecycle": lifecycle, "attention": "investigate", "drill": true,
		"incidents": []map[string]any{{"id": f.situationID + "-inc-1", "acute_finding_status": "complete"}},
		"current_assessment": map[string]any{
			"action_contract": map[string]any{"next_actor": "alertint", "action_status": actionStatus},
		},
		"notifications":   []map[string]any{{"kind": "situation_root_create", "main_channel_poke": true, "status": "delivered"}},
		"terminal_banner": "",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	f.situationSeq = append(f.situationSeq, raw)
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
		pause:    func(string) error { return nil },
		newRunID: func() string { return "t3st01" },
		grace:    time.Second,
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

// flagshipGroupKey is the exact group key materializeScenario produces for
// the "flagship" scenario with the newRunID stub ("t3st01") and the default
// Receiver-mode group labels.
const flagshipGroupKey = "cluster=drill-cluster-flagship-t3st01,host=drill-node-01,namespace=drill-shop,service=drill-checkout"

// situationFixture builds one alertint_situation_get payload for the given
// id/group key/lifecycle, with a published handle and one complete member
// Incident — the shared shape most tests need.
func situationFixture(id, groupKey, lifecycle string) map[string]any {
	return map[string]any{
		"id": id, "group_key": groupKey, "public_handle": id + "-handle",
		"lifecycle": lifecycle, "attention": "investigate", "drill": true,
		"incidents": []map[string]any{{"id": id + "-inc-1", "acute_finding_status": "complete"}},
		"current_assessment": map[string]any{
			"action_contract": map[string]any{"next_actor": "alertint", "action_status": "running"},
		},
		"notifications":   []map[string]any{{"kind": "situation_root_create", "main_channel_poke": true, "status": "delivered"}},
		"terminal_banner": "",
	}
}

// drillHarness wraps a drillCmd wired to a fakeInstance with a fixed drill
// identity, for tests that drive the Situation lifecycle over a sequence of
// alertint_situation_get responses (queueSituation).
type drillHarness struct {
	cmd *drillCmd
	mcp *fakeInstance
	out *bytes.Buffer
}

func newDrillHarness(t *testing.T) *drillHarness {
	t.Helper()
	f := newFakeInstance(t)
	f.situationID = "sit-1"
	f.situationHandle = "drill-checkout-high-error-rate"
	f.groupKey = flagshipGroupKey
	// A row with an unset (zero-time) UpdatedAt is naturally outside the
	// rerun-candidate collapse window, so the pre-fire scan mints a fresh
	// salt matching flagshipGroupKey exactly — the same convention every
	// other test in this file relies on.
	f.listRows = []map[string]any{{"id": f.situationID, "group_key": f.groupKey}}
	cfg := drillTestConfig(t)
	cmd, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", resolve: true})
	return &drillHarness{cmd: cmd, mcp: f, out: out}
}

func (h *drillHarness) run(ctx context.Context) error { return h.cmd.run(ctx) }
func (h *drillHarness) output() string                { return h.out.String() }

// TestDrillResolveWaitsThroughRecoveryPending: the brief's canonical example
// — --resolve watches the Situation move active -> recovery_pending ->
// recovered, reporting each stage rather than only the terminal outcome.
func TestDrillResolveWaitsThroughRecoveryPending(t *testing.T) {
	d := newDrillHarness(t)
	d.mcp.queueSituation("active", "planned")
	d.mcp.queueSituation("recovery_pending", "complete")
	d.mcp.queueSituation("recovered", "complete")
	if err := d.run(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := d.output()
	if !strings.Contains(out, "recovery pending") || !strings.Contains(out, "recovered") {
		t.Fatalf("output=%s", out)
	}
}

// TestDrill_HappyPath: change then burst then poll; the console carries the
// Situation payoff and the investigate CTA.
func TestDrill_HappyPath(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	f.listRows = []map[string]any{
		{"id": "other", "group_key": "x=y"},
		{"id": "sit-42", "group_key": flagshipGroupKey},
	}
	f.situation = situationFixture("sit-42", flagshipGroupKey, "active")

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
	headings := []string{
		"── fire",
		"── correlate",
		"── finding",
		"── investigate",
	}
	last := -1
	for _, heading := range headings {
		at := strings.Index(s, heading)
		if at < 0 {
			t.Errorf("stdout missing %q:\n%s", heading, s)
		} else if at <= last {
			t.Errorf("phase %q out of order:\n%s", heading, s)
		}
		last = at
	}
	for _, want := range []string{
		"handle: sit-42-handle",
		"lifecycle: active",
		"investigate situation sit-42-handle using alertint",
		"DRILL",
		"L1 gate",
		"sit-42-inc-1: complete",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\x1b[") {
		t.Errorf("captured output must stay plain in automatic color mode:\n%q", s)
	}
}

// TestDrill_ColorPresentation: when color is enabled, the same drill payoff
// gains semantic stage colors without changing its text content.
func TestDrill_ColorPresentation(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
	d.color = true

	f.listRows = []map[string]any{{"id": "sit-color", "group_key": flagshipGroupKey}}
	f.situation = situationFixture("sit-color", flagshipGroupKey, "active")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	for _, want := range []string{
		"\x1b[1;33m── fire",
		"\x1b[1;36m── correlate",
		"\x1b[1;32m── finding",
		"\x1b[1;34m── investigate",
		"\x1b[1;35m🧪 DRILL",
		"\x1b[1mhandle: sit-color-handle",
		"\x1b[1;34m  investigate situation sit-color-handle using alertint",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("colored stdout missing %q:\n%q", want, s)
		}
	}
}

// TestDrill_ColorMode: recordings can force color, redirected/default output
// stays plain, and the standard NO_COLOR opt-out always wins.
func TestDrill_ColorMode(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatalf("unset NO_COLOR: %v", err)
	}
	t.Setenv("CLICOLOR_FORCE", "0")

	if got, err := resolveDrillColor("auto", &bytes.Buffer{}); err != nil || got {
		t.Fatalf("auto on redirected output = %v, %v; want false, nil", got, err)
	}
	if got, err := resolveDrillColor("always", &bytes.Buffer{}); err != nil || !got {
		t.Fatalf("always = %v, %v; want true, nil", got, err)
	}
	if got, err := resolveDrillColor("never", os.Stdout); err != nil || got {
		t.Fatalf("never = %v, %v; want false, nil", got, err)
	}
	if _, err := resolveDrillColor("rainbow", os.Stdout); err == nil || !strings.Contains(err.Error(), "auto, always, or never") {
		t.Fatalf("invalid mode error = %v", err)
	}

	t.Setenv("NO_COLOR", "1")
	if got, err := resolveDrillColor("always", &bytes.Buffer{}); err != nil || got {
		t.Fatalf("NO_COLOR + always = %v, %v; want false, nil", got, err)
	}
}

// TestDrill_ChangesDisabled: no change POST, enable lines printed, burst
// still fired.
func TestDrill_ChangesDisabled(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	cfg.Changes.Ingress.Enabled = false
	cfg.Changes.Ingress.WebhookTokenEnv = "" // realistic: disabled feature, no env named
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	f.listRows = []map[string]any{{"id": "sit-7", "group_key": flagshipGroupKey}}
	f.situation = situationFixture("sit-7", flagshipGroupKey, "active")

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
	} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
}

// TestDrill_MCPDisabled: fires, prints enable lines and the serve-log
// pointer, never touches MCP, exits 0.
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
	for _, want := range []string{"mcp is disabled", "mcp.enabled is false in cfg.yaml", "Situation stdout line in serve logs"} {
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

// TestDrill_SilentNonCriticalStorm: a Situation with no delivered
// main-channel-poke notification reports the controller correctly kept
// Slack quiet — silence is not treated as failure.
func TestDrill_SilentNonCriticalStorm(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "storm"})

	stormGroupKey := "cluster=drill-cluster-storm-t3st01,host=drill-node-01,namespace=drill-shop,service=drill-checkout"
	f.listRows = []map[string]any{{"id": "sit-storm", "group_key": stormGroupKey}}
	f.situation = map[string]any{
		"id": "sit-storm", "group_key": stormGroupKey, "public_handle": nil,
		"lifecycle": "active", "attention": "observe", "drill": true,
		"incidents":          []map[string]any{{"id": "inc-storm-1", "acute_finding_status": "not_requested"}},
		"current_assessment": map[string]any{"action_contract": map[string]any{"next_actor": "alertint", "action_status": "waiting"}},
		"notifications":      []map[string]any{},
		"terminal_banner":    "",
	}

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "Situation created; controller kept Slack quiet") {
		t.Errorf("stdout missing the quiet-controller note:\n%s", s)
	}
	if !strings.Contains(s, "not yet published") {
		t.Errorf("stdout missing the still-silent handle note:\n%s", s)
	}
}

// TestDrill_ResultMode: --result fetches exactly one Situation, list-free.
func TestDrill_ResultMode(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", result: "sit-42"})
	f.situation = situationFixture("sit-42", flagshipGroupKey, "active")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(f.alertBodies)+len(f.changeBodies) != 0 {
		t.Error("--result must not fire anything")
	}
	if len(f.getSituationID) != 1 || f.getSituationID[0] != "sit-42" {
		t.Errorf("get calls = %v, want exactly [sit-42]", f.getSituationID)
	}
	if !strings.Contains(out.String(), "investigate situation sit-42-handle using alertint") {
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
	d, _ := drillTestCmd(t, nil, cfg, drillOpts{cfgPath: "cfg.yaml", result: "sit-1", target: "http://alertint.example:9911"})
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

// TestDrill_ChangePostRejected: an attempted-but-rejected planted deploy
// warns with the token hint.
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
	f.listRows = []map[string]any{{"id": "sit-8", "group_key": flagshipGroupKey}}
	f.situation = situationFixture("sit-8", flagshipGroupKey, "active")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	for _, want := range []string{"change event not accepted", "check the DEMO_TEST_CH env var"} {
		if !strings.Contains(s, want) {
			t.Errorf("stdout missing %q:\n%s", want, s)
		}
	}
}

// TestDrill_DriftFallback: when no Situation matches the locally-computed
// group key, the newest situation whose group key still looks like a drill's
// is used with a config-drift caveat.
func TestDrill_DriftFallback(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	f.listRows = []map[string]any{
		{"id": "real-1", "group_key": "service=checkout"},
		{"id": "drill-9", "group_key": "cluster=drill-cluster-flagship-driftedsalt,namespace=drill-shop,service=drill-checkout"},
	}
	f.situation = situationFixture("drill-9", "cluster=drill-cluster-flagship-driftedsalt,namespace=drill-shop,service=drill-checkout", "active")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "config drift") || !strings.Contains(s, "investigate situation drill-9-handle using alertint") {
		t.Errorf("drift fallback missing:\n%s", s)
	}
}

// TestDrill_ResultUnknownSituation: --result with a bad id must error
// (exit 1).
func TestDrill_ResultUnknownSituation(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	f.mcp.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "mcp-session-x")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"isError":true,"content":[{"type":"text","text":"situation \"nope\" not found"}]}}`))
	})
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", result: "nope"})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("run = %v, want fetch error surfaced", err)
	}
}

// TestDrill_SanitizesFindingText: control characters in MCP-sourced strings
// never reach the terminal.
func TestDrill_SanitizesFindingText(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", result: "sit-evil"})
	evil := situationFixture("sit-evil", flagshipGroupKey, "active")
	evil["public_handle"] = "evil\x1b[31mred\x07bell"
	f.situation = evil

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

// TestDrill_PollsUntilFound: with a multi-poll grace, the payoff returns as
// soon as a poll finds the Situation instead of sleeping out the full grace.
func TestDrill_PollsUntilFound(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})
	d.grace = 4 * drillPollInterval // budget for four polls

	var sleeps []time.Duration
	d.sleep = func(_ context.Context, dur time.Duration) error {
		sleeps = append(sleeps, dur)
		return nil
	}

	found := []map[string]any{{"id": "sit-7", "group_key": flagshipGroupKey}}
	// [0] answers the pre-fire rerun scan (no drill candidate → fresh salt);
	// [1],[2] answer the discovery poll with nothing yet; the fallback (not
	// consumed by listRowsSeq) then finally returns the row.
	f.listRowsSeq = [][]map[string]any{{}, {}, {}}
	f.listRows = found
	f.situation = situationFixture("sit-7", flagshipGroupKey, "active")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out.String(), "investigate situation sit-7-handle using alertint") {
		t.Errorf("missing finding CTA:\n%s", out.String())
	}
	var polls int
	for _, dur := range sleeps {
		if dur == drillPollInterval {
			polls++
		}
	}
	if polls != 2 {
		t.Errorf("poll sleeps = %d, want 2 (loop must stop as soon as the Situation is found)", polls)
	}
}

// TestDrill_RerunCollapses: a second drill inside the collapse window reuses
// the prior (nonterminal) Situation's group salt; the runtime attaches
// rather than minting a fresh Situation, and the payoff reports the collapse
// rather than a new linked Situation.
func TestDrill_RerunCollapses(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	priorGroupKey := "cluster=drill-cluster-flagship-priorsalt,host=drill-node-01,namespace=drill-shop,service=drill-checkout"
	f.listRows = []map[string]any{{
		"id": "sit-9", "group_key": priorGroupKey, "lifecycle": "active", "updated_at": "2026-07-03T11:55:00Z",
	}}
	f.situation = situationFixture("sit-9", priorGroupKey, "active")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "reusing its group key") {
		t.Errorf("expected a rerun-detected note:\n%s", s)
	}
	if !strings.Contains(s, "collapsed: situation") || !strings.Contains(s, "no new Situation minted") {
		t.Errorf("expected the collapsed payoff:\n%s", s)
	}
	if strings.Contains(s, "waiting ~") {
		t.Errorf("a rerun must skip the correlation-window wait:\n%s", s)
	}
	if len(f.getSituationID) == 0 || f.getSituationID[len(f.getSituationID)-1] != "sit-9" {
		t.Errorf("expected a get on sit-9, got %v", f.getSituationID)
	}
}

// TestDrill_RerunCreatesLinkedSituation: a rerun whose exact group key was
// last owned by a terminal (recovered) Situation reuses the salt too, but
// the runtime mints a fresh Situation linked through previous_situation_id
// — the drill must report the new link, not a collapse.
func TestDrill_RerunCreatesLinkedSituation(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship"})

	priorGroupKey := "cluster=drill-cluster-flagship-priorsalt,host=drill-node-01,namespace=drill-shop,service=drill-checkout"
	// The pre-fire rerun scan (the first list call) sees the terminal prior;
	// every list call after that (the post-fire discovery poll, on the same
	// reused exact group key) sees the fallback — the brand new Situation the
	// runtime minted because the owner had gone terminal.
	f.listRowsSeq = [][]map[string]any{
		{{"id": "sit-old", "group_key": priorGroupKey, "lifecycle": "recovered", "updated_at": "2026-07-03T11:55:00Z"}},
	}
	f.listRows = []map[string]any{{"id": "sit-new", "group_key": priorGroupKey}}
	newSit := situationFixture("sit-new", priorGroupKey, "active")
	newSit["previous_situation"] = map[string]any{"id": "sit-old", "lifecycle": "recovered"}
	f.situation = newSit

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "reusing its group key") {
		t.Errorf("expected a rerun-detected note:\n%s", s)
	}
	if !strings.Contains(s, "new linked situation") || !strings.Contains(s, "sit-old") {
		t.Errorf("expected the new-linked-situation payoff naming the terminal prior:\n%s", s)
	}
	if strings.Contains(s, "collapsed:") {
		t.Errorf("a post-terminal rerun must not be reported as a collapse:\n%s", s)
	}
}

// TestDrill_FreshBypassesRerunCollapse: --fresh ignores an eligible prior
// drill and creates a new group immediately, while preserving the normal
// correlation and finding flow for the new Situation.
func TestDrill_FreshBypassesRerunCollapse(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", fresh: true})

	priorGroupKey := "cluster=drill-cluster-flagship-priorsalt,host=drill-node-01,namespace=drill-shop,service=drill-checkout"
	f.listRows = []map[string]any{
		{"id": "sit-prior", "group_key": priorGroupKey, "lifecycle": "active", "updated_at": "2026-07-03T11:55:00Z"},
		{"id": "sit-fresh", "group_key": flagshipGroupKey},
	}
	f.situation = situationFixture("sit-fresh", flagshipGroupKey, "active")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "fresh: bypassing prior drill recurrence") {
		t.Errorf("expected an explicit fresh-mode note:\n%s", s)
	}
	if strings.Contains(s, "reusing its group key") || strings.Contains(s, "collapsed:") {
		t.Errorf("fresh mode must not use the recurrence path:\n%s", s)
	}
	if !strings.Contains(s, "waiting ~") {
		t.Errorf("fresh mode must run a new correlation window:\n%s", s)
	}
	if !strings.Contains(s, flagshipGroupKey) || strings.Contains(s, "group: "+priorGroupKey) {
		t.Errorf("fresh mode must fire the new group key:\n%s", s)
	}
}

// TestDrill_ResolveFlag: --resolve re-sends the burst as resolved after the
// payoff — same fingerprints so the rows overwrite, endsAt set, payload
// status resolved.
func TestDrill_ResolveFlag(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, out := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", resolve: true})

	f.listRows = []map[string]any{{"id": "sit-42", "group_key": flagshipGroupKey}}
	f.situation = situationFixture("sit-42", flagshipGroupKey, "active")

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
	if !strings.Contains(out.String(), "alerts: 4 resolved") {
		t.Errorf("stdout missing resolution note:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "── resolve") {
		t.Errorf("stdout missing resolution phase:\n%s", out.String())
	}
}

// TestDrill_ResolveWaitFlag: with --resolve --resolve-wait the resolution is
// gated on the pause hook — the resolved burst posts only after it returns.
func TestDrill_ResolveWaitFlag(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", resolve: true, resolveWait: true})

	paused := false
	d.pause = func(string) error {
		paused = true
		if got := len(f.alertBodies); got != 1 {
			t.Errorf("alert posts before Enter = %d, want 1 (burst only — resolution must wait)", got)
		}
		return nil
	}

	f.listRows = []map[string]any{{"id": "sit-42", "group_key": flagshipGroupKey}}
	f.situation = situationFixture("sit-42", flagshipGroupKey, "active")

	if err := d.run(context.Background()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if !paused {
		t.Fatal("pause hook never fired")
	}
	if len(f.alertBodies) != 2 {
		t.Fatalf("alert posts = %d, want 2 (burst + resolution after Enter)", len(f.alertBodies))
	}
}

// TestDrill_ResolveWaitRequiresResolve: the flag is meaningless alone.
func TestDrill_ResolveWaitRequiresResolve(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", scenario: "flagship", resolveWait: true})
	err := d.run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--resolve-wait requires --resolve") {
		t.Fatalf("err = %v, want the -resolve-wait requires -resolve error", err)
	}
}

// TestDrill_ResolveWithResultRejected: --resolve needs a firing run.
func TestDrill_ResolveWithResultRejected(t *testing.T) {
	f := newFakeInstance(t)
	cfg := drillTestConfig(t)
	d, _ := drillTestCmd(t, f, cfg, drillOpts{cfgPath: "cfg.yaml", result: "sit-1", resolve: true})
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
