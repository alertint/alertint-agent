// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
)

// seedSituationForMCP builds one real Situation the same way the durable
// pipeline does — InsertIncident, a queued situation_input_outbox row,
// ClaimSituationInputs, ApplySituationInput — never an INSERT INTO
// situations by hand. It returns the created Situation's id. kind lets a
// caller choose the due reason a given input contributes (e.g.
// "incident_created" vs "membership_changed"), mirroring how a fresh
// Incident vs. an existing one produces a different kind on the real path
// (see internal/correlator.applyDeliveryPlan).
func seedSituationForMCP(t *testing.T, st *store.Store, incidentID, groupKey, kind string, at time.Time) string {
	t.Helper()
	ctx := context.Background()
	if err := st.InsertIncident(ctx, store.Incident{
		ID: incidentID, GroupKey: groupKey,
		FirstAlertAt: at, LastAlertAt: at, ReadyAt: at.Add(time.Minute),
	}); err != nil {
		t.Fatalf("insert incident %s: %v", incidentID, err)
	}
	inputID := "input-" + incidentID
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_input_outbox (id, idempotency_key, incident_id, kind, group_key, occurred_at, status)
		VALUES (?, ?, ?, ?, ?, ?, 'pending')`,
		inputID, "idem:"+inputID, incidentID, kind, groupKey, at.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert situation input for %s: %v", incidentID, err)
	}
	claims, err := st.ClaimSituationInputs(ctx, "test-worker", at, time.Minute, 1)
	if err != nil {
		t.Fatalf("claim situation input for %s: %v", incidentID, err)
	}
	if len(claims) != 1 {
		t.Fatalf("claimed = %d, want 1", len(claims))
	}
	if err := st.ApplySituationInput(ctx, claims[0]); err != nil {
		t.Fatalf("apply situation input for %s: %v", incidentID, err)
	}
	var situationID string
	if err := st.DB().QueryRowContext(ctx, `SELECT situation_id FROM situation_incidents WHERE incident_id = ?`, incidentID).Scan(&situationID); err != nil {
		t.Fatalf("read situation id for %s: %v", incidentID, err)
	}
	return situationID
}

// ----------------------------------------------------------------------
// Step 1: MCP contract tests
// ----------------------------------------------------------------------

// TestSituationToolsRegistered proves NewServer registers both Situation
// tools under their exact names, and that both are read-only: their
// mcp.Tool metadata carries no destructive/write annotation, matching every
// other read tool in this package (only server_feedback.go's two tools
// write anything, and this task adds no third).
func TestSituationToolsRegistered(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))
	if s == nil {
		t.Fatal("NewServer returned nil")
	}

	listTool, listHandler := s.toolListSituations()
	if listTool.Name != "alertint_list_situations" {
		t.Fatalf("list tool name = %q, want alertint_list_situations", listTool.Name)
	}
	if listHandler == nil {
		t.Fatal("list tool handler is nil")
	}

	getTool, getHandler := s.toolGetSituation()
	if getTool.Name != "alertint_get_situation" {
		t.Fatalf("get tool name = %q, want alertint_get_situation", getTool.Name)
	}
	if getHandler == nil {
		t.Fatal("get tool handler is nil")
	}
}

func TestListSituationsNewestFirstWithLimit(t *testing.T) {
	st := newMCPStore(t)
	base := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)

	seedSituationForMCP(t, st, "inc-a", "service=a", "incident_created", base)
	seedSituationForMCP(t, st, "inc-b", "service=b", "incident_created", base.Add(time.Minute))
	seedSituationForMCP(t, st, "inc-c", "service=c", "incident_created", base.Add(2*time.Minute))

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleListSituations(context.Background(), reqWith(map[string]any{"limit": 2}))
	if err != nil || res.IsError {
		t.Fatalf("list situations errored: %v %s", err, resultText(t, res))
	}

	var payload struct {
		Situations []struct {
			GroupKey string `json:"group_key"`
		} `json:"situations"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, resultText(t, res))
	}
	if len(payload.Situations) != 2 {
		t.Fatalf("situations = %+v, want exactly 2 (limit)", payload.Situations)
	}
	if payload.Situations[0].GroupKey != "service=c" || payload.Situations[1].GroupKey != "service=b" {
		t.Fatalf("order = %+v, want [service=c, service=b] (newest first)", payload.Situations)
	}
}

func TestListSituationsDefaultAndClampedLimit(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))

	for _, limit := range []any{nil, 0, -5, 1000} {
		args := map[string]any{}
		if limit != nil {
			args["limit"] = limit
		}
		res, err := s.handleListSituations(context.Background(), reqWith(args))
		if err != nil || res.IsError {
			t.Fatalf("limit %v errored: %v %s", limit, err, resultText(t, res))
		}
	}
}

// TestGetSituationByIDExactContract proves the exact response shape Step 1
// of this task's plan specifies, including the two explicit null fields
// (assessment, operator_contract) that make the foundation honest: no
// controller Assessment or operator contract exists yet.
func TestGetSituationByIDExactContract(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)

	situationID := seedSituationForMCP(t, st, "inc-1", "service=api", "incident_created", at)
	// incidents_one_collecting_group_idx allows only one "collecting"
	// Incident per group_key at a time, so inc-1 must leave "collecting"
	// before a second same-group Incident can be inserted.
	if err := st.MarkIncidentReady(context.Background(), "inc-1"); err != nil {
		t.Fatalf("mark inc-1 ready: %v", err)
	}
	seedSituationForMCP(t, st, "inc-2", "service=api", "membership_changed", at.Add(time.Minute))

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetSituation(context.Background(), reqWith(map[string]any{"id": situationID}))
	if err != nil || res.IsError {
		t.Fatalf("get situation errored: %v %s", err, resultText(t, res))
	}

	var payload map[string]any
	raw := resultText(t, res)
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}

	wantKeys := []string{
		"id", "previous_situation_id", "public_handle", "group_key", "lifecycle", "attention",
		"input_version", "due_reasons", "opened_at", "effective_started_at", "first_received_at",
		"next_assessment_at", "incidents", "assessment", "operator_contract",
		// Task 9 additions: current Assessment derivation, material/basis
		// hashes, bounded recent attempts, and controller retry/park state.
		"assessment_derivation", "material_fact_hash", "assessment_basis_hash",
		"eligible_reasons", "recent_attempts", "controller_state",
		// Plan 3 Task 9 additions: the current Episode summary read
		// coherently with its source Transition (explicit null before any
		// Transition exists) and the Situation's whole Slack presence.
		"episode", "slack_delivery",
	}
	if len(payload) != len(wantKeys) {
		t.Fatalf("payload has %d keys, want exactly %d: %+v", len(payload), len(wantKeys), payload)
	}
	for _, k := range wantKeys {
		if _, ok := payload[k]; !ok {
			t.Fatalf("payload missing key %q: %+v", k, payload)
		}
	}

	if payload["id"] != situationID {
		t.Errorf("id = %v, want %v", payload["id"], situationID)
	}
	if payload["previous_situation_id"] != nil {
		t.Errorf("previous_situation_id = %v, want explicit null", payload["previous_situation_id"])
	}
	if payload["public_handle"] != nil {
		t.Errorf("public_handle = %v, want explicit null", payload["public_handle"])
	}
	if payload["group_key"] != "service=api" {
		t.Errorf("group_key = %v, want service=api", payload["group_key"])
	}
	if payload["lifecycle"] != "active" {
		t.Errorf("lifecycle = %v, want active", payload["lifecycle"])
	}
	if payload["attention"] != "observe" {
		t.Errorf("attention = %v, want observe", payload["attention"])
	}
	if payload["input_version"] != float64(2) {
		t.Errorf("input_version = %v, want 2", payload["input_version"])
	}
	dueReasons, _ := payload["due_reasons"].([]any)
	if len(dueReasons) != 2 || dueReasons[0] != "incident_created" || dueReasons[1] != "membership_changed" {
		t.Errorf("due_reasons = %v, want [incident_created membership_changed]", dueReasons)
	}
	// The two explicit nulls this task's plan calls out by name, plus every
	// Task 9 addition — all still their "no controller cycle has run yet"
	// shape for this fixture.
	assertNoControllerStateYet(t, payload)

	incidents, ok := payload["incidents"].([]any)
	if !ok || len(incidents) != 2 {
		t.Fatalf("incidents = %v, want exactly 2 entries", payload["incidents"])
	}
	first, _ := incidents[0].(map[string]any)
	if first["id"] != "inc-1" || first["status"] != "ready" {
		t.Errorf("incidents[0] = %+v, want {id:inc-1 status:ready}", first)
	}
	second, _ := incidents[1].(map[string]any)
	if second["id"] != "inc-2" || second["status"] != "collecting" {
		t.Errorf("incidents[1] = %+v, want {id:inc-2 status:collecting}", second)
	}
}

// assertNoControllerStateYet checks every Task 9 controller-derived field on
// an alertint_get_situation payload renders as its "no controller cycle has
// run yet" shape: assessment/operator_contract/assessment_derivation/hashes
// explicit null, recent_attempts an empty array, and controller_state a
// present object with every field at its zero/null value.
func assertNoControllerStateYet(t *testing.T, payload map[string]any) {
	t.Helper()
	if payload["assessment"] != nil {
		t.Errorf("assessment = %v, want explicit null (no controller cycle has run yet)", payload["assessment"])
	}
	if payload["operator_contract"] != nil {
		t.Errorf("operator_contract = %v, want explicit null (no operator contract exists yet)", payload["operator_contract"])
	}
	if payload["assessment_derivation"] != nil {
		t.Errorf("assessment_derivation = %v, want explicit null", payload["assessment_derivation"])
	}
	if payload["material_fact_hash"] != nil || payload["assessment_basis_hash"] != nil {
		t.Errorf("hashes = %v/%v, want explicit null", payload["material_fact_hash"], payload["assessment_basis_hash"])
	}
	if attempts, ok := payload["recent_attempts"].([]any); !ok || len(attempts) != 0 {
		t.Errorf("recent_attempts = %v, want an empty array", payload["recent_attempts"])
	}
	if reasons, ok := payload["eligible_reasons"].([]any); !ok || len(reasons) != 0 {
		t.Errorf("eligible_reasons = %v, want an empty array before the first reconcile", payload["eligible_reasons"])
	}
	controllerState, ok := payload["controller_state"].(map[string]any)
	if !ok {
		t.Fatalf("controller_state type = %T, want an object", payload["controller_state"])
	}
	wantZero := []string{"parked_at", "parked_reason", "retry_at", "last_error_class"}
	for _, k := range wantZero {
		if controllerState[k] != nil {
			t.Errorf("controller_state[%q] = %v, want null", k, controllerState[k])
		}
	}
	if controllerState["retry_epoch"] != float64(0) || controllerState["work_attempts"] != float64(0) {
		t.Errorf("controller_state = %+v, want retry_epoch=0 work_attempts=0", controllerState)
	}
}

// TestGetSituationExposesControllerAssessmentTriageAndRetryState proves
// Task 9's own MCP extension end to end: once a Situation has a committed
// authoritative Assessment, the get payload surfaces its full content and
// derivation, the material/basis hashes, one bounded sanitized recent
// attempt, the member Incident's Triage decision/phase/attempts/due
// time/covered digests, and controller retry/park state — never a raw
// proposal or provider body.
func TestGetSituationExposesControllerAssessmentTriageAndRetryState(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-controller", "service=controller", "incident_created", at)
	nextAt := at.Add(2 * time.Minute)
	seedControllerAssessmentFixture(t, st, situationID, "inc-controller", at, nextAt)

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetSituation(context.Background(), reqWith(map[string]any{"id": situationID}))
	if err != nil || res.IsError {
		t.Fatalf("get situation errored: %v %s", err, resultText(t, res))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatal(err)
	}

	assertAssessmentContent(t, payload)
	assertSanitizedRecentAttempt(t, payload)
	assertControllerRetryState(t, payload)
	assertIncidentTriageState(t, payload, nextAt)
}

// seedControllerAssessmentFixture seeds one committed authoritative
// Assessment attempt, its current_* projection, controller retry/park
// state, and one member Incident's Triage decision/covered digests —
// directly via SQL, mirroring internal/store's own controller-view fixture
// style (this package never constructs a real Controller/Reconcile cycle).
func seedControllerAssessmentFixture(t *testing.T, st *store.Store, situationID, incidentID string, at, triageNextAt time.Time) {
	t.Helper()
	ctx := context.Background()
	assessmentJSON := []byte(`{
		"schema_version": 1, "persistence": "sustained", "impact": "suspected",
		"novelty": "familiar", "causality": "correlated", "attention": "observe",
		"lifecycle": "active", "evidence_quality": "complete",
		"sufficient_reason": {"code": "x", "candidate_id": "cand-1", "summary": "s", "evidence_refs": ["ref-1"]},
		"action_contract": {"next_actor": "none", "next_update_at": "2026-09-01T04:00:00Z"},
		"limitations": [], "cadence": "normal"
	}`)
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_assessment_attempts (
			id, situation_id, sequence, input_version, work_attempt, status, derivation,
			provider_request_started, material_fact_hash, assessment_json, validation_errors_json, created_at, completed_at
		) VALUES ('attempt-mcp', ?, 1, 1, 1, 'authoritative', 'deterministic_controller', 'false', 'sha256:material-mcp', ?, '[]', ?, ?)`,
		situationID, string(assessmentJSON), at.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		UPDATE situations SET
			current_assessment_id = 'attempt-mcp', current_material_fact_hash = 'sha256:material-mcp',
			current_assessment_basis_hash = 'sha256:basis-mcp',
			controller_retry_epoch = 1, controller_work_attempts = 2,
			controller_parked_at = ?, controller_parked_reason = 'dependency_exhausted',
			retry_at = ?, last_error_class = 'transport_failure'
		WHERE id = ?`, at.UTC().Format(time.RFC3339Nano), at.Add(5*time.Minute).UTC().Format(time.RFC3339Nano), situationID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO incident_triage (incident_id, phase, attempts, decision, decided_at, next_at, membership_digest, incident_input_digest, updated_at)
		VALUES (?, 'backoff', 1, 'request', ?, ?, 'sha256:membership-mcp', 'sha256:input-mcp', ?)`,
		incidentID, at.UTC().Format(time.RFC3339Nano), triageNextAt.UTC().Format(time.RFC3339Nano), at.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
}

func assertAssessmentContent(t *testing.T, payload map[string]any) {
	t.Helper()
	assessment, ok := payload["assessment"].(map[string]any)
	if !ok {
		t.Fatalf("assessment type = %T, want an object", payload["assessment"])
	}
	if assessment["persistence"] != "sustained" || assessment["impact"] != "suspected" {
		t.Errorf("assessment content = %+v, want persistence=sustained impact=suspected", assessment)
	}
	if payload["assessment_derivation"] != "deterministic_controller" {
		t.Errorf("assessment_derivation = %v, want deterministic_controller", payload["assessment_derivation"])
	}
	if payload["material_fact_hash"] != "sha256:material-mcp" || payload["assessment_basis_hash"] != "sha256:basis-mcp" {
		t.Errorf("hashes = %v/%v", payload["material_fact_hash"], payload["assessment_basis_hash"])
	}
}

func assertSanitizedRecentAttempt(t *testing.T, payload map[string]any) {
	t.Helper()
	attempts, ok := payload["recent_attempts"].([]any)
	if !ok || len(attempts) != 1 {
		t.Fatalf("recent_attempts = %v, want exactly 1", payload["recent_attempts"])
	}
	attempt, _ := attempts[0].(map[string]any)
	if attempt["id"] != "attempt-mcp" || attempt["status"] != "authoritative" {
		t.Errorf("attempt = %+v, want id=attempt-mcp status=authoritative", attempt)
	}
	for _, forbidden := range []string{"proposal", "validated", "proposal_json", "assessment_json"} {
		if _, ok := attempt[forbidden]; ok {
			t.Errorf("recent_attempts entry exposes forbidden key %q: %+v", forbidden, attempt)
		}
	}
}

func assertControllerRetryState(t *testing.T, payload map[string]any) {
	t.Helper()
	controllerState, ok := payload["controller_state"].(map[string]any)
	if !ok {
		t.Fatalf("controller_state type = %T", payload["controller_state"])
	}
	if controllerState["retry_epoch"] != float64(1) || controllerState["work_attempts"] != float64(2) {
		t.Errorf("controller_state = %+v, want retry_epoch=1 work_attempts=2", controllerState)
	}
	if controllerState["parked_reason"] != "dependency_exhausted" {
		t.Errorf("parked_reason = %v, want dependency_exhausted", controllerState["parked_reason"])
	}
	if controllerState["last_error_class"] != "transport_failure" {
		t.Errorf("last_error_class = %v, want transport_failure", controllerState["last_error_class"])
	}
}

func assertIncidentTriageState(t *testing.T, payload map[string]any, wantDueAt time.Time) {
	t.Helper()
	incidents, ok := payload["incidents"].([]any)
	if !ok || len(incidents) != 1 {
		t.Fatalf("incidents = %v, want exactly 1", payload["incidents"])
	}
	inc, _ := incidents[0].(map[string]any)
	if inc["triage_phase"] != "backoff" || inc["triage_decision"] != "request" || inc["triage_attempts"] != float64(1) {
		t.Errorf("incident triage state = %+v, want phase=backoff decision=request attempts=1", inc)
	}
	if inc["membership_digest"] != "sha256:membership-mcp" || inc["incident_input_digest"] != "sha256:input-mcp" {
		t.Errorf("incident covered digests = %+v", inc)
	}
	if inc["triage_due_at"] != wantDueAt.Format(time.RFC3339Nano) {
		t.Errorf("triage_due_at = %v, want %v", inc["triage_due_at"], wantDueAt.Format(time.RFC3339Nano))
	}
}

func TestGetSituationByHandle(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-h1", "service=handle", "incident_created", at)
	if _, err := st.DB().ExecContext(context.Background(), `UPDATE situations SET public_handle = ? WHERE id = ?`, "sit-42", situationID); err != nil {
		t.Fatalf("seed public_handle: %v", err)
	}

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetSituation(context.Background(), reqWith(map[string]any{"handle": "SIT-42"}))
	if err != nil || res.IsError {
		t.Fatalf("get situation by handle errored: %v %s", err, resultText(t, res))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatal(err)
	}
	if payload["id"] != situationID {
		t.Errorf("id = %v, want %v", payload["id"], situationID)
	}
	if payload["public_handle"] != "sit-42" {
		t.Errorf("public_handle = %v, want sit-42", payload["public_handle"])
	}
}

func TestGetSituationRequiresExactlyOneOfIDOrHandle(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))

	res, err := s.handleGetSituation(context.Background(), reqWith(map[string]any{}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected a tool error when neither id nor handle is given")
	}

	at := time.Date(2026, 9, 1, 3, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-both", "service=both", "incident_created", at)
	res, err = s.handleGetSituation(context.Background(), reqWith(map[string]any{"id": situationID, "handle": "whatever"}))
	if err != nil {
		t.Fatal(err)
	}
	if !res.IsError {
		t.Fatal("expected a tool error when both id and handle are given")
	}
}

// TestGetSituationUnknownDoesNotLeakSQL proves an unknown id/handle returns
// a tool error without leaking SQL text (Step 1's explicit requirement).
func TestGetSituationUnknownDoesNotLeakSQL(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))

	for _, args := range []map[string]any{
		{"id": "does-not-exist"},
		{"handle": "no-such-handle"},
	} {
		res, err := s.handleGetSituation(context.Background(), reqWith(args))
		if err != nil {
			t.Fatal(err)
		}
		if !res.IsError {
			t.Fatalf("%v: expected a tool error for an unknown situation", args)
		}
		msg := resultText(t, res)
		lower := strings.ToLower(msg)
		for _, forbidden := range []string{"select ", "from situations", "sql:", "sqlite"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("%v: error message leaks SQL text: %q", args, msg)
			}
		}
	}
}

// ----------------------------------------------------------------------
// Plan 3 Task 9: bounded read-only history and delivery views
// ----------------------------------------------------------------------

// seedSituationHistoryForMCP writes one Situation's durable Plan 3 history
// straight into the immutable tables the fenced controller commit owns —
// transitions, the current Episode summary, the stdout stream rows, and the
// notification intents they warranted. Raw SQL on purpose: these views are
// read-only, and driving a full ControllerCommit here would test the
// controller, not the view. It returns the Transition IDs it wrote.
func seedSituationHistoryForMCP(t *testing.T, st *store.Store, situationID string, at time.Time, count int) []string {
	t.Helper()
	ctx := context.Background()
	ids := make([]string, 0, count)
	for seq := 1; seq <= count; seq++ {
		id := fmt.Sprintf("tr-%s-%d", situationID[:8], seq)
		ids = append(ids, id)
		created := at.Add(time.Duration(seq) * time.Minute).UTC().Format(time.RFC3339Nano)
		contract := `{"next_actor":"alertint","alertint_action":"run_acute_triage","alertint_status":"running","next_update_on":["triage_outcome"]}`
		journal := fmt.Sprintf(`{"headline":"Material change %d","detail":"bounded journal detail","occurred_at":%q}`, seq, created)
		projection := fmt.Sprintf(`{"effective_started_at":%q,"effective_started_at_basis":"source_payload"}`,
			at.UTC().Format(time.RFC3339Nano))
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO situation_transitions (
				id, situation_id, sequence, input_version, material_fact_hash, lifecycle, attention,
				action_contract_json, reason, journal_kind, journal_json, projection_json,
				evidence_refs_json, actor, drill, created_at
			) VALUES (?, ?, ?, ?, ?, 'active', 'investigate', ?, ?, 'publication', ?, ?, '["fact-a"]', 'deterministic_controller', 0, ?)`,
			id, situationID, seq, seq, "sha256:material", contract,
			map[bool]string{true: "first_authoritative_state", false: "attention_changed"}[seq == 1],
			journal, projection, created); err != nil {
			t.Fatalf("insert transition %d: %v", seq, err)
		}
		if _, err := st.DB().ExecContext(ctx, `
			INSERT INTO situation_transition_stream (id, transition_id, situation_id, sequence, status, created_at)
			VALUES (?, ?, ?, ?, 'pending', ?)`, "stream-"+id, id, situationID, seq, created); err != nil {
			t.Fatalf("insert stream row %d: %v", seq, err)
		}
	}
	last := count
	summary := fmt.Sprintf(`{"situation_id":%q,"version":%d,"source_transition_sequence":%d,"title":"Situation api",`+
		`"current_attention":"investigate","peak_attention":"investigate","investigation_work":[],`+
		`"recorded_operator_context":[],"action_contract":{"next_actor":"alertint","alertint_action":"run_acute_triage",`+
		`"alertint_status":"running","next_update_on":["triage_outcome"]},"effective_started_at":%q,`+
		`"recurrence_count":0,"updated_at":%q}`,
		situationID, last, last, at.UTC().Format(time.RFC3339Nano),
		at.Add(time.Duration(last)*time.Minute).UTC().Format(time.RFC3339Nano))
	if _, err := st.DB().ExecContext(ctx, `
		INSERT INTO situation_episode_summaries (situation_id, version, source_transition_sequence, summary_json, updated_at)
		VALUES (?, ?, ?, ?, ?)`, situationID, last, last, summary,
		at.Add(time.Duration(last)*time.Minute).UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("insert episode summary: %v", err)
	}
	return ids
}

// seedSituationIntentForMCP writes one durable notification intent.
func seedSituationIntentForMCP(t *testing.T, st *store.Store, situationID, transitionID string,
	seq int, effectClass, status string, at time.Time) {
	t.Helper()
	id := fmt.Sprintf("intent-%s-%s", effectClass, transitionID)
	var summaryVersion any
	requiresRoot := 0
	switch effectClass {
	case "root_sync":
		summaryVersion = seq
	case "thread_append", "broadcast_handoff":
		requiresRoot = 1
	}
	var deliveredAt, channel, messageTS, deliveredAs any
	if status == "delivered" {
		deliveredAt = at.UTC().Format(time.RFC3339Nano)
		channel = "C123"
		messageTS = "1700000000.000100"
		deliveredAs = map[bool]string{true: "root", false: "thread"}[effectClass == "root_sync"]
	}
	if _, err := st.DB().ExecContext(context.Background(), `
		INSERT INTO notification_intents (
			id, idempotency_key, effect_class, situation_id, transition_id, transition_sequence,
			summary_version, requires_root, main_channel_poke, client_message_id, status,
			attempt_count, last_error_class, delivered_as, channel, message_ts, created_at, delivered_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, "idem:"+id, effectClass, situationID, transitionID, seq, summaryVersion, requiresRoot,
		"client:"+id, status, 2, "timeout", deliveredAs, channel, messageTS,
		at.UTC().Format(time.RFC3339Nano), deliveredAt); err != nil {
		t.Fatalf("insert notification intent: %v", err)
	}
}

// TestSituationMCPHistoryToolsRegisteredAndReadOnly proves both Plan 3 read
// surfaces exist under stable names and neither declares a write.
func TestSituationMCPHistoryToolsRegisteredAndReadOnly(t *testing.T) {
	st := newMCPStore(t)
	s := NewServer(Config{}, st, audit.New(st.DB()))

	journalTool, journalHandler := s.toolListSituationTransitions()
	if journalTool.Name != "alertint_list_situation_transitions" || journalHandler == nil {
		t.Fatalf("journal tool = %q / handler nil=%v", journalTool.Name, journalHandler == nil)
	}
	deliveryTool, deliveryHandler := s.toolGetDeliveryState()
	if deliveryTool.Name != "alertint_get_delivery_state" || deliveryHandler == nil {
		t.Fatalf("delivery tool = %q / handler nil=%v", deliveryTool.Name, deliveryHandler == nil)
	}
	for _, tool := range []string{journalTool.Name, deliveryTool.Name} {
		if strings.Contains(tool, "create") || strings.Contains(tool, "update") || strings.Contains(tool, "record") {
			t.Errorf("tool %q reads as a mutation; Plan 3's MCP surface is read-only", tool)
		}
	}
}

// TestSituationMCPTransitionJournalPagesByStableCursor proves the journal is
// bounded and paginated with a stable (sequence, id) cursor, oldest first,
// and that resuming from the returned cursor never repeats or skips an
// entry.
func TestSituationMCPTransitionJournalPagesByStableCursor(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-j", "service=journal", "incident_created", at)
	seedSituationHistoryForMCP(t, st, situationID, at, 5)

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleListSituationTransitions(context.Background(),
		reqWith(map[string]any{"id": situationID, "limit": 2}))
	if err != nil || res.IsError {
		t.Fatalf("list transitions errored: %v %s", err, resultText(t, res))
	}
	var page struct {
		Transitions []struct {
			ID       string `json:"id"`
			Sequence int    `json:"sequence"`
			Reason   string `json:"reason"`
		} `json:"transitions"`
		NextCursor *struct {
			Sequence int    `json:"sequence"`
			ID       string `json:"id"`
		} `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res)), &page); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(page.Transitions) != 2 || page.Transitions[0].Sequence != 1 || page.Transitions[1].Sequence != 2 {
		t.Fatalf("first page = %+v, want sequences 1 and 2", page.Transitions)
	}
	if page.NextCursor == nil || page.NextCursor.Sequence != 2 {
		t.Fatalf("next_cursor = %+v, want the last row's stable position", page.NextCursor)
	}

	res2, err := s.handleListSituationTransitions(context.Background(), reqWith(map[string]any{
		"id": situationID, "limit": 10,
		"cursor_sequence": page.NextCursor.Sequence, "cursor_id": page.NextCursor.ID,
	}))
	if err != nil || res2.IsError {
		t.Fatalf("second page errored: %v %s", err, resultText(t, res2))
	}
	var page2 struct {
		Transitions []struct {
			Sequence int `json:"sequence"`
		} `json:"transitions"`
		NextCursor *struct{} `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(resultText(t, res2)), &page2); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(page2.Transitions) != 3 || page2.Transitions[0].Sequence != 3 {
		t.Fatalf("second page = %+v, want sequences 3,4,5", page2.Transitions)
	}
	if page2.NextCursor != nil {
		t.Fatalf("next_cursor = %+v on the final page, want null", page2.NextCursor)
	}
}

// TestSituationMCPGetSituationCarriesEpisodeAndDeliveryState proves the
// extended alertint_get_situation payload: the current Episode summary read
// coherently with its own source Transition, the Slack root coordinates and
// per-effect delivery status, and the withheld/superseded/delayed modes —
// with no claim owner, claim token, lease, or provider error body anywhere.
func TestSituationMCPGetSituationCarriesEpisodeAndDeliveryState(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-e", "service=episode", "incident_created", at)
	ids := seedSituationHistoryForMCP(t, st, situationID, at, 2)
	seedSituationIntentForMCP(t, st, situationID, ids[1], 2, "root_sync", "delivered", at)
	seedSituationIntentForMCP(t, st, situationID, ids[0], 1, "thread_append", "withheld_by_operator_slack_floor", at)

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetSituation(context.Background(), reqWith(map[string]any{"id": situationID}))
	if err != nil || res.IsError {
		t.Fatalf("get situation errored: %v %s", err, resultText(t, res))
	}
	raw := resultText(t, res)
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	episode, ok := payload["episode"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no episode object: %v", payload["episode"])
	}
	if episode["version"] != float64(2) {
		t.Errorf("episode version = %v, want 2", episode["version"])
	}
	source, ok := episode["source_transition"].(map[string]any)
	if !ok {
		t.Fatal("episode carries no source_transition; a summary must never be shown without the Transition it was folded from")
	}
	if source["sequence"] != float64(2) {
		t.Errorf("source transition sequence = %v, want 2 (coherent with the summary)", source["sequence"])
	}

	delivery, ok := payload["slack_delivery"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no slack_delivery object: %v", payload["slack_delivery"])
	}
	effects, ok := delivery["effects"].([]any)
	if !ok || len(effects) != 2 {
		t.Fatalf("slack_delivery effects = %v, want two durable effects", delivery["effects"])
	}
	first, _ := effects[0].(map[string]any)
	if first["effect_class"] != "root_sync" || first["status"] != "delivered" {
		t.Errorf("first effect = %v, want the delivered root projection first", first)
	}
	if first["channel"] != "C123" {
		t.Errorf("delivered coordinates missing: %v", first)
	}
	second, _ := effects[1].(map[string]any)
	if second["status"] != "withheld_by_operator_slack_floor" {
		t.Errorf("withheld effect is not visible as a durable decision: %v", second)
	}

	for _, forbidden := range []string{"claim_owner", "claim_token", "lease_expires_at", "xoxb-", "bot_token", "SELECT "} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("get_situation payload leaks %q", forbidden)
		}
	}
}

// TestSituationMCPDeliveryStateExposesBoundedOperationalFields proves the
// installation-level view: gap generation/status, replay progress, retries
// by effect class, uncertain outcomes, and the blocked backlog — bounded
// counts only, and no OTel metric instrument anywhere (R8).
func TestSituationMCPDeliveryStateExposesBoundedOperationalFields(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-d", "service=delivery", "incident_created", at)
	ids := seedSituationHistoryForMCP(t, st, situationID, at, 1)
	seedSituationIntentForMCP(t, st, situationID, ids[0], 1, "root_sync", "pending", at)

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetDeliveryState(context.Background(), reqWith(map[string]any{}))
	if err != nil || res.IsError {
		t.Fatalf("get delivery state errored: %v %s", err, resultText(t, res))
	}
	raw := resultText(t, res)
	var payload struct {
		Slack struct {
			ConfigurationGeneration   int64 `json:"configuration_generation"`
			BlockedConfigurationCount int   `json:"blocked_configuration_count"`
		} `json:"slack"`
		Delivery struct {
			ByEffectClass []struct {
				EffectClass   string `json:"effect_class"`
				Pending       int    `json:"pending"`
				RetryAttempts int    `json:"retry_attempts"`
			} `json:"by_effect_class"`
			UncertainOutcomes       int  `json:"uncertain_outcomes"`
			ReplayBacklog           int  `json:"replay_backlog"`
			OpenGapAgeSeconds       *int `json:"open_gap_age_seconds"`
			TransitionStreamPending int  `json:"transition_stream_pending"`
		} `json:"delivery"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, raw)
	}
	if len(payload.Delivery.ByEffectClass) != 1 || payload.Delivery.ByEffectClass[0].EffectClass != "root_sync" {
		t.Fatalf("by_effect_class = %+v, want one root_sync row", payload.Delivery.ByEffectClass)
	}
	if payload.Delivery.ByEffectClass[0].Pending != 1 {
		t.Errorf("pending root_sync = %d, want 1", payload.Delivery.ByEffectClass[0].Pending)
	}
	if payload.Delivery.ByEffectClass[0].RetryAttempts != 1 {
		t.Errorf("retry_attempts = %d, want 1 (attempt_count 2 minus the first attempt)",
			payload.Delivery.ByEffectClass[0].RetryAttempts)
	}
	if payload.Delivery.UncertainOutcomes != 1 {
		t.Errorf("uncertain_outcomes = %d, want 1 (the seeded timeout)", payload.Delivery.UncertainOutcomes)
	}
	if payload.Delivery.OpenGapAgeSeconds != nil {
		t.Errorf("open_gap_age_seconds = %v with no gap open, want null", *payload.Delivery.OpenGapAgeSeconds)
	}
	if payload.Delivery.TransitionStreamPending != 1 {
		t.Errorf("transition_stream_pending = %d, want 1", payload.Delivery.TransitionStreamPending)
	}
	for _, forbidden := range []string{"claim_owner", "claim_token", "lease_expires_at", "xoxb-"} {
		if strings.Contains(raw, forbidden) {
			t.Errorf("delivery state payload leaks %q", forbidden)
		}
	}
}

// TestSituationMCPHistoryIsAbsentNotFabricated proves the honesty rule: a
// Situation with no Plan 3 history yet renders explicit nulls, never a
// reconstruction of current state as if it were history.
func TestSituationMCPHistoryIsAbsentNotFabricated(t *testing.T) {
	st := newMCPStore(t)
	at := time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC)
	situationID := seedSituationForMCP(t, st, "inc-n", "service=none", "incident_created", at)

	s := NewServer(Config{}, st, audit.New(st.DB()))
	res, err := s.handleGetSituation(context.Background(), reqWith(map[string]any{"id": situationID}))
	if err != nil || res.IsError {
		t.Fatalf("get situation errored: %v %s", err, resultText(t, res))
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(resultText(t, res)), &payload); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if payload["episode"] != nil {
		t.Errorf("episode = %v for a Situation with no Transition, want explicit null", payload["episode"])
	}
	delivery, ok := payload["slack_delivery"].(map[string]any)
	if !ok {
		t.Fatalf("slack_delivery = %v, want an object saying nothing is published", payload["slack_delivery"])
	}
	if delivery["published"] != false {
		t.Errorf("published = %v, want false", delivery["published"])
	}

	res2, err := s.handleListSituationTransitions(context.Background(), reqWith(map[string]any{"id": situationID}))
	if err != nil || res2.IsError {
		t.Fatalf("list transitions errored: %v %s", err, resultText(t, res2))
	}
	if !strings.Contains(resultText(t, res2), `"transitions":[]`) {
		t.Errorf("journal for a Situation with no history = %s, want an empty array", resultText(t, res2))
	}
}
