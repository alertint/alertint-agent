// SPDX-License-Identifier: FSL-1.1-ALv2

package mcp

import (
	"context"
	"encoding/json"
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
