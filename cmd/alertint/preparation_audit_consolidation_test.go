// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPreparationConsolidationAuditsCommittedFanoutIdentities(t *testing.T) {
	f := newPrepE2EFixture(t)
	prom := newFakePrometheusServer(t)
	rt := buildPrepE2ERuntime(t, f, prom.srv.URL, &prepE2ELLM{})
	f.postAlert("checkout-audit", "HighErrorRate", "fp-audit")
	f.drainFoundation()
	f.markReady(f.soleIncidentID())
	if err := rt.prt.Recover(f.ctx); err != nil {
		t.Fatal(err)
	}
	f.clock.advance(time.Minute)
	if _, err := rt.cw.Drain(f.ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.prt.Drain(f.ctx); err != nil {
		t.Fatal(err)
	}
	var raw string
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT payload_json FROM audit_log
		WHERE kind='semantic_profile.change_delivered' ORDER BY seq DESC LIMIT 1`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var payload struct {
		ChangeID     string   `json:"change_id"`
		SignatureKey string   `json:"signature_key"`
		VersionID    string   `json:"version_id"`
		SituationIDs []string `json:"situation_ids"`
		Acknowledged bool     `json:"acknowledged"`
	}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ChangeID == "" || payload.SignatureKey == "" || payload.VersionID == "" || !payload.Acknowledged || len(payload.SituationIDs) != 1 || payload.SituationIDs[0] != f.soleSituationID() {
		t.Fatalf("audit must name the committed fanout: %s", raw)
	}
	var count int
	if err := f.st.DB().QueryRowContext(f.ctx, `SELECT COUNT(*) FROM semantic_profile_change_deliveries d
		JOIN semantic_profile_changes c ON c.id=d.change_id
		WHERE c.id=? AND c.signature_key=? AND c.version_id=? AND d.situation_id=?`,
		payload.ChangeID, payload.SignatureKey, payload.VersionID, payload.SituationIDs[0]).Scan(&count); err != nil || count != 1 {
		t.Fatalf("audit does not match durable fanout: count=%d err=%v", count, err)
	}
}
