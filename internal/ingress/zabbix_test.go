// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/store"
)

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestParseZabbix_DecodesFullPayload(t *testing.T) {
	body := []byte(`{
		"event_id": "9134",
		"status": "PROBLEM",
		"severity": "High",
		"nseverity": "4",
		"host": "db01",
		"host_visible": "DB primary",
		"trigger_id": "22713",
		"trigger_name": "Disk space is critically low",
		"item_key": "vfs.fs.size[/,pused]",
		"item_value": "97.1",
		"tags": [{"tag":"service","value":"billing"},{"tag":"scope","value":"capacity"}],
		"clock": "2026.07.30 14:03:22",
		"recovery_clock": "",
		"generator_url": "https://zbx.example.com/tr_events.php?triggerid=22713&eventid=9134"
	}`)
	ev, err := ParseZabbix(body)
	if err != nil {
		t.Fatal(err)
	}
	if ev.EventID != "9134" || ev.Status != "PROBLEM" || ev.Host != "db01" {
		t.Fatalf("core fields wrong: %+v", ev)
	}
	if len(ev.Tags) != 2 || ev.Tags[0].Tag != "service" || ev.Tags[0].Value != "billing" {
		t.Fatalf("tags wrong: %+v", ev.Tags)
	}
	if ev.NSeverity != "4" {
		t.Fatalf("nseverity: %q", ev.NSeverity)
	}
}

func TestParseZabbix_Rejections(t *testing.T) {
	cases := []struct {
		name, body, wantErr string
	}{
		{"invalid json", `{`, "invalid JSON"},
		{"missing event_id", `{"status":"PROBLEM","host":"h","trigger_name":"t"}`, "event_id is required"},
		{"bad status", `{"event_id":"1","status":"NOPE","host":"h","trigger_name":"t"}`, `status "NOPE"`},
		{"missing host", `{"event_id":"1","status":"PROBLEM","trigger_name":"t"}`, "host is required"},
		{"missing trigger_name", `{"event_id":"1","status":"PROBLEM","host":"h"}`, "trigger_name is required"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseZabbix([]byte(c.body))
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

func TestParseZabbix_EmptyTagsTolerated(t *testing.T) {
	for _, tags := range []string{`[]`, `null`} {
		body := []byte(`{"event_id":"1","status":"RESOLVED","host":"h","trigger_name":"t","tags":` + tags + `}`)
		ev, err := ParseZabbix(body)
		if err != nil {
			t.Fatalf("tags=%s: %v", tags, err)
		}
		if len(ev.Tags) != 0 {
			t.Fatalf("tags=%s: want empty, got %+v", tags, ev.Tags)
		}
	}
}

func TestZabbixReceiver_MapsProblemToFiringAlert(t *testing.T) {
	st := newTestStore(t)
	var sunk []store.Alert
	sink := func(ctx context.Context, a store.Alert) error { sunk = append(sunk, a); return nil }
	r := NewZabbixReceiver(st, "tok", sink, slog.Default())

	if r.Route() != "POST /webhook/zabbix" || r.Name() != "zabbix" {
		t.Fatalf("identity: route=%q name=%q", r.Route(), r.Name())
	}

	body := []byte(`{"event_id":"9134","status":"PROBLEM","severity":"High","nseverity":"4",
		"host":"db01","host_visible":"DB primary","trigger_id":"22713",
		"trigger_name":"Disk space is critically low","item_key":"vfs.fs.size[/,pused]","item_value":"97.1",
		"tags":[{"tag":"service","value":"billing"},{"tag":"bad key!","value":"x"},{"tag":"severity","value":"evil"}],
		"clock":"2026.07.30 14:03:22","recovery_clock":"","generator_url":"https://zbx/tr?x=1"}`)
	sum, err := r.Ingest(context.Background(), body)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Kind != "alert.received" {
		t.Fatalf("audit kind: %q", sum.Kind)
	}
	if len(sunk) != 1 {
		t.Fatalf("sink calls: %d", len(sunk))
	}
	a := sunk[0]
	if a.Fingerprint != "zabbix:9134" {
		t.Fatalf("fingerprint: %q", a.Fingerprint)
	}
	if a.Status != "firing" || a.EndsAt != nil {
		t.Fatalf("status: %q endsAt=%v", a.Status, a.EndsAt)
	}
	wantLabels := map[string]string{
		"alertname":         "Disk space is critically low",
		"host":              "db01",
		"severity":          "High", // verbatim: Rank("high") > 0
		"zabbix_trigger_id": "22713",
		"service":           "billing",
		"bad_key_":          "x", // sanitised to [a-zA-Z0-9_]
	}
	for k, v := range wantLabels {
		if a.Labels[k] != v {
			t.Errorf("label %s: got %q want %q", k, a.Labels[k], v)
		}
	}
	if _, collided := a.Labels["severity"]; !collided || a.Labels["severity"] == "evil" {
		t.Error("a tag colliding with a core label must be skipped, core label wins")
	}
	wantAnn := map[string]string{
		"trigger_name":    "Disk space is critically low",
		"item_key":        "vfs.fs.size[/,pused]",
		"item_value":      "97.1",
		"zabbix_event_id": "9134",
		"host_visible":    "DB primary",
		"generator_url":   "https://zbx/tr?x=1",
		"clock":           "2026.07.30 14:03:22",
	}
	for k, v := range wantAnn {
		if a.Annotations[k] != v {
			t.Errorf("annotation %s: got %q want %q", k, a.Annotations[k], v)
		}
	}
	if _, ok := a.Annotations["severity_display"]; ok {
		t.Error("severity_display must be absent when the name ranked verbatim")
	}
	if a.StartsAt.IsZero() {
		t.Error("StartsAt must be receipt time, not zero")
	}
}

func TestZabbixReceiver_ResolvedDedupsOntoFiringRow(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	problem := []byte(`{"event_id":"77","status":"PROBLEM","severity":"Warning","nseverity":"2","host":"h1","trigger_id":"5","trigger_name":"T"}`)
	resolved := []byte(`{"event_id":"77","status":"RESOLVED","severity":"Warning","nseverity":"2","host":"h1","trigger_id":"5","trigger_name":"T","recovery_clock":"2026.07.30 15:00:00"}`)
	if _, err := r.Ingest(context.Background(), problem); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Ingest(context.Background(), resolved); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetAlertByFingerprint(context.Background(), "zabbix:77")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "resolved" || got.EndsAt == nil {
		t.Fatalf("resolution must upsert onto the firing row: status=%q endsAt=%v", got.Status, got.EndsAt)
	}
}

func TestZabbixReceiver_NSeverityFallbackForRenamedSeverity(t *testing.T) {
	st := newTestStore(t)
	var sunk []store.Alert
	sink := func(ctx context.Context, a store.Alert) error { sunk = append(sunk, a); return nil }
	r := NewZabbixReceiver(st, "tok", sink, slog.Default())
	body := []byte(`{"event_id":"88","status":"PROBLEM","severity":"P1","nseverity":"5","host":"h1","trigger_id":"5","trigger_name":"T"}`)
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	a := sunk[0]
	if a.Labels["severity"] != "disaster" {
		t.Fatalf("renamed severity must canonicalise via nseverity: got %q want disaster", a.Labels["severity"])
	}
	if a.Annotations["severity_display"] != "P1" {
		t.Fatalf("operator's word must be preserved: %q", a.Annotations["severity_display"])
	}
}

func TestZabbixReceiver_BadPayloadIsIngestError(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	if _, err := r.Ingest(context.Background(), []byte(`{"status":"PROBLEM"}`)); err == nil {
		t.Fatal("want parse error (maps to 400)")
	}
}

func TestServer_MountsZabbixRouteWithOwnToken(t *testing.T) {
	st := newTestStore(t)
	host, err := New(Options{
		Store:   st,
		Auditor: audit.New(st.DB()),
		Receivers: []Receiver{
			NewAlertReceiver(st, "atok", nil, slog.Default()),
			NewZabbixReceiver(st, "ztok", nil, slog.Default()),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(host.Handler())
	defer ts.Close()

	body := `{"event_id":"1","status":"PROBLEM","severity":"High","nseverity":"4","host":"h","trigger_id":"9","trigger_name":"T"}`

	// zabbix token on the zabbix route: accepted
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/webhook/zabbix", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer ztok")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("zabbix route with its token: %d", resp.StatusCode)
	}

	// alertmanager token on the zabbix route: rejected
	req2, _ := http.NewRequest(http.MethodPost, ts.URL+"/webhook/zabbix", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer atok")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("cross-token must 401, got %d", resp2.StatusCode)
	}
}
