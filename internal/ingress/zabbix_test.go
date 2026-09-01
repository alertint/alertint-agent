// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/audit"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
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
	var wakes int
	r := NewZabbixReceiver(st, "tok", func() { wakes++ }, slog.Default())

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
	if wakes != 1 {
		t.Fatalf("wake calls: %d, want 1", wakes)
	}
	assertTableCount(t, st.DB(), "alert_deliveries", 1)
	a, err := st.GetAlertByFingerprint(context.Background(), "zabbix:9134")
	if err != nil {
		t.Fatal(err)
	}
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

func TestZabbixReceiverHandsOffPerHostIdentityAcrossResolution(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())

	bodies := [][]byte{
		[]byte(`{"event_id":"77","status":"PROBLEM","severity":"Warning","nseverity":"2","host":"db01","trigger_name":"Disk low"}`),
		[]byte(`{"event_id":"77","status":"RESOLVED","severity":"Warning","nseverity":"2","host":"db01","trigger_name":"Disk low"}`),
		[]byte(`{"event_id":"78","status":"PROBLEM","severity":"Warning","nseverity":"2","host":"db02","trigger_name":"Disk low"}`),
	}
	for _, body := range bodies {
		if _, err := r.Ingest(context.Background(), body); err != nil {
			t.Fatal(err)
		}
	}

	claims := claimAll(t, st)
	if len(claims) != 3 {
		t.Fatalf("claimed dispatches = %d, want 3", len(claims))
	}
	problem := findDelivery(t, claims, "zabbix:77", "firing")
	resolved := findDelivery(t, claims, "zabbix:77", "resolved")
	secondHost := findDelivery(t, claims, "zabbix:78", "firing")

	if got := problem.Delivery.ReceiverGroupingIdentity; got != "host=db01" {
		t.Fatalf("problem identity = %q, want host=db01", got)
	}
	if got := resolved.Delivery.ReceiverGroupingIdentity; got != problem.Delivery.ReceiverGroupingIdentity {
		t.Fatalf("resolved identity = %q, want firing identity %q", got, problem.Delivery.ReceiverGroupingIdentity)
	}
	if got := secondHost.Delivery.ReceiverGroupingIdentity; got != "host=db02" || got == problem.Delivery.ReceiverGroupingIdentity {
		t.Fatalf("second host identity = %q, want distinct host=db02", got)
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
	firing, err := st.GetAlertByFingerprint(context.Background(), "zabbix:77")
	if err != nil {
		t.Fatal(err)
	}
	originalStartsAt := firing.StartsAt

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
	if !got.StartsAt.Equal(originalStartsAt) {
		t.Errorf("StartsAt must be preserved from the firing delivery, got %v want %v", got.StartsAt, originalStartsAt)
	}
}

func TestZabbixReceiver_NSeverityFallbackForRenamedSeverity(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	body := []byte(`{"event_id":"88","status":"PROBLEM","severity":"P1","nseverity":"5","host":"h1","trigger_id":"5","trigger_name":"T"}`)
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	a, err := st.GetAlertByFingerprint(context.Background(), "zabbix:88")
	if err != nil {
		t.Fatal(err)
	}
	if a.Labels["severity"] != "disaster" {
		t.Fatalf("renamed severity must canonicalise via nseverity: got %q want disaster", a.Labels["severity"])
	}
	if a.Annotations["severity_display"] != "P1" {
		t.Fatalf("operator's word must be preserved: %q", a.Annotations["severity_display"])
	}
}

func TestZabbixReceiver_UnrecognizedSeverityWithNoNSeverityFallback(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	body := []byte(`{"event_id":"99","status":"PROBLEM","severity":"Not classified","nseverity":"0","host":"h1","trigger_id":"5","trigger_name":"T"}`)
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	a, err := st.GetAlertByFingerprint(context.Background(), "zabbix:99")
	if err != nil {
		t.Fatal(err)
	}
	if a.Labels["severity"] != "Not classified" {
		t.Fatalf("an unrecognized name with no valid nseverity fallback must stay verbatim: got %q", a.Labels["severity"])
	}
	if _, ok := a.Annotations["severity_display"]; ok {
		t.Error("severity_display must be absent when no nseverity fallback fired")
	}
}

func TestZabbixReceiver_TagCollidesWithAnotherTag(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	body := []byte(`{"event_id":"100","status":"PROBLEM","severity":"High","host":"h1","trigger_id":"5","trigger_name":"T",
		"tags":[{"tag":"foo-bar","value":"first"},{"tag":"foo_bar","value":"second"}]}`)
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	a, err := st.GetAlertByFingerprint(context.Background(), "zabbix:100")
	if err != nil {
		t.Fatal(err)
	}
	if a.Labels["foo_bar"] != "first" {
		t.Fatalf("the first tag to claim a sanitised key must win over a later colliding tag: got %q", a.Labels["foo_bar"])
	}
}

func TestZabbixReceiver_BadPayloadIsIngestError(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	if _, err := r.Ingest(context.Background(), []byte(`{"status":"PROBLEM"}`)); err == nil {
		t.Fatal("want parse error (maps to 400)")
	}
}

// TestZabbixReceiver_TriggerIDBecomesSignalIDOnly proves trigger_id is
// persisted as SourceProvenance.SignalID and never doubles as a
// SignalVersion or an episode identity — the webhook cannot prove the
// trigger configuration version, so that field must stay unavailable.
func TestZabbixReceiver_TriggerIDBecomesSignalIDOnly(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	body := []byte(`{"event_id":"200","status":"PROBLEM","severity":"High","host":"h1","trigger_id":"555","trigger_name":"T"}`)
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	d := findDelivery(t, claimAll(t, st), "zabbix:200", "firing")
	if d.Delivery.SourceProvenance.SignalID == nil || *d.Delivery.SourceProvenance.SignalID != "555" {
		t.Fatalf("SignalID = %v, want \"555\"", d.Delivery.SourceProvenance.SignalID)
	}
	if d.Delivery.SourceProvenance.SignalVersion != nil {
		t.Fatalf("SignalVersion must stay unavailable, got %v", *d.Delivery.SourceProvenance.SignalVersion)
	}
	if d.Delivery.SourceEpisodeKey != "zabbix:200" {
		t.Fatalf("SourceEpisodeKey = %q, want zabbix:200 (trigger_id must never leak into episode identity)", d.Delivery.SourceEpisodeKey)
	}
}

// TestZabbixReceiver_ResolutionReusesFirstEpisodeStart proves a RESOLVED
// delivery's SourceStartedAt reuses the first PROBLEM's established episode
// start rather than recomputing a fresh receipt time, while still recording
// distinct delivery IDs and its own receipt-based SourceResolvedAt.
func TestZabbixReceiver_ResolutionReusesFirstEpisodeStart(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	problem := []byte(`{"event_id":"300","status":"PROBLEM","severity":"High","host":"h1","trigger_id":"5","trigger_name":"T"}`)
	resolved := []byte(`{"event_id":"300","status":"RESOLVED","severity":"High","host":"h1","trigger_id":"5","trigger_name":"T"}`)
	if _, err := r.Ingest(context.Background(), problem); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Ingest(context.Background(), resolved); err != nil {
		t.Fatal(err)
	}

	claims := claimAll(t, st)
	firing := findDelivery(t, claims, "zabbix:300", "firing")
	res := findDelivery(t, claims, "zabbix:300", "resolved")

	if firing.Delivery.ID == res.Delivery.ID {
		t.Fatal("firing and resolved deliveries must have distinct IDs")
	}
	if firing.Delivery.SourceEpisodeKey != res.Delivery.SourceEpisodeKey {
		t.Fatalf("episode key must stay stable: firing=%q resolved=%q", firing.Delivery.SourceEpisodeKey, res.Delivery.SourceEpisodeKey)
	}
	if firing.Delivery.SourceStartedAt == nil || res.Delivery.SourceStartedAt == nil {
		t.Fatal("both deliveries must carry a SourceStartedAt")
	}
	if !firing.Delivery.SourceStartedAt.Equal(*res.Delivery.SourceStartedAt) {
		t.Fatalf("resolved delivery must reuse the first episode start: firing=%v resolved=%v",
			*firing.Delivery.SourceStartedAt, *res.Delivery.SourceStartedAt)
	}
	if res.Delivery.SourceResolvedAt == nil {
		t.Fatal("resolved delivery must carry a SourceResolvedAt")
	}

	// Neither Zabbix time is ever payload-derived (ADR-0031 forbids parsing
	// clock/recovery_clock), including when a delivery reuses the first
	// episode's established start — reuse must never silently relabel that
	// basis as source_payload.
	if firing.Delivery.StartedAtBasis != situationmodel.SourceTimeBasisReceiptFallback {
		t.Fatalf("firing StartedAtBasis = %q, want receipt_fallback", firing.Delivery.StartedAtBasis)
	}
	if firing.Delivery.ResolvedAtBasis != situationmodel.SourceTimeBasisMissing {
		t.Fatalf("firing ResolvedAtBasis = %q, want missing", firing.Delivery.ResolvedAtBasis)
	}
	if res.Delivery.StartedAtBasis != situationmodel.SourceTimeBasisReceiptFallback {
		t.Fatalf("resolved StartedAtBasis = %q, want receipt_fallback (reuse must not relabel the basis)", res.Delivery.StartedAtBasis)
	}
	if res.Delivery.ResolvedAtBasis != situationmodel.SourceTimeBasisReceiptFallback {
		t.Fatalf("resolved ResolvedAtBasis = %q, want receipt_fallback", res.Delivery.ResolvedAtBasis)
	}
}

// TestZabbixReceiver_RedeliveryIsIdempotent proves transport redelivery of
// the exact same Zabbix event body is a successful no-op.
func TestZabbixReceiver_RedeliveryIsIdempotent(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	body := []byte(`{"event_id":"400","status":"PROBLEM","severity":"High","host":"h1","trigger_id":"5","trigger_name":"T"}`)
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Ingest(context.Background(), body); err != nil {
		t.Fatal(err)
	}
	assertTableCount(t, st.DB(), "alert_deliveries", 1)
	assertTableCount(t, st.DB(), "alert_delivery_dispatches", 1)
}

// TestZabbixReceiver_EpisodeLookupFailureIsDurabilityError proves a Store
// read failure while resolving the episode start is a *DurabilityError
// (503), never treated as "no prior episode" (which would silently
// overwrite an established episode's start with a fresh receipt time).
func TestZabbixReceiver_EpisodeLookupFailureIsDurabilityError(t *testing.T) {
	st := newTestStore(t)
	r := NewZabbixReceiver(st, "tok", nil, slog.Default())
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	body := []byte(`{"event_id":"500","status":"PROBLEM","severity":"High","host":"h1","trigger_id":"5","trigger_name":"T"}`)
	_, err := r.Ingest(context.Background(), body)
	if err == nil {
		t.Fatal("want an error once the Store is unusable")
	}
	var durable *DurabilityError
	if !errors.As(err, &durable) {
		t.Fatalf("err = %v, want a *DurabilityError", err)
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
	ctx := context.Background()

	// zabbix token on the zabbix route: accepted
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/webhook/zabbix", strings.NewReader(body))
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
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL+"/webhook/zabbix", strings.NewReader(body))
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
