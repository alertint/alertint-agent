// SPDX-License-Identifier: FSL-1.1-ALv2

// Package ingress implements the Alertmanager v4 webhook receiver.
//
// The receiver is intentionally narrow:
//   - one route: POST /webhook/alertmanager
//   - bearer-token auth, constant-time compare
//   - 1 MiB body cap (http.MaxBytesReader)
//   - JSON-only (Content-Type guard)
//   - persist via store.UpsertAlertByFingerprint (latest-wins dedupe)
//   - one audit row per call: kind=alert.received
//   - hand off each persisted alert to the optional AlertSink
//     (Slice 05's correlator implements it; tests inject fakes)
//
// Sink errors are logged but never fail the HTTP response: alerts are
// already persisted by the time the sink runs, so 5xx would be misleading
// to Alertmanager.
package ingress

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/health"
	"github.com/alertint/alertint-agent/internal/store"
)

// MaxBodyBytes is the cap on inbound request bodies.
const MaxBodyBytes = 1 << 20 // 1 MiB

// Default HTTP server timeouts. cmd/alertint applies these when wiring
// up the http.Server.
const (
	DefaultReadTimeout     = 10 * time.Second
	DefaultWriteTimeout    = 10 * time.Second
	DefaultIdleTimeout     = 60 * time.Second
	DefaultShutdownTimeout = 10 * time.Second
)

// AlertSink receives each alert after it has been persisted. The
// correlator (Slice 05) implements this; webhook tests inject fakes.
// A nil sink means "skip handoff".
type AlertSink func(ctx context.Context, alert store.Alert) error

// Webhook is the Alertmanager webhook receiver.
type Webhook struct {
	store   *store.Store
	auditor *audit.Auditor
	sink    AlertSink
	token   []byte
	logger  *slog.Logger
	health  *health.Registry
	now     func() time.Time
	newID   func() string
}

// Options configures a Webhook.
type Options struct {
	Store   *store.Store
	Auditor *audit.Auditor
	Sink    AlertSink    // optional
	Token   string       // bearer token; required
	Logger  *slog.Logger // optional; defaults to slog.Default()
	// Health is optional; when set, GET /health includes per-integration
	// connectivity statuses (cached by the registry's TTL).
	Health *health.Registry
}

// New constructs a Webhook. It returns an error if any required field is
// missing.
func New(opts Options) (*Webhook, error) {
	if opts.Store == nil {
		return nil, errors.New("ingress: Store is required")
	}
	if opts.Auditor == nil {
		return nil, errors.New("ingress: Auditor is required")
	}
	if strings.TrimSpace(opts.Token) == "" {
		return nil, errors.New("ingress: Token is required")
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Webhook{
		store:   opts.Store,
		auditor: opts.Auditor,
		sink:    opts.Sink,
		token:   []byte(opts.Token),
		logger:  logger,
		health:  opts.Health,
		now:     func() time.Time { return time.Now().UTC() },
		newID:   uuid.NewString,
	}, nil
}

// Handler returns the http.Handler for this webhook. Mounting is the
// caller's responsibility; the handler maps POST /webhook/alertmanager
// to the receiver and returns 405 / 404 for everything else.
//
// GET /health is unauthenticated. The top-level status reflects liveness
// (SQLite reachable): {"status":"ok"} (200) or {"status":"degraded"}
// (503). When a health registry is wired, the response also carries
// per-integration connectivity statuses — informational only, so a Slack
// or Prometheus outage never makes a container orchestrator restart the
// agent.
func (h *Webhook) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /webhook/alertmanager", h.handlePost)
	mux.HandleFunc("GET /health", h.handleHealth)
	return mux
}

func (h *Webhook) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := "ok"
	code := http.StatusOK
	if err := h.store.DB().PingContext(r.Context()); err != nil {
		status = "degraded"
		code = http.StatusServiceUnavailable
	}

	body := struct {
		Status       string          `json:"status"`
		Integrations []health.Status `json:"integrations,omitempty"`
	}{
		Status:       status,
		Integrations: h.health.Run(r.Context()),
	}
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		h.logger.Warn("ingress: encode health response", "err", err)
	}
}

// AlertmanagerPayload is the v4 webhook envelope. Fields we don't
// currently use are decoded but ignored.
type AlertmanagerPayload struct {
	Version           string              `json:"version"`
	GroupKey          string              `json:"groupKey"`
	Status            string              `json:"status"`
	Receiver          string              `json:"receiver"`
	GroupLabels       map[string]string   `json:"groupLabels"`
	CommonLabels      map[string]string   `json:"commonLabels"`
	CommonAnnotations map[string]string   `json:"commonAnnotations"`
	ExternalURL       string              `json:"externalURL"`
	Alerts            []AlertmanagerAlert `json:"alerts"`
}

// AlertmanagerAlert is an alert inside a v4 payload.
type AlertmanagerAlert struct {
	Status       string            `json:"status"`
	Labels       map[string]string `json:"labels"`
	Annotations  map[string]string `json:"annotations"`
	StartsAt     time.Time         `json:"startsAt"`
	EndsAt       time.Time         `json:"endsAt"`
	GeneratorURL string            `json:"generatorURL"`
	Fingerprint  string            `json:"fingerprint"`
}

func (h *Webhook) handlePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if !h.authenticate(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, MaxBodyBytes)
	defer func() { _ = r.Body.Close() }()

	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			http.Error(w, fmt.Sprintf("body too large (max %d bytes)", MaxBodyBytes), http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "could not read body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var payload AlertmanagerPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if payload.Version != "4" {
		http.Error(w, fmt.Sprintf("unsupported alertmanager payload version %q (want \"4\")", payload.Version), http.StatusBadRequest)
		return
	}

	// One INFO line per accepted POST so a quiet-but-receiving agent is
	// unambiguous; per-alert dedup/upsert detail stays at DEBUG (persistAlerts).
	h.logger.Info("webhook received",
		slog.Int("alerts", len(payload.Alerts)),
		slog.String("group", payload.GroupKey),
		slog.String("status", payload.Status),
	)

	if len(payload.Alerts) == 0 {
		// Empty alert lists are technically valid AM payloads, but they
		// give us nothing to do. Accept them with 204 and an audit row.
		h.auditCall(ctx, payload, nil)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	persisted, persistErrs := h.persistAlerts(ctx, payload.Alerts)

	// Audit before sink: the durable record is what matters; sink
	// failures are downstream concerns.
	h.auditCall(ctx, payload, persisted)

	if h.sink != nil {
		for _, a := range persisted {
			if err := h.sink(ctx, a); err != nil {
				h.logger.Warn("alert sink failed",
					slog.String("fingerprint", a.Fingerprint),
					slog.String("err", err.Error()),
				)
			}
		}
	}

	if len(persistErrs) > 0 {
		// Some alerts couldn't be persisted (validation or DB error).
		// We still return 204 because at least the audit row recorded
		// what we received; failing the response would cause AM to
		// retry the entire batch, which doesn't help. Log loudly.
		h.logger.Error("partial persist failure",
			slog.Int("alerts_received", len(payload.Alerts)),
			slog.Int("alerts_persisted", len(persisted)),
			slog.Int("alerts_failed", len(persistErrs)),
		)
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Webhook) authenticate(r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	got := []byte(strings.TrimSpace(auth[len(prefix):]))
	// ConstantTimeCompare requires equal length, hence the explicit
	// length check first to avoid an obvious early-exit timing leak.
	if len(got) != len(h.token) {
		return false
	}
	return subtle.ConstantTimeCompare(got, h.token) == 1
}

// persistAlerts upserts each alert. Returns the slice of successfully
// persisted alerts (in the order received) and a parallel slice of
// errors for those that failed.
func (h *Webhook) persistAlerts(ctx context.Context, in []AlertmanagerAlert) ([]store.Alert, []error) {
	persisted := make([]store.Alert, 0, len(in))
	var errs []error

	for _, a := range in {
		alert, err := h.toStoreAlert(a)
		if err != nil {
			errs = append(errs, err)
			h.logger.Warn("dropping invalid alert",
				slog.String("fingerprint", a.Fingerprint),
				slog.String("err", err.Error()),
			)
			continue
		}
		stored, err := h.store.UpsertAlertByFingerprint(ctx, alert)
		if err != nil {
			errs = append(errs, err)
			h.logger.Error("upsert alert failed",
				slog.String("fingerprint", alert.Fingerprint),
				slog.String("err", err.Error()),
			)
			continue
		}
		persisted = append(persisted, stored)
		// Per-alert detail is DEBUG: the per-POST "webhook received" INFO line
		// is the action-trail entry; this is troubleshooting depth.
		h.logger.Debug("alert upserted",
			slog.String("fingerprint", stored.Fingerprint),
			slog.String("status", stored.Status),
		)
	}
	return persisted, errs
}

func (h *Webhook) toStoreAlert(a AlertmanagerAlert) (store.Alert, error) {
	if strings.TrimSpace(a.Fingerprint) == "" {
		return store.Alert{}, errors.New("alert.fingerprint is required")
	}
	switch a.Status {
	case "firing", "resolved":
	default:
		return store.Alert{}, fmt.Errorf("alert.status %q must be firing or resolved", a.Status)
	}
	if a.StartsAt.IsZero() {
		return store.Alert{}, errors.New("alert.startsAt is required")
	}

	labels := a.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	annotations := a.Annotations
	if annotations == nil {
		annotations = map[string]string{}
	}

	// Alertmanager uses 0001-01-01T00:00:00Z to mean "no end time".
	// Treat any zero-equivalent value as nil.
	var endsAt *time.Time
	if !a.EndsAt.IsZero() && a.EndsAt.Year() > 1 {
		t := a.EndsAt.UTC()
		endsAt = &t
	}

	return store.Alert{
		ID:          h.newID(),
		Fingerprint: a.Fingerprint,
		Status:      a.Status,
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    a.StartsAt.UTC(),
		EndsAt:      endsAt,
		ReceivedAt:  h.now(),
	}, nil
}

func (h *Webhook) auditCall(ctx context.Context, payload AlertmanagerPayload, persisted []store.Alert) {
	fps := make([]string, 0, len(persisted))
	for _, a := range persisted {
		fps = append(fps, a.Fingerprint)
	}
	rec := map[string]any{
		"version":                payload.Version,
		"group_key":              payload.GroupKey,
		"status":                 payload.Status,
		"receiver":               payload.Receiver,
		"alert_count":            len(payload.Alerts),
		"persisted_count":        len(persisted),
		"persisted_fingerprints": fps,
	}
	if err := h.auditor.Append(ctx, "ingress", "alert.received", rec); err != nil {
		h.logger.Error("audit append failed",
			slog.String("kind", "alert.received"),
			slog.String("err", err.Error()),
		)
	}
}

func isJSONContentType(ct string) bool {
	if ct == "" {
		return false
	}
	// Strip parameters like "; charset=utf-8".
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	return strings.EqualFold(strings.TrimSpace(ct), "application/json")
}
