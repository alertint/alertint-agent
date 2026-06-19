// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/store"
)

// AlertSink receives each alert after it has been persisted. The correlator
// implements this; tests inject fakes. A nil sink means "skip handoff".
type AlertSink func(ctx context.Context, alert store.Alert) error

// AlertmanagerPayload is the v4 webhook envelope. Fields we don't use are
// decoded but ignored.
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

// ParseAlertmanager decodes and version-checks a v4 webhook body. Pure: no clock,
// no persistence. (Zabbix will add a sibling ParseZabbix; both feed alertReceiver.)
func ParseAlertmanager(body []byte) (AlertmanagerPayload, error) {
	var payload AlertmanagerPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		return AlertmanagerPayload{}, fmt.Errorf("invalid JSON: %w", err)
	}
	if payload.Version != "4" {
		return AlertmanagerPayload{}, fmt.Errorf("unsupported alertmanager payload version %q (want \"4\")", payload.Version)
	}
	return payload, nil
}

// alertReceiver wraps ParseAlertmanager → persist → AlertSink/correlator.
type alertReceiver struct {
	store  *store.Store
	sink   AlertSink
	token  []byte
	logger *slog.Logger
	now    func() time.Time
	newID  func() string
}

// NewAlertReceiver builds the Alertmanager receiver. sink may be nil.
func NewAlertReceiver(st *store.Store, token string, sink AlertSink, logger *slog.Logger) Receiver {
	if logger == nil {
		logger = slog.Default()
	}
	return &alertReceiver{
		store:  st,
		sink:   sink,
		token:  []byte(token),
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		newID:  uuid.NewString,
	}
}

func (r *alertReceiver) Route() string { return "POST /webhook/alertmanager" }
func (r *alertReceiver) Name() string  { return "alertmanager" }
func (r *alertReceiver) Token() []byte { return r.token }

func (r *alertReceiver) Ingest(ctx context.Context, body []byte) (Summary, error) {
	payload, err := ParseAlertmanager(body)
	if err != nil {
		return Summary{}, err // → 400
	}

	// One INFO line per accepted POST so a quiet-but-receiving agent is
	// unambiguous; per-alert dedup detail stays at DEBUG in persistAlerts.
	r.logger.Info("webhook received",
		slog.Int("alerts", len(payload.Alerts)),
		slog.String("group", payload.GroupKey),
		slog.String("status", payload.Status),
	)

	var persisted []store.Alert
	if len(payload.Alerts) > 0 {
		var persistErrs []error
		persisted, persistErrs = r.persistAlerts(ctx, payload.Alerts)
		// Hand off AFTER persistence; sink errors are logged, never fail the response.
		if r.sink != nil {
			for _, a := range persisted {
				if err := r.sink(ctx, a); err != nil {
					r.logger.Warn("alert sink failed",
						slog.String("fingerprint", a.Fingerprint),
						slog.String("err", err.Error()),
					)
				}
			}
		}
		if len(persistErrs) > 0 {
			r.logger.Error("partial persist failure",
				slog.Int("alerts_received", len(payload.Alerts)),
				slog.Int("alerts_persisted", len(persisted)),
				slog.Int("alerts_failed", len(persistErrs)),
			)
		}
	}

	return Summary{Kind: "alert.received", Audit: alertAuditRecord(payload, persisted)}, nil
}

// alertAuditRecord preserves the legacy alert.received payload byte-for-byte.
func alertAuditRecord(payload AlertmanagerPayload, persisted []store.Alert) map[string]any {
	fps := make([]string, 0, len(persisted))
	for _, a := range persisted {
		fps = append(fps, a.Fingerprint)
	}
	return map[string]any{
		"version":                payload.Version,
		"group_key":              payload.GroupKey,
		"status":                 payload.Status,
		"receiver":               payload.Receiver,
		"alert_count":            len(payload.Alerts),
		"persisted_count":        len(persisted),
		"persisted_fingerprints": fps,
	}
}

func (r *alertReceiver) persistAlerts(ctx context.Context, in []AlertmanagerAlert) ([]store.Alert, []error) {
	persisted := make([]store.Alert, 0, len(in))
	var errs []error
	for _, a := range in {
		alert, err := r.toStoreAlert(a)
		if err != nil {
			errs = append(errs, err)
			r.logger.Warn("dropping invalid alert",
				slog.String("fingerprint", a.Fingerprint),
				slog.String("err", err.Error()),
			)
			continue
		}
		stored, err := r.store.UpsertAlertByFingerprint(ctx, alert)
		if err != nil {
			errs = append(errs, err)
			r.logger.Error("upsert alert failed",
				slog.String("fingerprint", alert.Fingerprint),
				slog.String("err", err.Error()),
			)
			continue
		}
		persisted = append(persisted, stored)
		r.logger.Debug("alert upserted",
			slog.String("fingerprint", stored.Fingerprint),
			slog.String("status", stored.Status),
		)
	}
	return persisted, errs
}

func (r *alertReceiver) toStoreAlert(a AlertmanagerAlert) (store.Alert, error) {
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
	var endsAt *time.Time
	if !a.EndsAt.IsZero() && a.EndsAt.Year() > 1 {
		t := a.EndsAt.UTC()
		endsAt = &t
	}
	return store.Alert{
		ID:          r.newID(),
		Fingerprint: a.Fingerprint,
		Status:      a.Status,
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    a.StartsAt.UTC(),
		EndsAt:      endsAt,
		ReceivedAt:  r.now(),
	}, nil
}
