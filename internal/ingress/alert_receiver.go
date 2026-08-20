// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/grouping"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// AlertSink is retained as a constructor compatibility type while correlation
// moves to the durable alert delivery dispatch outbox.
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

// alertReceiver validates and durably accepts an Alertmanager envelope.
type alertReceiver struct {
	store  *store.Store
	token  []byte
	logger *slog.Logger
	now    func() time.Time
	newID  func() string
}

// NewAlertReceiver builds the Alertmanager receiver. sink is intentionally
// ignored: accepted deliveries are handed off by durable workers.
func NewAlertReceiver(st *store.Store, token string, _ AlertSink, logger *slog.Logger) Receiver {
	if logger == nil {
		logger = slog.Default()
	}
	return &alertReceiver{
		store:  st,
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
	// unambiguous.
	r.logger.Info("webhook received",
		slog.Int("alerts", len(payload.Alerts)),
		slog.String("group", payload.GroupKey),
		slog.String("status", payload.Status),
	)

	inputs, err := r.deliveryInputs(payload)
	if err != nil {
		return Summary{}, err
	}
	persisted := make([]store.Alert, 0, len(inputs))
	if len(inputs) > 0 {
		deliveries, err := r.store.AcceptDeliveries(ctx, inputs)
		if err != nil {
			return Summary{}, &DurabilityError{Err: err}
		}
		for _, d := range deliveries {
			persisted = append(persisted, d.Alert)
			r.logger.Debug("alert upserted",
				slog.String("fingerprint", d.Alert.Fingerprint),
				slog.String("status", d.Alert.Status),
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

func (r *alertReceiver) deliveryInputs(payload AlertmanagerPayload) ([]store.DeliveryInput, error) {
	inputs := make([]store.DeliveryInput, 0, len(payload.Alerts))
	for _, a := range payload.Alerts {
		alert, err := r.toStoreAlert(a)
		if err != nil {
			return nil, err
		}
		identity := grouping.Ensure(
			grouping.RenderLabels(payload.GroupLabels), alert.Labels, alert.Fingerprint,
		)
		startedAt := alert.StartsAt
		normalized := alertmanagerDeliveryPayload{
			Version: payload.Version, GroupKey: payload.GroupKey, Status: payload.Status, Receiver: payload.Receiver,
			GroupLabels: payload.GroupLabels, CommonLabels: payload.CommonLabels, CommonAnnotations: payload.CommonAnnotations,
			ExternalURL: payload.ExternalURL, Alert: a,
		}
		input := store.DeliveryInput{
			ID:                       payloadDigest("alertmanager-delivery", normalized),
			Alert:                    alert,
			Source:                   "alertmanager",
			SourceEpisodeKey:         "alertmanager:" + alert.Fingerprint + ":" + startedAt.UTC().Format(time.RFC3339Nano),
			SourceStartedAt:          &startedAt,
			StartedAtBasis:           situationmodel.SourceTimeBasisSourcePayload,
			ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
			ReceiverGroupingIdentity: identity,
			PayloadDigest:            payloadDigest("alertmanager-payload", normalized),
		}
		if alert.EndsAt != nil {
			input.SourceResolvedAt = alert.EndsAt
			input.ResolvedAtBasis = situationmodel.SourceTimeBasisSourcePayload
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
}

// alertmanagerDeliveryPayload is the normalized, per-member source payload
// retained by a delivery digest. Envelope context is included because it
// determines receiver grouping and therefore durable dispatch semantics.
type alertmanagerDeliveryPayload struct {
	Version           string            `json:"version"`
	GroupKey          string            `json:"group_key"`
	Status            string            `json:"status"`
	Receiver          string            `json:"receiver"`
	GroupLabels       map[string]string `json:"group_labels"`
	CommonLabels      map[string]string `json:"common_labels"`
	CommonAnnotations map[string]string `json:"common_annotations"`
	ExternalURL       string            `json:"external_url"`
	Alert             AlertmanagerAlert `json:"alert"`
}

func payloadDigest(source string, v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		// Receiver payload structs are JSON-marshalable; preserve a stable
		// value if that invariant is ever broken so validation still decides
		// the HTTP class rather than panicking in the request path.
		b = []byte(source)
	}
	sum := sha256.Sum256(append([]byte(source+":"), b...))
	return fmt.Sprintf("sha256:%x", sum[:])
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
