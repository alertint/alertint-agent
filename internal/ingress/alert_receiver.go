// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// DeliveryWake nudges the durable dispatch worker (wired in a later task) to
// look for newly pending work sooner than its normal poll interval. It is
// called at most once per Ingest call, strictly after that call's
// AcceptDeliveries commits successfully — never before, and never when
// Ingest rejects the payload (4xx) or the Store fails to persist it (503). A
// nil DeliveryWake is a no-op.
type DeliveryWake func()

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

// alertReceiver wraps ParseAlertmanager → durable acceptance → wake.
type alertReceiver struct {
	store  *store.Store
	wake   DeliveryWake
	token  []byte
	logger *slog.Logger
	now    func() time.Time
	newID  func() string
}

// NewAlertReceiver builds the Alertmanager receiver. wake may be nil.
func NewAlertReceiver(st *store.Store, token string, wake DeliveryWake, logger *slog.Logger) Receiver {
	if logger == nil {
		logger = slog.Default()
	}
	return &alertReceiver{
		store:  st,
		wake:   wake,
		token:  []byte(token),
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		newID:  uuid.NewString,
	}
}

func (r *alertReceiver) Route() string { return "POST /webhook/alertmanager" }
func (r *alertReceiver) Name() string  { return "alertmanager" }
func (r *alertReceiver) Token() []byte { return r.token }

// Ingest parses the envelope, validates and normalizes every member into a
// store.DeliveryInput, then commits the whole batch in one AcceptDeliveries
// call. A structurally invalid member rejects the whole envelope (400)
// before the Store is ever called — this POST is all-or-nothing. Once
// AcceptDeliveries commits, wake fires exactly once and the delivery is
// durable; nothing after this point (including the audit append) can turn
// the response into anything but 204.
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
		inputs, err := r.buildDeliveryInputs(payload)
		if err != nil {
			return Summary{}, err // → 400, nothing committed
		}

		accepted, err := r.store.AcceptDeliveries(ctx, inputs)
		if err != nil {
			return Summary{}, &DurabilityError{Err: err} // → 503
		}
		if r.wake != nil {
			r.wake()
		}

		persisted = make([]store.Alert, 0, len(accepted))
		for _, d := range accepted {
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

// normalizedAlertmanagerMember is the deterministic content payloadDigest
// hashes for one Alertmanager alert: the raw wire-level fields for that
// member plus the enclosing envelope metadata that participates in its
// derived grouping identity. It never includes a locally-generated ID,
// receipt-clock reading, or anything else this receiver invents — only what
// Alertmanager actually sent — so re-POSTing the same body twice yields the
// same digest for the same member, which is what makes transport redelivery
// a successful no-op instead of a duplicate row.
type normalizedAlertmanagerMember struct {
	Version     string
	GroupKey    string
	Receiver    string
	GroupLabels map[string]string
	Alert       AlertmanagerAlert
}

// buildDeliveryInputs validates and normalizes every Alertmanager alert
// member into a store.DeliveryInput before any of them reaches the Store.
// One invalid member returns an error and produces no inputs at all, so the
// caller never commits a partial envelope.
func (r *alertReceiver) buildDeliveryInputs(payload AlertmanagerPayload) ([]store.DeliveryInput, error) {
	inputs := make([]store.DeliveryInput, 0, len(payload.Alerts))
	for _, raw := range payload.Alerts {
		alert, err := r.toStoreAlert(raw)
		if err != nil {
			return nil, fmt.Errorf("alertmanager: invalid alert (fingerprint %q): %w", raw.Fingerprint, err)
		}

		member := normalizedAlertmanagerMember{
			Version:     payload.Version,
			GroupKey:    payload.GroupKey,
			Receiver:    payload.Receiver,
			GroupLabels: payload.GroupLabels,
			Alert:       raw,
		}

		input := store.DeliveryInput{
			ID:                       payloadDigest("alertmanager-delivery", member),
			Alert:                    alert,
			Source:                   "alertmanager",
			SourceEpisodeKey:         "alertmanager:" + alert.Fingerprint + ":" + alert.StartsAt.UTC().Format(time.RFC3339Nano),
			SourceStartedAt:          timePtr(alert.StartsAt),
			StartedAtBasis:           situationmodel.SourceTimeBasisSourcePayload,
			ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
			ReceiverGroupingIdentity: grouping.Ensure(grouping.RenderLabels(payload.GroupLabels), alert.Labels, alert.Fingerprint),
			PayloadDigest:            payloadDigest("alertmanager-payload", member),
			SourceProvenance: store.SourceProvenance{
				GeneratorURL:    raw.GeneratorURL,
				AcquisitionMode: store.SourceAcquisitionWebhook,
			},
		}
		if alert.Status == "resolved" && alert.EndsAt != nil {
			input.SourceResolvedAt = timePtr(*alert.EndsAt)
			input.ResolvedAtBasis = situationmodel.SourceTimeBasisSourcePayload
		}
		inputs = append(inputs, input)
	}
	return inputs, nil
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

// timePtr returns a pointer to an independent copy of t.
func timePtr(t time.Time) *time.Time { return &t }

// payloadDigest returns a deterministic "sha256:<hex>" digest over a
// namespaced JSON encoding of value. Namespacing on source lets the same
// underlying value produce different digests for different purposes (e.g. a
// delivery ID vs. a recorded payload digest for the same normalized alert),
// while guaranteeing that byte-identical input always produces the
// byte-identical digest — required for transport redelivery of the same
// normalized source payload to resolve to the same delivery ID.
//
// encoding/json already sorts map keys and fixes struct field order, so
// marshaling is canonical enough here: every caller passes one of this
// package's own fixed-shape struct/map values built from already-decoded
// JSON, never anything with nondeterministic field order.
func payloadDigest(source string, value any) string {
	b, err := json.Marshal(value)
	if err != nil {
		// value is always one of this package's own struct/map types
		// decoded from JSON we already parsed once; re-encoding it can only
		// fail for shapes this package never constructs. Fall back to a
		// deterministic textual representation rather than let one
		// unexpected value panic the request.
		b = []byte(fmt.Sprintf("%#v", value))
	}
	sum := sha256.Sum256(append([]byte(source+"\x00"), b...))
	return "sha256:" + hex.EncodeToString(sum[:])
}
