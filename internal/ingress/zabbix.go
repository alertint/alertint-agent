// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/alertint/alertint-agent/internal/grouping"
	"github.com/alertint/alertint-agent/internal/severity"
	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
	"github.com/alertint/alertint-agent/internal/store"
)

// ZabbixEvent is the webhook contract AlertINT owns (ADR-0031): a small fixed
// JSON object the Zabbix media-type JS template builds from macros and POSTs
// to /webhook/zabbix. All mapping intelligence lives here, in tested Go; the
// template is a thin macro-forwarder (docs/integrations/zabbix.md).
type ZabbixEvent struct {
	EventID       string      `json:"event_id"`     // {EVENT.ID} — stable across PROBLEM→RESOLVED
	Status        string      `json:"status"`       // "PROBLEM" | "RESOLVED"
	Severity      string      `json:"severity"`     // {EVENT.SEVERITY} display name (per-install renameable)
	NSeverity     string      `json:"nseverity"`    // {EVENT.NSEVERITY} numeric 0..5 (stable)
	Host          string      `json:"host"`         // {HOST.HOST} technical name — the API lookup key
	HostVisible   string      `json:"host_visible"` // {HOST.NAME} display only
	TriggerID     string      `json:"trigger_id"`
	TriggerName   string      `json:"trigger_name"`
	ItemKey       string      `json:"item_key"`
	ItemValue     string      `json:"item_value"`
	Tags          []ZabbixTag `json:"tags"`           // {EVENT.TAGSJSON}, emitted unquoted by the template
	Clock         string      `json:"clock"`          // display only — never parsed (ADR-0031)
	RecoveryClock string      `json:"recovery_clock"` // display only — never parsed
	GeneratorURL  string      `json:"generator_url"`
}

// ZabbixTag is one {tag,value} entry from {EVENT.TAGSJSON}.
type ZabbixTag struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

// ParseZabbix decodes and validates a Zabbix webhook body. Pure: no clock, no
// persistence (the ParseAlertmanager split). A returned error maps to HTTP 400.
func ParseZabbix(body []byte) (ZabbixEvent, error) {
	var ev ZabbixEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		return ZabbixEvent{}, fmt.Errorf("zabbix: invalid JSON: %w", err)
	}
	if strings.TrimSpace(ev.EventID) == "" {
		return ZabbixEvent{}, fmt.Errorf("zabbix: event_id is required")
	}
	switch ev.Status {
	case "PROBLEM", "RESOLVED":
	default:
		return ZabbixEvent{}, fmt.Errorf("zabbix: status %q must be PROBLEM or RESOLVED", ev.Status)
	}
	if strings.TrimSpace(ev.Host) == "" {
		return ZabbixEvent{}, fmt.Errorf("zabbix: host is required")
	}
	if strings.TrimSpace(ev.TriggerName) == "" {
		return ZabbixEvent{}, fmt.Errorf("zabbix: trigger_name is required")
	}
	return ev, nil
}

// zabbixReceiver validates and durably accepts one Zabbix event per request.
type zabbixReceiver struct {
	store  *store.Store
	token  []byte
	logger *slog.Logger
	now    func() time.Time
	newID  func() string
}

// NewZabbixReceiver builds the Zabbix receiver. sink is intentionally
// ignored: accepted deliveries are handed off by durable workers.
func NewZabbixReceiver(st *store.Store, token string, _ AlertSink, logger *slog.Logger) Receiver {
	if logger == nil {
		logger = slog.Default()
	}
	return &zabbixReceiver{
		store:  st,
		token:  []byte(token),
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
		newID:  uuid.NewString,
	}
}

func (r *zabbixReceiver) Route() string { return "POST /webhook/zabbix" }
func (r *zabbixReceiver) Name() string  { return "zabbix" }
func (r *zabbixReceiver) Token() []byte { return r.token }

func (r *zabbixReceiver) Ingest(ctx context.Context, body []byte) (Summary, error) {
	ev, err := ParseZabbix(body)
	if err != nil {
		return Summary{}, err // → 400
	}
	r.logger.Info("webhook received",
		slog.String("source", "zabbix"),
		slog.String("event_id", ev.EventID),
		slog.String("status", ev.Status),
		slog.String("host", ev.Host),
	)

	// Preserve the firing row's original StartsAt across a later delivery for
	// the same event_id (e.g. RESOLVED, or a retried PROBLEM): StartsAt is
	// receipt-based only for the FIRST delivery, never rewritten by a later
	// one, since UpsertAlertByFingerprint otherwise overwrites starts_at
	// unconditionally on every upsert.
	var existingStartsAt *time.Time
	existing, err := r.store.GetAlertByFingerprint(ctx, "zabbix:"+ev.EventID)
	switch {
	case err == nil:
		t := existing.StartsAt
		existingStartsAt = &t
	case errors.Is(err, store.ErrNotFound):
		// First delivery for this event_id — StartsAt is this delivery's receipt time.
	default:
		return Summary{}, &DurabilityError{Err: fmt.Errorf("zabbix: read existing alert: %w", err)}
	}

	alert := r.toStoreAlert(ev, existingStartsAt)
	identity := grouping.Ensure(
		grouping.RenderSelectedLabels(alert.Labels, []string{"host"}), alert.Labels, alert.Fingerprint,
	)
	startedAt := alert.StartsAt
	input := store.DeliveryInput{
		ID:                       payloadDigest("zabbix", ev),
		Alert:                    alert,
		Source:                   "zabbix",
		SourceEventID:            &ev.EventID,
		SourceEpisodeKey:         "zabbix:" + ev.EventID,
		SourceStartedAt:          &startedAt,
		StartedAtBasis:           situationmodel.SourceTimeBasisReceiptFallback,
		ResolvedAtBasis:          situationmodel.SourceTimeBasisMissing,
		ReceiverGroupingIdentity: identity,
		PayloadDigest:            payloadDigest("zabbix-payload", ev),
	}
	if alert.EndsAt != nil {
		input.SourceResolvedAt = alert.EndsAt
		input.ResolvedAtBasis = situationmodel.SourceTimeBasisReceiptFallback
	}
	_, err = r.store.AcceptDeliveries(ctx, []store.DeliveryInput{input})
	if err != nil {
		return Summary{}, &DurabilityError{Err: err}
	}
	return Summary{Kind: "alert.received", Audit: zabbixAuditRecord(ev, true)}, nil
}

// labelKeySanitiser collapses every character outside [a-zA-Z0-9_] to _.
var labelKeySanitiser = regexp.MustCompile(`[^a-zA-Z0-9_]`)

// canonicalZabbixSeverity maps {EVENT.NSEVERITY} 1..5 to the default Zabbix
// severity names, for the renamed-severity fallback (ADR-0033).
var canonicalZabbixSeverity = map[string]string{
	"1": "information", "2": "warning", "3": "average", "4": "high", "5": "disaster",
}

func (r *zabbixReceiver) toStoreAlert(ev ZabbixEvent, existingStartsAt *time.Time) store.Alert {
	now := r.now()
	startsAt := now
	if existingStartsAt != nil {
		startsAt = *existingStartsAt
	}

	// Verbatim-first severity with nseverity fallback (ADR-0033): a name the
	// shared ladder knows stays verbatim; an unknown name with a valid
	// nseverity becomes the canonical tier name, the operator's word moving to
	// the severity_display annotation.
	sev := ev.Severity
	var sevDisplay string
	if severity.Rank(sev) == 0 {
		if canonical, ok := canonicalZabbixSeverity[ev.NSeverity]; ok {
			sevDisplay = ev.Severity
			sev = canonical
		}
	}

	labels := map[string]string{
		"alertname":         ev.TriggerName,
		"host":              ev.Host,
		"severity":          sev,
		"zabbix_trigger_id": ev.TriggerID,
	}
	coreKeys := make(map[string]bool, len(labels))
	for k := range labels {
		coreKeys[k] = true
	}
	for _, tag := range ev.Tags {
		key := labelKeySanitiser.ReplaceAllString(tag.Tag, "_")
		if key == "" {
			continue
		}
		if _, taken := labels[key]; taken {
			// The first writer of a key wins, whether it's a core identity
			// label or an earlier tag in this same delivery; the second is
			// dropped, not merged.
			if coreKeys[key] {
				r.logger.Debug("zabbix tag collides with core label, skipped", slog.String("tag", tag.Tag))
			} else {
				r.logger.Debug("zabbix tag collides with another tag, skipped", slog.String("tag", tag.Tag))
			}
			continue
		}
		labels[key] = tag.Value
	}

	annotations := map[string]string{}
	setIfPresent := func(k, v string) {
		if v != "" {
			annotations[k] = v
		}
	}
	setIfPresent("trigger_name", ev.TriggerName)
	setIfPresent("item_key", ev.ItemKey)
	setIfPresent("item_value", ev.ItemValue)
	setIfPresent("zabbix_event_id", ev.EventID)
	setIfPresent("host_visible", ev.HostVisible)
	setIfPresent("generator_url", ev.GeneratorURL)
	setIfPresent("clock", ev.Clock)
	setIfPresent("recovery_clock", ev.RecoveryClock)
	setIfPresent("severity_display", sevDisplay)

	a := store.Alert{
		ID:          r.newID(),
		Fingerprint: "zabbix:" + ev.EventID,
		Labels:      labels,
		Annotations: annotations,
		StartsAt:    startsAt, // receipt-based by design, preserved across later deliveries — never parsed from clock (ADR-0031)
		ReceivedAt:  now,
	}
	if ev.Status == "RESOLVED" {
		a.Status = "resolved"
		t := now
		a.EndsAt = &t
	} else {
		a.Status = "firing"
	}
	return a
}

// zabbixAuditRecord is the receiver-owned audit payload (Summary contract).
func zabbixAuditRecord(ev ZabbixEvent, persisted bool) map[string]any {
	return map[string]any{
		"event_id":  ev.EventID,
		"status":    ev.Status,
		"severity":  ev.Severity,
		"host":      ev.Host,
		"persisted": persisted,
	}
}
