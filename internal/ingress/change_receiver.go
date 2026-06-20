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

// changeRequest is the canonical, source-agnostic change webhook body. Any
// emitter (a one-line curl at the end of a deploy) can POST this shape.
type changeRequest struct {
	Source     string            `json:"source"`
	Kind       string            `json:"kind"`
	Title      string            `json:"title"`
	Labels     map[string]string `json:"labels"`
	Version    string            `json:"version"`
	Link       string            `json:"link"`
	OccurredAt time.Time         `json:"occurred_at"`
}

// ParseChange validates and normalizes one change body. It returns a one-element
// slice (the slice return keeps batch ingest a trivial later extension). ID is
// left empty for the receiver to stamp; ReceivedAt is set to now.
//
// occurred_at is accept-and-normalize, never reject (push APIs stay lenient,
// per the never-5xx spirit): effective occurrence = occurred_at if present and
// NOT in the future relative to now, else now. A future timestamp is clock skew
// — exactly what degrades mid-incident — and would otherwise pollute every later
// window and render a nonsense "Δ before incident" hint, so it collapses to the
// received_at fallback. Ancient timestamps are trusted (legitimate backfill;
// they self-correct by falling outside the window/retention). This is stricter
// than the alert path (which trusts StartsAt un-clamped) on purpose: changes are
// append-only and flow straight into the LLM prompt.
func ParseChange(body []byte, now time.Time) ([]store.Change, error) {
	var req changeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		return nil, fmt.Errorf("change: invalid JSON: %w", err)
	}
	if strings.TrimSpace(req.Kind) == "" {
		return nil, errors.New("change: kind is required")
	}
	if len(req.Labels) == 0 {
		return nil, errors.New("change: labels must contain at least one key")
	}

	received := now.UTC()
	occurred := received
	if !req.OccurredAt.IsZero() && !req.OccurredAt.After(received) {
		occurred = req.OccurredAt.UTC()
	}

	source := strings.TrimSpace(req.Source)
	if source == "" {
		source = "unknown"
	}
	kind := strings.TrimSpace(req.Kind)
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = synthTitle(kind, req.Labels, req.Version)
	}

	return []store.Change{{
		Source:     source,
		Kind:       kind,
		Title:      title,
		Labels:     req.Labels,
		Version:    strings.TrimSpace(req.Version),
		Link:       strings.TrimSpace(req.Link),
		OccurredAt: occurred,
		ReceivedAt: received,
	}}, nil
}

// synthTitle builds a human summary when the emitter omits title: "<kind>
// <service-ish label> <version>", e.g. "deploy checkout v9".
func synthTitle(kind string, labels map[string]string, version string) string {
	parts := []string{kind}
	for _, k := range []string{"service", "app", "namespace"} {
		if v := strings.TrimSpace(labels[k]); v != "" {
			parts = append(parts, v)
			break
		}
	}
	if v := strings.TrimSpace(version); v != "" {
		parts = append(parts, v)
	}
	return strings.Join(parts, " ")
}

// changeReceiver wraps ParseChange → store.InsertChange. It has NO correlator
// sink — that distinct sink is the entire reason changes are a separate receiver:
// a change enriches incidents but must never spawn one.
type changeReceiver struct {
	store         *store.Store
	token         []byte
	retentionDays int
	logger        *slog.Logger
	now           func() time.Time
	newID         func() string
}

// NewChangeReceiver builds the change-event receiver. retentionDays bounds the
// append-only changes table: it prunes on insert (plus the one-shot startup
// prune in runServe) so the table stays bounded regardless of uptime.
func NewChangeReceiver(st *store.Store, token string, retentionDays int, logger *slog.Logger) Receiver {
	if logger == nil {
		logger = slog.Default()
	}
	return &changeReceiver{
		store:         st,
		token:         []byte(token),
		retentionDays: retentionDays,
		logger:        logger,
		now:           func() time.Time { return time.Now().UTC() },
		newID:         uuid.NewString,
	}
}

func (r *changeReceiver) Route() string { return "POST /webhook/change" }
func (r *changeReceiver) Name() string  { return "change" }
func (r *changeReceiver) Token() []byte { return r.token }

func (r *changeReceiver) Ingest(ctx context.Context, body []byte) (Summary, error) {
	changes, err := ParseChange(body, r.now())
	if err != nil {
		return Summary{}, err // → 400
	}

	ids := make([]string, 0, len(changes))
	for i := range changes {
		changes[i].ID = r.newID()
		if err := r.store.InsertChange(ctx, changes[i]); err != nil {
			// Logged + swallowed: like the alert path, failing the response would
			// only trigger pointless retries. The audit row still records intent.
			r.logger.Error("insert change failed",
				slog.String("change_id", changes[i].ID),
				slog.String("err", err.Error()),
			)
			continue
		}
		ids = append(ids, changes[i].ID)
	}

	// Prune on insert (spec §4.3): bound the append-only table continuously.
	// Sparse webhooks → negligible cost; logged-and-swallowed like the insert.
	if r.retentionDays > 0 {
		cutoff := r.now().AddDate(0, 0, -r.retentionDays)
		if _, err := r.store.PruneChanges(ctx, cutoff); err != nil {
			r.logger.Warn("change prune failed", slog.String("err", err.Error()))
		}
	}

	r.logger.Info("change received",
		slog.Int("changes", len(changes)),
		slog.Int("persisted", len(ids)),
	)

	return Summary{Kind: "change.received", Audit: map[string]any{
		"received":   len(changes),
		"persisted":  len(ids),
		"change_ids": ids,
	}}, nil
}
