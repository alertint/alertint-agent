// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// PokeFunnel derives local-compression counts from durable rows — accepted
// deliveries, distinct source episodes, Incidents, Situations, and
// notification intents. It never maintains a mutable aggregate counter, so
// the report always reflects exactly what is durably recorded for the
// window. Delivery and source-episode counts are reported separately so
// webhook retries and recovery deliveries are never misrepresented as
// avoided operator interruptions; this report makes no claim about external
// Zabbix-to-Slack messages avoided — that baseline is observable only from
// the operator's separate path.
type PokeFunnel struct {
	Since              time.Time `json:"since"`
	Until              time.Time `json:"until"`
	AcceptedDeliveries int       `json:"accepted_deliveries"`
	SourceEpisodes     int       `json:"source_episodes"`
	Incidents          int       `json:"incidents"`
	Situations         int       `json:"situations"`
	RootCreates        int       `json:"root_creates"`
	RootEdits          int       `json:"root_edits"`
	ThreadReplies      int       `json:"non_broadcast_replies"`
	BroadcastReplies   int       `json:"broadcast_replies"`
	EnvelopeReviews    int       `json:"envelope_reviews"`
	HealthPokes        int       `json:"health_pokes"`
	MainChannelPokes   int       `json:"main_channel_pokes"`
}

// PokeFunnel reports the delivery -> source-episode -> Incident -> Situation
// -> main-channel-poke funnel for [since, until], the same query the MCP
// alertint_poke_funnel_get tool and the `alertint funnel` CLI both use.
func (s *Store) PokeFunnel(ctx context.Context, since, until time.Time) (PokeFunnel, error) {
	if since.IsZero() || until.IsZero() {
		return PokeFunnel{}, errors.New("store: poke funnel requires since and until")
	}
	since, until = since.UTC(), until.UTC()
	if since.After(until) {
		return PokeFunnel{}, errors.New("store: poke funnel since must not be after until")
	}
	sinceStr, untilStr := since.Format(time.RFC3339Nano), until.Format(time.RFC3339Nano)

	out := PokeFunnel{Since: since, Until: until}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT source_episode_key)
		FROM alert_deliveries WHERE received_at >= ? AND received_at <= ?`, sinceStr, untilStr).
		Scan(&out.AcceptedDeliveries, &out.SourceEpisodes); err != nil {
		return PokeFunnel{}, fmt.Errorf("store: poke funnel deliveries: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM incidents WHERE created_at >= ? AND created_at <= ?`, sinceStr, untilStr).
		Scan(&out.Incidents); err != nil {
		return PokeFunnel{}, fmt.Errorf("store: poke funnel incidents: %w", err)
	}

	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM situations WHERE opened_at >= ? AND opened_at <= ?`, sinceStr, untilStr).
		Scan(&out.Situations); err != nil {
		return PokeFunnel{}, fmt.Errorf("store: poke funnel situations: %w", err)
	}

	rows, err := s.db.QueryContext(ctx, `SELECT kind, subject_kind, main_channel_poke, COUNT(*)
		FROM notification_intents
		WHERE created_at >= ? AND created_at <= ?
		GROUP BY kind, subject_kind, main_channel_poke`, sinceStr, untilStr)
	if err != nil {
		return PokeFunnel{}, fmt.Errorf("store: poke funnel notifications: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var kind, subjectKind string
		var mainChannelPoke, count int
		if err := rows.Scan(&kind, &subjectKind, &mainChannelPoke, &count); err != nil {
			return PokeFunnel{}, fmt.Errorf("store: scan poke funnel notification row: %w", err)
		}
		switch kind {
		case "situation_root_create":
			out.RootCreates += count
		case "situation_root_edit":
			out.RootEdits += count
		case "situation_thread_reply":
			out.ThreadReplies += count
		case "situation_broadcast_reply":
			out.BroadcastReplies += count
		case "envelope_review":
			out.EnvelopeReviews += count
		case "health_root", "health_update":
			out.HealthPokes += count
		}
		if mainChannelPoke == 1 {
			out.MainChannelPokes += count
		}
	}
	if err := rows.Err(); err != nil {
		return PokeFunnel{}, fmt.Errorf("store: iterate poke funnel notifications: %w", err)
	}
	return out, nil
}
