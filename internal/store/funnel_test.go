// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"testing"
	"time"

	situationmodel "github.com/alertint/alertint-agent/internal/situation/model"
)

func mustFunnelTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.UTC()
}

// seededFunnelStore builds a store with:
//   - 4 accepted deliveries across 2 distinct source episodes (2 each)
//   - 2 Incidents, both attached to the same Situation (recurrence
//     collapse / multi-incident membership before the aggregate terminates)
//   - 1 Situation
//   - 1 main-channel poke (a situation_root_create notification intent)
//
// All timestamps fall inside [2026-08-01, 2026-09-01).
func seededFunnelStore(t *testing.T) *Store {
	t.Helper()
	s := newTestStore(t)
	ctx := context.Background()
	now := mustFunnelTime(t, "2026-08-10T10:00:00Z")

	deliveries := []struct {
		id, alertID, episode string
	}{
		{"d1", "a1", "ep1"},
		{"d2", "a1", "ep1"},
		{"d3", "a2", "ep2"},
		{"d4", "a2", "ep2"},
	}
	for _, d := range deliveries {
		if _, err := s.DB().ExecContext(ctx, `INSERT OR IGNORE INTO alerts (id, fingerprint, status, labels_json, annotations_json, starts_at, received_at)
			VALUES (?, ?, 'firing', '{}', '{}', ?, ?)`, d.alertID, d.alertID, canonicalTime(now), canonicalTime(now)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.DB().ExecContext(ctx, `INSERT INTO alert_deliveries (
			id, alert_id, source, source_episode_key, status, labels_json, annotations_json,
			starts_at, started_at_basis, resolved_at_basis, receiver_grouping_identity, payload_digest, received_at
		) VALUES (?, ?, 'zabbix', ?, 'firing', '{}', '{}', ?, 'source_payload', 'missing', 'zabbix:webhook', ?, ?)`,
			d.id, d.alertID, d.episode, canonicalTime(now), d.id, canonicalTime(now)); err != nil {
			t.Fatal(err)
		}
	}

	incidents := []string{"inc1", "inc2"}
	for _, id := range incidents {
		if _, err := s.DB().ExecContext(ctx, `INSERT INTO incidents (id, group_key, status, first_alert_at, last_alert_at, ready_at, alert_count, created_at, updated_at)
			VALUES (?, 'host=db-prod-1', 'ready', ?, ?, ?, 1, ?, ?)`,
			id, canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now), canonicalTime(now)); err != nil {
			t.Fatal(err)
		}
	}

	if _, err := insertSituationFixtureErr(s, "sit1", "host=db-prod-1", "db-prod-sustained-cpu", situationmodel.LifecycleActive, now); err != nil {
		t.Fatal(err)
	}
	for _, id := range incidents {
		if _, err := s.DB().ExecContext(ctx, `INSERT INTO situation_incidents (situation_id, incident_id, attached_at) VALUES ('sit1', ?, ?)`,
			id, canonicalTime(now)); err != nil {
			t.Fatal(err)
		}
	}

	priority := situationmodel.PriorityHigh
	situationID := "sit1"
	if err := s.CreateNotificationIntent(ctx, situationmodel.NotificationIntent{
		ID: "ni1", IdempotencyKey: "situation:sit1:transition:t1:root", SubjectKind: situationmodel.NotificationSubjectSituation,
		SubjectID: situationID, SituationID: &situationID, Kind: situationmodel.NotificationSituationRootCreate,
		MainChannelPoke: true, InterruptionPriority: &priority, Status: situationmodel.NotificationPending,
		ClientMessageID: "client-1", CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	return s
}

func TestFunnelSeparatesDeliveriesAndSourceEpisodes(t *testing.T) {
	s := seededFunnelStore(t)
	r, err := s.PokeFunnel(context.Background(), mustFunnelTime(t, "2026-08-01T00:00:00Z"), mustFunnelTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if r.AcceptedDeliveries != 4 || r.SourceEpisodes != 2 || r.Incidents != 2 || r.Situations != 1 || r.MainChannelPokes != 1 {
		t.Fatalf("report=%+v", r)
	}
}

func TestFunnelExcludesRowsOutsideWindow(t *testing.T) {
	s := seededFunnelStore(t)
	r, err := s.PokeFunnel(context.Background(), mustFunnelTime(t, "2020-01-01T00:00:00Z"), mustFunnelTime(t, "2020-02-01T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if r.AcceptedDeliveries != 0 || r.SourceEpisodes != 0 || r.Incidents != 0 || r.Situations != 0 || r.MainChannelPokes != 0 {
		t.Fatalf("report=%+v, want all zero outside window", r)
	}
}

func TestFunnelCountsNotificationKindsSeparately(t *testing.T) {
	s := seededFunnelStore(t)
	ctx := context.Background()
	now := mustFunnelTime(t, "2026-08-11T10:00:00Z")
	situationID := "sit1"
	rows := []situationmodel.NotificationIntent{
		{ID: "ni2", IdempotencyKey: "k2", SubjectKind: situationmodel.NotificationSubjectSituation, SubjectID: situationID, SituationID: &situationID,
			Kind: situationmodel.NotificationSituationRootEdit, MainChannelPoke: false, Status: situationmodel.NotificationPending, ClientMessageID: "c2", CreatedAt: now},
		{ID: "ni3", IdempotencyKey: "k3", SubjectKind: situationmodel.NotificationSubjectSituation, SubjectID: situationID, SituationID: &situationID,
			Kind: situationmodel.NotificationSituationThreadReply, MainChannelPoke: false, Status: situationmodel.NotificationPending, ClientMessageID: "c3", CreatedAt: now},
		{ID: "ni4", IdempotencyKey: "k4", SubjectKind: situationmodel.NotificationSubjectSituation, SubjectID: situationID, SituationID: &situationID,
			Kind: situationmodel.NotificationSituationBroadcastReply, MainChannelPoke: false, Status: situationmodel.NotificationPending, ClientMessageID: "c4", CreatedAt: now},
	}
	for _, in := range rows {
		if err := s.CreateNotificationIntent(ctx, in); err != nil {
			t.Fatal(err)
		}
	}
	r, err := s.PokeFunnel(ctx, mustFunnelTime(t, "2026-08-01T00:00:00Z"), mustFunnelTime(t, "2026-09-01T00:00:00Z"))
	if err != nil {
		t.Fatal(err)
	}
	if r.RootCreates != 1 || r.RootEdits != 1 || r.ThreadReplies != 1 || r.BroadcastReplies != 1 {
		t.Fatalf("report=%+v", r)
	}
	// only the root_create is a main-channel poke; the rest are quiet.
	if r.MainChannelPokes != 1 {
		t.Fatalf("main_channel_pokes=%d, want 1", r.MainChannelPokes)
	}
}

func TestPokeFunnelRejectsInvertedWindow(t *testing.T) {
	s := newTestStore(t)
	_, err := s.PokeFunnel(context.Background(), mustFunnelTime(t, "2026-09-01T00:00:00Z"), mustFunnelTime(t, "2026-08-01T00:00:00Z"))
	if err == nil {
		t.Fatal("want error for since after until")
	}
}
