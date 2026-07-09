// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// occurrenceTimeLayout is a fixed-width RFC3339 layout — always nine fractional
// digits — so occurrence timestamps sort lexicographically in SQL. time.RFC3339Nano
// trims trailing zeros, which would sort a whole-second time (…00Z) AFTER a
// sub-second one (…00.5Z) and reverse the occurrence order that the cadence and
// span math depend on.
const occurrenceTimeLayout = "2006-01-02T15:04:05.000000000Z07:00"

func fmtOccTime(t time.Time) string { return t.UTC().Format(occurrenceTimeLayout) }

// Occurrence is one firing episode that attached to an already-analyzed
// incident (a re-fire inside the collapse horizon). One row per attach, 1:1
// with an incident.occurrence_attached audit row. The incident's own first
// firing is not an occurrence — occurrence rows are the re-fires.
type Occurrence struct {
	ID           int64
	IncidentID   string
	OccurredAt   time.Time
	LastSeen     time.Time
	Fingerprints []string           // member fingerprints of this episode
	Payload      []OccurrenceMember // labels+annotations per member alert (R2 snapshot)
	TriggerKind  string             // none | severity | new_alertname | cadence | ceiling | cap
	SnapshotRef  string             // declare-ephemeral hook; ships empty
}

// OccurrenceMember is the persisted snapshot of one member alert in an episode,
// so annotation trajectories survive the latest-wins alerts upsert.
type OccurrenceMember struct {
	Fingerprint string            `json:"fingerprint"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// validTriggerKinds is the closed enum for incident_occurrences.trigger_kind.
// 'none' is a plain attach (no re-judgment); the rest name why a re-judgment
// happened. Kept in sync with the DDL comment in 0008.
var validTriggerKinds = map[string]bool{
	"none":          true,
	"severity":      true,
	"new_alertname": true,
	"cadence":       true,
	"ceiling":       true,
	"cap":           true,
}

// InsertOccurrence appends an occurrence row and returns its new id. The write
// is a single statement (no multi-row transaction needed): the row is
// self-contained and derived counts are read on demand.
func (s *Store) InsertOccurrence(ctx context.Context, occ Occurrence) (int64, error) {
	if occ.IncidentID == "" {
		return 0, errors.New("store: occurrence: incident_id is required")
	}
	if occ.OccurredAt.IsZero() {
		return 0, errors.New("store: occurrence: occurred_at is required")
	}
	if occ.TriggerKind == "" {
		occ.TriggerKind = "none"
	}
	if !validTriggerKinds[occ.TriggerKind] {
		return 0, fmt.Errorf("store: occurrence: trigger_kind %q invalid", occ.TriggerKind)
	}
	lastSeen := occ.LastSeen
	if lastSeen.IsZero() {
		lastSeen = occ.OccurredAt
	}
	fpsJSON, err := json.Marshal(occ.Fingerprints)
	if err != nil {
		return 0, fmt.Errorf("store: occurrence: marshal fingerprints: %w", err)
	}
	payloadJSON, err := json.Marshal(occ.Payload)
	if err != nil {
		return 0, fmt.Errorf("store: occurrence: marshal payload: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO incident_occurrences
			(incident_id, occurred_at, last_seen, fingerprints_json, payload_json, trigger_kind, snapshot_ref)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		occ.IncidentID,
		fmtOccTime(occ.OccurredAt),
		fmtOccTime(lastSeen),
		string(fpsJSON),
		string(payloadJSON),
		occ.TriggerKind,
		occ.SnapshotRef,
	)
	if err != nil {
		return 0, fmt.Errorf("store: insert occurrence: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: insert occurrence id: %w", err)
	}
	return id, nil
}

// InsertOccurrenceAndAttach records an occurrence AND mirrors its alert into
// incident_alerts in ONE transaction, so a partial failure can never leave an
// occurrence row whose alert never became a member (which a redelivery would
// then re-count as a fresh episode). It mirrors AddAlertToIncident's counter
// logic: the alert_count / last_alert_at bump runs only when the membership row
// is newly inserted. Returns the new occurrence id.
func (s *Store) InsertOccurrenceAndAttach(ctx context.Context, occ Occurrence, alertID string, alertTime time.Time) (int64, error) {
	if alertID == "" {
		return 0, errors.New("store: occurrence: alert_id is required")
	}
	if occ.IncidentID == "" {
		return 0, errors.New("store: occurrence: incident_id is required")
	}
	if occ.OccurredAt.IsZero() {
		return 0, errors.New("store: occurrence: occurred_at is required")
	}
	if occ.TriggerKind == "" {
		occ.TriggerKind = "none"
	}
	if !validTriggerKinds[occ.TriggerKind] {
		return 0, fmt.Errorf("store: occurrence: trigger_kind %q invalid", occ.TriggerKind)
	}
	lastSeen := occ.LastSeen
	if lastSeen.IsZero() {
		lastSeen = occ.OccurredAt
	}
	fpsJSON, err := json.Marshal(occ.Fingerprints)
	if err != nil {
		return 0, fmt.Errorf("store: occurrence: marshal fingerprints: %w", err)
	}
	payloadJSON, err := json.Marshal(occ.Payload)
	if err != nil {
		return 0, fmt.Errorf("store: occurrence: marshal payload: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store: begin occurrence tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	res, err := tx.ExecContext(ctx, `
		INSERT INTO incident_occurrences
			(incident_id, occurred_at, last_seen, fingerprints_json, payload_json, trigger_kind, snapshot_ref)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, occ.IncidentID, fmtOccTime(occ.OccurredAt), fmtOccTime(lastSeen),
		string(fpsJSON), string(payloadJSON), occ.TriggerKind, occ.SnapshotRef)
	if err != nil {
		return 0, fmt.Errorf("store: insert occurrence: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: insert occurrence id: %w", err)
	}

	now := time.Now().UTC().Format(time.RFC3339Nano)
	linkRes, err := tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO incident_alerts (incident_id, alert_id, created_at)
		VALUES (?, ?, ?)
	`, occ.IncidentID, alertID, now)
	if err != nil {
		return 0, fmt.Errorf("store: attach occurrence alert: %w", err)
	}
	inserted, err := linkRes.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: attach occurrence alert rows: %w", err)
	}
	if inserted > 0 {
		if _, err := tx.ExecContext(ctx, `
			UPDATE incidents
			SET alert_count  = alert_count + 1,
			    last_alert_at = MAX(last_alert_at, ?),
			    updated_at    = ?
			WHERE id = ?
		`, alertTime.UTC().Format(time.RFC3339Nano), now, occ.IncidentID); err != nil {
			return 0, fmt.Errorf("store: attach occurrence alert_count: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: commit occurrence tx: %w", err)
	}
	return id, nil
}

// LatestOccurrence returns the most recent occurrence for an incident, or
// ErrNotFound when the incident has none yet. The correlator reads it to slide
// Clock A (from the last occurrence's last_seen) and to touch last_seen on an
// unchanged Alertmanager repeat.
func (s *Store) LatestOccurrence(ctx context.Context, incidentID string) (*Occurrence, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, incident_id, occurred_at, last_seen, fingerprints_json, payload_json, trigger_kind, snapshot_ref
		FROM incident_occurrences
		WHERE incident_id = ?
		ORDER BY occurred_at DESC, id DESC
		LIMIT 1
	`, incidentID)
	return scanOccurrence(row)
}

// ListOccurrences returns an incident's occurrences most-recent-first, capped at
// limit (limit <= 0 returns all). Used to render the re-judgment prompt's
// occurrence trajectory from the persisted payload snapshots.
func (s *Store) ListOccurrences(ctx context.Context, incidentID string, limit int) ([]Occurrence, error) {
	q := `
		SELECT id, incident_id, occurred_at, last_seen, fingerprints_json, payload_json, trigger_kind, snapshot_ref
		FROM incident_occurrences
		WHERE incident_id = ?
		ORDER BY occurred_at DESC, id DESC`
	args := []any{incidentID}
	if limit > 0 {
		q += " LIMIT ?"
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store: list occurrences: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []Occurrence
	for rows.Next() {
		occ, err := scanOccurrence(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *occ)
	}
	return out, rows.Err()
}

// GetRecentJudgedIncidentByGroupKey returns the most recent incident (by
// created_at) for the verbatim group_key whose status is 'analyzed' or
// 'resolved' — i.e. one carrying a persisted finding — or ErrNotFound. The
// status filter is load-bearing: a trailing never-analyzed 'ready'/'collecting'
// row for the same key must not shadow the judged incident the collapse horizon
// attaches to. Returns the full row (incl. last_judged_at) so the correlator can
// evaluate Clock B in the same read.
func (s *Store) GetRecentJudgedIncidentByGroupKey(ctx context.Context, groupKey string) (*Incident, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, group_key, status,
		       first_alert_at, last_alert_at, ready_at, alert_count,
		       COALESCE(summary,''), COALESCE(root_cause,''),
		       COALESCE(confidence,0.0), COALESCE(output_json,''),
		       COALESCE(enrichment_json,''),
		       created_at, updated_at, last_judged_at
		FROM incidents
		WHERE group_key = ? AND status IN ('analyzed','resolved')
		ORDER BY created_at DESC
		LIMIT 1
	`, groupKey)
	return scanIncidentFull(row)
}

// ReplaceIncidentOutput overwrites an already-judged incident's finding in place
// during a re-judgment: summary, root_cause, confidence, output_json,
// enrichment_json, and last_judged_at, atomically. It is guarded to status IN
// ('analyzed','resolved') and never touches status — SaveIncidentOutput's
// ('ready','processing') guard would silently no-op every re-judgment. 'resolved'
// is accepted so a resolution landing between the re-judgment trigger and the
// persist is not lost. A zero-row update surfaces as ErrNotFound, never silent
// success. Empty enrichmentJSON stores SQL NULL (same convention as
// SaveIncidentOutput) so the evidence pack omits the logs section.
func (s *Store) ReplaceIncidentOutput(ctx context.Context, incidentID, outputJSON, summary, rootCause string, confidence float64, enrichmentJSON string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	var enrichment any
	if enrichmentJSON != "" {
		enrichment = enrichmentJSON
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET output_json     = ?,
		    summary         = ?,
		    root_cause      = ?,
		    confidence      = ?,
		    enrichment_json = ?,
		    last_judged_at  = ?,
		    updated_at      = ?
		WHERE id = ? AND status IN ('analyzed','resolved')
	`, outputJSON, summary, rootCause, confidence, enrichment, now, now, incidentID)
	if err != nil {
		return fmt.Errorf("store: replace incident output: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: replace incident output rows: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CountOccurrencesSince returns how many occurrence rows for an incident have
// occurred_at strictly after `since` — the "attaches since the last judgment"
// backing the occurrence-cap trigger. `since` is the incident's last_judged_at,
// so a re-judgment (which advances last_judged_at) resets the count to zero.
func (s *Store) CountOccurrencesSince(ctx context.Context, incidentID string, since time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM incident_occurrences
		WHERE incident_id = ? AND occurred_at > ?
	`, incidentID, since.UTC().Format(time.RFC3339Nano)).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("store: count occurrences since: %w", err)
	}
	return n, nil
}

// TouchIncidentActivity slides an incident's last_alert_at forward (MAX
// semantics) without adding a member or occurrence — the write for an unchanged
// repeat of the original firing when the incident has no occurrence row yet, so
// Clock A stays anchored to recent activity for a future new episode.
func (s *Store) TouchIncidentActivity(ctx context.Context, incidentID string, t time.Time) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.db.ExecContext(ctx, `
		UPDATE incidents
		SET last_alert_at = MAX(last_alert_at, ?), updated_at = ?
		WHERE id = ?
	`, t.UTC().Format(time.RFC3339Nano), now, incidentID)
	if err != nil {
		return fmt.Errorf("store: touch incident activity: %w", err)
	}
	return nil
}

// TouchOccurrenceLastSeen advances last_seen on an existing occurrence without
// adding a row — the write for an unchanged Alertmanager repeat (same
// fingerprint + starts_at, still firing), which slides Clock A but is not a new
// episode.
func (s *Store) TouchOccurrenceLastSeen(ctx context.Context, occurrenceID int64, lastSeen time.Time) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE incident_occurrences SET last_seen = ? WHERE id = ?
	`, fmtOccTime(lastSeen), occurrenceID)
	if err != nil {
		return fmt.Errorf("store: touch occurrence last_seen: %w", err)
	}
	return nil
}

// OccurrenceStats is the derived per-incident occurrence summary: how many
// re-fire episodes, when the first attached, and when last seen. Count is the
// raw occurrence-row count (attaches); the rendered "recurred xN" adds 1 for the
// incident's own first episode.
type OccurrenceStats struct {
	Count           int
	FirstOccurredAt time.Time
	LastSeen        time.Time
}

// Episodes is the displayed recurrence count: the occurrence rows (re-fires)
// plus the incident's own first firing, which is not an occurrence row. This is
// the "recurred ×N" number — centralized here so stdout, Slack, and the
// re-judgment prompt can't drift on the +1.
func (s OccurrenceStats) Episodes() int { return s.Count + 1 }

// OccurrenceStatsByIncident returns occurrence stats for each incident id in one
// GROUP BY query (no N+1), using the same json_each id-set idiom as
// IncidentMemberStatusCounts. Incidents with no occurrences are absent from the
// map; an empty id list yields an empty map.
func (s *Store) OccurrenceStatsByIncident(ctx context.Context, ids []string) (map[string]OccurrenceStats, error) {
	out := make(map[string]OccurrenceStats, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	idsJSON, err := json.Marshal(ids)
	if err != nil {
		return nil, fmt.Errorf("store: marshal incident ids: %w", err)
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT incident_id, COUNT(*), MIN(occurred_at), MAX(last_seen)
		FROM incident_occurrences
		WHERE incident_id IN (SELECT value FROM json_each(?))
		GROUP BY incident_id
	`, string(idsJSON))
	if err != nil {
		return nil, fmt.Errorf("store: occurrence stats: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var (
			id       string
			count    int
			firstStr string
			lastStr  string
		)
		if err := rows.Scan(&id, &count, &firstStr, &lastStr); err != nil {
			return nil, fmt.Errorf("store: scan occurrence stats: %w", err)
		}
		st := OccurrenceStats{Count: count}
		if st.FirstOccurredAt, err = time.Parse(time.RFC3339Nano, firstStr); err != nil {
			return nil, fmt.Errorf("store: parse occurrence first: %w", err)
		}
		if st.LastSeen, err = time.Parse(time.RFC3339Nano, lastStr); err != nil {
			return nil, fmt.Errorf("store: parse occurrence last_seen: %w", err)
		}
		out[id] = st
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: occurrence stats rows: %w", err)
	}
	return out, nil
}

// KeyEpisodeTimes returns, ascending, the union of every firing-episode start
// time for a group_key within the lookback: each incident's first_alert_at plus
// every occurrence's occurred_at, filtered to timestamps at or after `since`.
// The cadence trigger (R6) derives its trailing-median interval from this cross-
// incident series, so a nightly key whose every episode is a separate incident
// still has a cadence. Interval math lives in the caller; this method is
// I/O-only.
func (s *Store) KeyEpisodeTimes(ctx context.Context, groupKey string, since time.Time) ([]time.Time, error) {
	sinceStr := since.UTC().Format(time.RFC3339Nano)
	rows, err := s.db.QueryContext(ctx, `
		SELECT first_alert_at AS t FROM incidents
			WHERE group_key = ? AND first_alert_at >= ?
		UNION ALL
		SELECT o.occurred_at AS t
			FROM incident_occurrences o
			JOIN incidents i ON i.id = o.incident_id
			WHERE i.group_key = ? AND o.occurred_at >= ?
		ORDER BY t ASC
	`, groupKey, sinceStr, groupKey, sinceStr)
	if err != nil {
		return nil, fmt.Errorf("store: key episode times: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []time.Time
	for rows.Next() {
		var ts string
		if err := rows.Scan(&ts); err != nil {
			return nil, fmt.Errorf("store: scan episode time: %w", err)
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			return nil, fmt.Errorf("store: parse episode time: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: episode time rows: %w", err)
	}
	// The UNION mixes incident first_alert_at (RFC3339Nano) with occurrence
	// occurred_at (fixed-width): re-sort by real time so the SQL ORDER BY's
	// lexicographic mixing of the two formats can't reverse an interval.
	sort.Slice(out, func(i, j int) bool { return out[i].Before(out[j]) })
	return out, nil
}

// defaultPruneBatch bounds one PruneOccurrences DELETE so a large backlog does
// not hold a single long write while the correlator loop is blocked on it.
const defaultPruneBatch = 500

// PruneOccurrences deletes occurrence rows with occurred_at strictly before
// `before` (the lookback cutoff), in batches of batchSize, and returns the total
// deleted. It piggybacks on the correlator's flush ticker (R12) — no background
// job. Deletes only occurrence rows; incident rows are untouched. batchSize <= 0
// uses the default. Batching via an id subquery keeps it portable across SQLite
// builds without DELETE ... LIMIT.
func (s *Store) PruneOccurrences(ctx context.Context, before time.Time, batchSize int) (int64, error) {
	if batchSize <= 0 {
		batchSize = defaultPruneBatch
	}
	cutoff := before.UTC().Format(time.RFC3339Nano)
	var total int64
	for {
		res, err := s.db.ExecContext(ctx, `
			DELETE FROM incident_occurrences
			WHERE id IN (
				SELECT id FROM incident_occurrences
				WHERE occurred_at < ?
				ORDER BY id
				LIMIT ?
			)
		`, cutoff, batchSize)
		if err != nil {
			return total, fmt.Errorf("store: prune occurrences: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, fmt.Errorf("store: prune occurrences rows: %w", err)
		}
		total += n
		if n < int64(batchSize) {
			break
		}
	}
	return total, nil
}

func scanOccurrence(sc scanner) (*Occurrence, error) {
	var (
		occ         Occurrence
		occurredStr string
		lastSeenStr string
		fpsJSON     string
		payloadJSON string
	)
	if err := sc.Scan(
		&occ.ID, &occ.IncidentID, &occurredStr, &lastSeenStr,
		&fpsJSON, &payloadJSON, &occ.TriggerKind, &occ.SnapshotRef,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan occurrence: %w", err)
	}
	var err error
	if occ.OccurredAt, err = time.Parse(time.RFC3339Nano, occurredStr); err != nil {
		return nil, fmt.Errorf("store: parse occurred_at: %w", err)
	}
	if occ.LastSeen, err = time.Parse(time.RFC3339Nano, lastSeenStr); err != nil {
		return nil, fmt.Errorf("store: parse last_seen: %w", err)
	}
	if err := json.Unmarshal([]byte(fpsJSON), &occ.Fingerprints); err != nil {
		return nil, fmt.Errorf("store: unmarshal fingerprints: %w", err)
	}
	if err := json.Unmarshal([]byte(payloadJSON), &occ.Payload); err != nil {
		return nil, fmt.Errorf("store: unmarshal payload: %w", err)
	}
	return &occ, nil
}
