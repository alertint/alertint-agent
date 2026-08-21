// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DependencyHealthStatus is the closed installation-level health state for
// one shared dependency (e.g. the configured LLM, a connector). It is
// deliberately independent of any Situation: a shared outage produces at
// most one health root plus one recovery update rather than fanning out
// into a per-Situation notice.
type DependencyHealthStatus string

const (
	DependencyHealthy     DependencyHealthStatus = "healthy"
	DependencyDegraded    DependencyHealthStatus = "degraded"
	DependencyUnavailable DependencyHealthStatus = "unavailable"
)

// DependencyHealth is the durable installation-level state for one
// dependency. SlackChannel/SlackMessageTS are the coordinates of the most
// recently posted health root, stamped by MarkNotificationDelivered so a
// later health_update targets the exact persisted message.
type DependencyHealth struct {
	Dependency      string
	Status          DependencyHealthStatus
	DegradedSince   *time.Time
	LastBroadcastAt *time.Time
	RecoveredAt     *time.Time
	SlackChannel    *string
	SlackMessageTS  *string
	UpdatedAt       time.Time
}

// DependencyHealthState reads the current durable state for one dependency.
// ok is false when the dependency has never been observed.
func (s *Store) DependencyHealthState(ctx context.Context, dependency string) (DependencyHealth, bool, error) {
	if strings.TrimSpace(dependency) == "" {
		return DependencyHealth{}, false, errors.New("store: dependency health lookup requires a dependency name")
	}
	out, err := scanDependencyHealth(s.db.QueryRowContext(ctx, `SELECT `+dependencyHealthColumns+` FROM dependency_health WHERE dependency = ?`, dependency))
	if errors.Is(err, ErrNotFound) {
		return DependencyHealth{}, false, nil
	}
	if err != nil {
		return DependencyHealth{}, false, err
	}
	return out, true, nil
}

// RecordDependencyDegraded marks dependency degraded (or unavailable, when
// unavailable is true), first observed at observedAt. It is idempotent: a
// dependency already degraded keeps its original degraded_since so a
// broadcast decision (e.g. "sustained for N seconds") stays anchored to the
// first observation, not the most recent retry. transitioned reports
// whether this call actually moved the dependency out of healthy — the
// signal a caller uses to decide whether a fresh health_root is due.
func (s *Store) RecordDependencyDegraded(ctx context.Context, dependency string, unavailable bool, observedAt time.Time) (health DependencyHealth, transitioned bool, err error) {
	if strings.TrimSpace(dependency) == "" || observedAt.IsZero() {
		return DependencyHealth{}, false, errors.New("store: recording dependency degradation requires a dependency name and observation time")
	}
	status := DependencyDegraded
	if unavailable {
		status = DependencyUnavailable
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DependencyHealth{}, false, fmt.Errorf("store: begin record dependency degraded: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, ok, err := dependencyHealthTx(ctx, tx, dependency)
	if err != nil {
		return DependencyHealth{}, false, err
	}
	switch {
	case !ok:
		if _, err := tx.ExecContext(ctx, `INSERT INTO dependency_health (dependency, status, degraded_since, updated_at) VALUES (?,?,?,?)`,
			dependency, status, canonicalTime(observedAt), canonicalTime(observedAt)); err != nil {
			return DependencyHealth{}, false, fmt.Errorf("store: insert dependency health: %w", err)
		}
		transitioned = true
	case current.Status == DependencyHealthy:
		if _, err := tx.ExecContext(ctx, `UPDATE dependency_health SET status = ?, degraded_since = ?, recovered_at = NULL, updated_at = ? WHERE dependency = ?`,
			status, canonicalTime(observedAt), canonicalTime(observedAt), dependency); err != nil {
			return DependencyHealth{}, false, fmt.Errorf("store: update dependency health degraded: %w", err)
		}
		transitioned = true
	case current.Status != status:
		// Already unhealthy but the severity changed (degraded <-> unavailable):
		// preserve the original degraded_since, just update the status.
		if _, err := tx.ExecContext(ctx, `UPDATE dependency_health SET status = ?, updated_at = ? WHERE dependency = ?`,
			status, canonicalTime(observedAt), dependency); err != nil {
			return DependencyHealth{}, false, fmt.Errorf("store: update dependency health severity: %w", err)
		}
	}
	out, _, err := dependencyHealthTx(ctx, tx, dependency)
	if err != nil {
		return DependencyHealth{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return DependencyHealth{}, false, fmt.Errorf("store: commit record dependency degraded: %w", err)
	}
	return out, transitioned, nil
}

// RecordDependencyRecovered marks dependency healthy again. transitioned
// reports whether this call actually moved the dependency out of a degraded
// or unavailable state — the signal a caller uses to decide whether the one
// permitted recovery update is due.
func (s *Store) RecordDependencyRecovered(ctx context.Context, dependency string, observedAt time.Time) (health DependencyHealth, transitioned bool, err error) {
	if strings.TrimSpace(dependency) == "" || observedAt.IsZero() {
		return DependencyHealth{}, false, errors.New("store: recording dependency recovery requires a dependency name and observation time")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return DependencyHealth{}, false, fmt.Errorf("store: begin record dependency recovered: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	current, ok, err := dependencyHealthTx(ctx, tx, dependency)
	if err != nil {
		return DependencyHealth{}, false, err
	}
	if !ok {
		return DependencyHealth{}, false, ErrNotFound
	}
	if current.Status != DependencyHealthy {
		if _, err := tx.ExecContext(ctx, `UPDATE dependency_health SET status = 'healthy', degraded_since = NULL, recovered_at = ?, updated_at = ? WHERE dependency = ?`,
			canonicalTime(observedAt), canonicalTime(observedAt), dependency); err != nil {
			return DependencyHealth{}, false, fmt.Errorf("store: update dependency health recovered: %w", err)
		}
		transitioned = true
	}
	out, _, err := dependencyHealthTx(ctx, tx, dependency)
	if err != nil {
		return DependencyHealth{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return DependencyHealth{}, false, fmt.Errorf("store: commit record dependency recovered: %w", err)
	}
	return out, transitioned, nil
}

const dependencyHealthColumns = `dependency, status, degraded_since, last_broadcast_at, recovered_at, slack_channel, slack_message_ts, updated_at`

func dependencyHealthTx(ctx context.Context, tx *sql.Tx, dependency string) (DependencyHealth, bool, error) {
	out, err := scanDependencyHealth(tx.QueryRowContext(ctx, `SELECT `+dependencyHealthColumns+` FROM dependency_health WHERE dependency = ?`, dependency))
	if errors.Is(err, ErrNotFound) {
		return DependencyHealth{}, false, nil
	}
	if err != nil {
		return DependencyHealth{}, false, err
	}
	return out, true, nil
}

func scanDependencyHealth(row rowScanner) (DependencyHealth, error) {
	var out DependencyHealth
	var status, updatedAt string
	var degradedSince, lastBroadcastAt, recoveredAt, slackChannel, slackMessageTS sql.NullString
	err := row.Scan(&out.Dependency, &status, &degradedSince, &lastBroadcastAt, &recoveredAt, &slackChannel, &slackMessageTS, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return DependencyHealth{}, ErrNotFound
	}
	if err != nil {
		return DependencyHealth{}, fmt.Errorf("store: scan dependency health: %w", err)
	}
	out.Status = DependencyHealthStatus(status)
	out.SlackChannel = nullStringPtr(slackChannel)
	out.SlackMessageTS = nullStringPtr(slackMessageTS)
	if out.DegradedSince, err = parseNullableSituationTime("dependency degraded_since", degradedSince); err != nil {
		return DependencyHealth{}, err
	}
	if out.LastBroadcastAt, err = parseNullableSituationTime("dependency last_broadcast_at", lastBroadcastAt); err != nil {
		return DependencyHealth{}, err
	}
	if out.RecoveredAt, err = parseNullableSituationTime("dependency recovered_at", recoveredAt); err != nil {
		return DependencyHealth{}, err
	}
	if out.UpdatedAt, err = parseSituationTime("dependency updated_at", updatedAt); err != nil {
		return DependencyHealth{}, err
	}
	return out, nil
}
