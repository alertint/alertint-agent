// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"time"
)

// StoragePolicy is how long the working record and the audit log are kept,
// and how much of its volume the database may use. Whichever limit is hit
// first applies. Memory (Situations, their journal and current state) is
// never removed by either.
type StoragePolicy struct {
	// RetentionDays keeps the working record this many days; 0 keeps it.
	RetentionDays int
	// AuditRetentionDays keeps audit entries this many days; 0 keeps them.
	AuditRetentionDays int
	// SizePercent limits the database to this share of the filesystem it is
	// on; SizeBytes, when set, is the limit instead. Neither: no size limit.
	SizePercent int
	SizeBytes   int64
}

// AuditRetention prunes the hash-chained audit log; *audit.Auditor
// implements it. The store does not own the chain.
type AuditRetention interface {
	PruneBefore(ctx context.Context, cutoff time.Time) (int, error)
	OldestEntry(ctx context.Context) (time.Time, bool, error)
}

// StorageReport is the outcome of the latest maintenance pass.
type StorageReport struct {
	CheckedAt time.Time `json:"checked_at"`
	// UsedBytes is the database's pages in use; freed pages are reused by
	// later writes but never returned to the filesystem.
	UsedBytes int64 `json:"used_bytes"`
	FileBytes int64 `json:"file_bytes"`
	// LimitBytes is the size limit in force; 0 means none.
	LimitBytes int64 `json:"limit_bytes,omitempty"`
	// VolumeBytes and VolumeFreeBytes describe the filesystem the database is
	// on; 0 when unknown.
	VolumeBytes        int64 `json:"volume_bytes,omitempty"`
	VolumeFreeBytes    int64 `json:"volume_free_bytes,omitempty"`
	RetentionDays      int   `json:"retention_days"`
	AuditRetentionDays int   `json:"audit_retention_days"`
	// KeptSince is the oldest working record still kept in full, and
	// AuditKeptSince the oldest audit entry.
	KeptSince      *time.Time `json:"kept_since,omitempty"`
	AuditKeptSince *time.Time `json:"audit_kept_since,omitempty"`
	// ShortenedBySizeLimit reports that the size limit, not the retention
	// days, decided what was kept.
	ShortenedBySizeLimit bool `json:"shortened_by_size_limit"`
	// VolumeNeededBytes estimates the volume that would keep RetentionDays
	// at the current rate, when the size limit shortened history.
	VolumeNeededBytes int64          `json:"volume_needed_bytes,omitempty"`
	Removed           StorageRemoved `json:"removed"`
	PassSeconds       float64        `json:"pass_seconds"`
}

// sizeLimitSteps bounds how many times one pass moves the size cutoff; each
// step moves it a tenth of the remaining span. sizeLimitFloor is the newest
// the size cutoff may get, and sizeLimitTarget the share of the limit a
// shortened history is brought back under, so it is not cut every pass.
const (
	sizeLimitSteps   = 40
	sizeLimitFloor   = time.Hour
	sizeLimitTarget  = 95
	retentionDayHour = 24 * time.Hour
)

// RunStorageMaintenance runs one storage maintenance pass at now: the backlog
// left from before migration 0048, then the working record and audit log
// past their retention, then, while the database is over its size limit,
// the oldest data of any kind. The report is also kept for StorageReport.
func (s *Store) RunStorageMaintenance(ctx context.Context, now time.Time, policy StoragePolicy, auditLog AuditRetention) (StorageReport, error) {
	started := time.Now()
	report := StorageReport{RetentionDays: policy.RetentionDays, AuditRetentionDays: policy.AuditRetentionDays}
	removed, err := s.CompactStorageBacklog(ctx)
	report.Removed = report.Removed.plus(removed)
	if err != nil {
		return report, err
	}

	workCutoff := retentionCutoff(now, policy.RetentionDays)
	auditCutoff := retentionCutoff(now, policy.AuditRetentionDays)
	observationCutoff := now.Add(-observationDetailRetention)
	if err := s.expireBefore(ctx, now, workCutoff, auditCutoff, observationCutoff, auditLog, &report.Removed); err != nil {
		return report, err
	}

	usage, err := s.measureStorage(ctx)
	if err != nil {
		return report, err
	}
	limit := policy.SizeBytes
	if limit <= 0 && policy.SizePercent > 0 && usage.volume > 0 {
		limit = usage.volume / 100 * int64(policy.SizePercent)
	}
	if limit > 0 && usage.used > limit {
		report.ShortenedBySizeLimit = true
		cutoffs := sizeCutoffs{work: workCutoff, audit: auditCutoff, observation: observationCutoff}
		if usage, err = s.shrinkToLimit(ctx, now, limit, usage, cutoffs, auditLog, &report.Removed); err != nil {
			return report, err
		}
	}

	report.CheckedAt = now.UTC()
	report.UsedBytes, report.FileBytes, report.LimitBytes = usage.used, usage.file, limit
	report.VolumeBytes, report.VolumeFreeBytes = usage.volume, usage.free
	kept, err := s.oldestWorkingRecord(ctx)
	if err != nil {
		return report, err
	}
	if !kept.IsZero() {
		report.KeptSince = &kept
	}
	if auditLog != nil {
		at, ok, err := auditLog.OldestEntry(ctx)
		if err != nil {
			return report, err
		}
		if ok {
			report.AuditKeptSince = &at
		}
	}
	if report.ShortenedBySizeLimit && report.KeptSince != nil && policy.RetentionDays > 0 {
		report.VolumeNeededBytes = volumeNeeded(usage.used, now.Sub(*report.KeptSince), policy)
	}
	report.PassSeconds = time.Since(started).Seconds()
	s.storageReport.Store(&report)
	return report, nil
}

// sizeCutoffs are the cutoffs one size-limit step applies.
type sizeCutoffs struct {
	work, audit, observation time.Time
}

// shrinkToLimit moves one cutoff forward from the oldest retained record, of
// any kind, a tenth of the remaining span at a time, until the database is
// back under sizeLimitTarget percent of limit or the cutoff reaches
// sizeLimitFloor ago. It returns the usage it ended with.
func (s *Store) shrinkToLimit(ctx context.Context, now time.Time, limit int64, usage storageUsage, cutoffs sizeCutoffs,
	auditLog AuditRetention, removed *StorageRemoved) (storageUsage, error) {
	floor := now.Add(-sizeLimitFloor)
	for step := 0; step < sizeLimitSteps && usage.used > limit/100*sizeLimitTarget; step++ {
		oldest, err := s.oldestRetained(ctx, auditLog)
		if err != nil {
			return usage, err
		}
		if oldest.IsZero() || !oldest.Before(floor) {
			return usage, nil
		}
		sizeCutoff := oldest.Add(max(time.Hour, now.Sub(oldest)/10))
		if sizeCutoff.After(floor) {
			sizeCutoff = floor
		}
		cutoffs.work, cutoffs.audit = later(cutoffs.work, sizeCutoff), later(cutoffs.audit, sizeCutoff)
		cutoffs.observation = later(cutoffs.observation, sizeCutoff)
		if err := s.expireBefore(ctx, now, cutoffs.work, cutoffs.audit, cutoffs.observation, auditLog, removed); err != nil {
			return usage, err
		}
		if usage, err = s.measureStorage(ctx); err != nil {
			return usage, err
		}
	}
	return usage, nil
}

// StorageReport returns the latest maintenance pass's report, if any pass ran.
func (s *Store) StorageReport() (StorageReport, bool) {
	report := s.storageReport.Load()
	if report == nil {
		return StorageReport{}, false
	}
	return *report, true
}

func (s *Store) expireBefore(ctx context.Context, now, workCutoff, auditCutoff, observationCutoff time.Time, auditLog AuditRetention, removed *StorageRemoved) error {
	r, err := s.ExpireWorkingRecord(ctx, now, workCutoff, observationCutoff)
	*removed = removed.plus(r)
	if err != nil {
		return err
	}
	if auditLog == nil || auditCutoff.IsZero() {
		return nil
	}
	n, err := auditLog.PruneBefore(ctx, auditCutoff)
	removed.Audit += n
	return err
}

func retentionCutoff(now time.Time, days int) time.Time {
	if days <= 0 {
		return time.Time{}
	}
	return now.Add(-time.Duration(days) * retentionDayHour)
}

func later(a, b time.Time) time.Time {
	if a.IsZero() || b.After(a) {
		return b
	}
	return a
}

// volumeNeeded estimates the volume that keeps policy.RetentionDays at the
// rate the kept span was written: used bytes scaled from the span kept to
// the span wanted, divided by the share of the volume the database may use.
func volumeNeeded(used int64, kept time.Duration, policy StoragePolicy) int64 {
	if kept <= 0 {
		return 0
	}
	wanted := time.Duration(policy.RetentionDays) * retentionDayHour
	if wanted <= kept {
		return 0
	}
	need := float64(used) * float64(wanted) / float64(kept)
	if policy.SizeBytes <= 0 && policy.SizePercent > 0 {
		need = need * 100 / float64(policy.SizePercent)
	}
	return int64(need)
}

type storageUsage struct {
	used, file, volume, free int64
}

// measureStorage reads the database's pages in use and its file size, and
// the filesystem holding it.
func (s *Store) measureStorage(ctx context.Context) (storageUsage, error) {
	var pageSize, pages, free int64
	for _, p := range []struct {
		pragma string
		out    *int64
	}{{"page_size", &pageSize}, {"page_count", &pages}, {"freelist_count", &free}} {
		if err := s.db.QueryRowContext(ctx, `PRAGMA `+p.pragma).Scan(p.out); err != nil {
			return storageUsage{}, fmt.Errorf("store: read %s: %w", p.pragma, err)
		}
	}
	u := storageUsage{used: (pages - free) * pageSize, file: pages * pageSize}
	if s.path != "" {
		u.volume, u.free, _ = volumeSpace(filepath.Dir(s.path))
	}
	return u, nil
}

// oldestRetained is the oldest data the size limit may remove: the oldest
// working record or the oldest audit entry.
func (s *Store) oldestRetained(ctx context.Context, auditLog AuditRetention) (time.Time, error) {
	oldest, err := s.oldestWorkingRecord(ctx)
	if err != nil || auditLog == nil {
		return oldest, err
	}
	at, ok, err := auditLog.OldestEntry(ctx)
	if err != nil {
		return time.Time{}, err
	}
	if ok && (oldest.IsZero() || at.Before(oldest)) {
		oldest = at
	}
	return oldest, nil
}

// oldestWorkingRecord is the time of the oldest record retention could still
// remove: Transition detail, attempt evidence, superseded and ended
// Situations' facts, facts written before 0048. Zero when there is none.
func (s *Store) oldestWorkingRecord(ctx context.Context) (time.Time, error) {
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return time.Time{}, fmt.Errorf("store: begin oldest working record: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	legacyMax, err := retentionStateTx(ctx, tx, "facts_legacy_max_rowid")
	if err != nil {
		return time.Time{}, err
	}
	legacyCursor, err := retentionStateTx(ctx, tx, "facts_legacy_age_cursor")
	if err != nil {
		return time.Time{}, err
	}
	queries := []struct {
		query string
		args  []any
	}{
		{`SELECT t.created_at FROM situation_transitions t INDEXED BY situation_transitions_unexpired_idx
			WHERE t.detail_expired_at IS NULL AND t.id NOT IN (SELECT transition_id FROM storage_protected_transitions)
			ORDER BY t.rowid LIMIT 1`, nil},
		{`SELECT a.completed_at FROM situation_assessment_attempts a INDEXED BY situation_assessment_attempts_unreleased_idx
			WHERE a.evidence_released_at IS NULL AND a.id NOT IN (SELECT attempt_id FROM storage_protected_attempts)
			ORDER BY a.rowid LIMIT 1`, nil},
		{`SELECT superseded_at FROM situation_fact_supersessions ORDER BY rowid LIMIT 1`, nil},
		{`SELECT min(s.terminal_at) FROM situations s
			WHERE s.terminal_at IS NOT NULL AND EXISTS (SELECT 1 FROM situation_fact_heads h WHERE h.situation_id = s.id)`, nil},
		{`SELECT observed_at FROM situation_facts WHERE rowid > ? AND rowid <= ? ORDER BY rowid LIMIT 1`,
			[]any{legacyCursor, legacyMax}},
	}
	var oldest time.Time
	for _, q := range queries {
		var at sql.NullString
		err := tx.QueryRowContext(ctx, q.query, q.args...).Scan(&at)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && !at.Valid) {
			continue
		}
		if err != nil {
			return time.Time{}, fmt.Errorf("store: read oldest working record: %w", err)
		}
		t, err := parseStoredTime(at.String)
		if err != nil {
			return time.Time{}, err
		}
		if oldest.IsZero() || t.Before(oldest) {
			oldest = t
		}
	}
	return oldest, nil
}

func clampInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}
