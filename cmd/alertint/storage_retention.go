// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/store"
)

// Storage maintenance runs shortly after start, so an upgrade's backlog and a
// long-stopped agent's expired records go early, then hourly (issue #99).
var (
	storageMaintenanceStart    = time.Minute
	storageMaintenanceInterval = time.Hour
)

// storageWarnEvery spaces the size and free-space warnings: the condition
// lasts until someone grows the volume or changes the limits.
const storageWarnEvery = 24 * time.Hour

type storageMaintainer interface {
	RunStorageMaintenance(ctx context.Context, now time.Time, policy store.StoragePolicy, auditLog store.AuditRetention) (store.StorageReport, error)
}

func storagePolicy(cfg *config.Config) store.StoragePolicy {
	return store.StoragePolicy{
		RetentionDays:      cfg.Storage.RetentionDays,
		AuditRetentionDays: cfg.Storage.AuditRetentionDays,
		SizePercent:        cfg.Storage.RetentionSizePercent,
		SizeBytes:          cfg.Storage.RetentionSizeBytes(),
	}
}

type storageMaintenance struct {
	st       storageMaintainer
	auditLog store.AuditRetention
	policy   store.StoragePolicy
	logger   *slog.Logger
	now      func() time.Time

	shortenedWarned, lowFreeWarned time.Time
}

// run passes once after storageMaintenanceStart, then every
// storageMaintenanceInterval, until ctx is done.
func (m *storageMaintenance) run(ctx context.Context) {
	timer := time.NewTimer(storageMaintenanceStart)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		m.pass(ctx)
		timer.Reset(storageMaintenanceInterval)
	}
}

func (m *storageMaintenance) pass(ctx context.Context) {
	now := m.now().UTC()
	// A failed step still returns what the other steps did and what was
	// measured, so the removal line and the warnings below still apply.
	report, err := m.st.RunStorageMaintenance(ctx, now, m.policy, m.auditLog)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		m.logger.Warn("store: storage maintenance failed; next pass in an hour", slog.String("err", err.Error()))
	}
	if r := report.Removed; r.Total() > 0 {
		m.logger.Info("store: storage maintenance",
			slog.Int("compacted_briefings", r.CompactedBriefings),
			slog.Int("repeated_facts", r.RepeatedFacts),
			slog.Int("facts", r.Facts),
			slog.Int("coverage", r.Coverage),
			slog.Int("transition_details", r.TransitionDetails),
			slog.Int("attempt_evidence", r.AttemptEvidence),
			slog.Int("lifecycle_evidence", r.LifecycleEvidence),
			slog.Int("observation", r.Observation),
			slog.Int("audit", r.Audit),
			slog.String("used", formatBytes(report.UsedBytes)),
			slog.Float64("pass_seconds", math.Round(report.PassSeconds*10)/10),
		)
	}
	if report.ShortenedBySizeLimit && now.Sub(m.shortenedWarned) >= storageWarnEvery {
		m.shortenedWarned = now
		attrs := []any{
			slog.String("used", formatBytes(report.UsedBytes)),
			slog.String("limit", formatBytes(report.LimitBytes)),
			slog.Int("retention_days", report.RetentionDays),
			slog.Int("audit_retention_days", report.AuditRetentionDays),
		}
		if report.KeptSince != nil {
			attrs = append(attrs, slog.Float64("kept_days", keptDays(now, *report.KeptSince)))
		}
		if report.AuditKeptSince != nil {
			attrs = append(attrs, slog.Float64("audit_kept_days", keptDays(now, *report.AuditKeptSince)))
		}
		if report.VolumeNeededBytes > 0 {
			attrs = append(attrs, slog.String("volume_needed", formatBytes(report.VolumeNeededBytes)))
		}
		m.logger.Warn("store: storage limit is shortening history; the oldest records went first, memory is kept", attrs...)
	}
	if report.VolumeBytes > 0 && report.VolumeFreeBytes < report.VolumeBytes/10 && now.Sub(m.lowFreeWarned) >= storageWarnEvery {
		m.lowFreeWarned = now
		m.logger.Warn("store: the database volume has less than 10% free; a full volume stops every write",
			slog.String("free", formatBytes(report.VolumeFreeBytes)),
			slog.String("volume", formatBytes(report.VolumeBytes)),
			slog.String("database_used", formatBytes(report.UsedBytes)),
		)
	}
}

func keptDays(now, since time.Time) float64 {
	return math.Round(now.Sub(since).Hours()/24*10) / 10
}

// formatBytes renders n in the largest binary unit that keeps it at or above
// one, with one decimal: 1.5GiB, 812.0MiB.
func formatBytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	v, i := float64(n), 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%dB", n)
	}
	return fmt.Sprintf("%.1f%s", v, units[i])
}
