// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/store"
)

type fakeMaintainer struct {
	report store.StorageReport
	err    error
	policy store.StoragePolicy
	passes int
}

func (f *fakeMaintainer) RunStorageMaintenance(_ context.Context, _ time.Time, policy store.StoragePolicy, _ store.AuditRetention) (store.StorageReport, error) {
	f.passes++
	f.policy = policy
	return f.report, f.err
}

func TestStoragePolicyFromConfig(t *testing.T) {
	cfg := config.Defaults()
	cfg.Storage.RetentionSize = "8GiB"
	got := storagePolicy(&cfg)
	want := store.StoragePolicy{RetentionDays: 90, AuditRetentionDays: 365, SizePercent: 80, SizeBytes: 8 << 30}
	if got != want {
		t.Fatalf("storagePolicy = %+v, want %+v", got, want)
	}
}

func TestStorageMaintenanceWarnsOncePerDay(t *testing.T) {
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)
	kept, auditKept := now.Add(-40*24*time.Hour), now.Add(-40*24*time.Hour)
	f := &fakeMaintainer{report: store.StorageReport{
		UsedBytes: 11 << 30, LimitBytes: 11 << 30, VolumeBytes: 14 << 30, VolumeFreeBytes: 1 << 30,
		RetentionDays: 90, AuditRetentionDays: 365, KeptSince: &kept, AuditKeptSince: &auditKept,
		ShortenedBySizeLimit: true, VolumeNeededBytes: 50 << 30,
		Removed: store.StorageRemoved{TransitionDetails: 12, Audit: 400},
	}}
	var logs bytes.Buffer
	m := &storageMaintenance{st: f, logger: slog.New(slog.NewTextHandler(&logs, nil)), now: func() time.Time { return now }}

	m.pass(context.Background())
	out := logs.String()
	for _, want := range []string{
		"store: storage maintenance", "transition_details=12", "audit=400",
		"storage limit is shortening history", "kept_days=40", "audit_kept_days=40", "volume_needed=50.0GiB",
		"less than 10% free", "free=1.0GiB",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("first pass log lacks %q:\n%s", want, out)
		}
	}

	logs.Reset()
	now = now.Add(time.Hour)
	m.pass(context.Background())
	if strings.Contains(logs.String(), "WARN") {
		t.Fatalf("an hour later the warnings repeated:\n%s", logs.String())
	}
	logs.Reset()
	now = now.Add(24 * time.Hour)
	m.pass(context.Background())
	if strings.Count(logs.String(), "level=WARN") != 2 {
		t.Fatalf("a day later both warnings should repeat once:\n%s", logs.String())
	}
}

func TestStorageMaintenanceQuietWhenNothingHappened(t *testing.T) {
	f := &fakeMaintainer{report: store.StorageReport{UsedBytes: 1 << 20, VolumeBytes: 100 << 30, VolumeFreeBytes: 60 << 30}}
	var logs bytes.Buffer
	m := &storageMaintenance{st: f, logger: slog.New(slog.NewTextHandler(&logs, nil)), now: time.Now}
	m.pass(context.Background())
	if logs.Len() != 0 {
		t.Fatalf("a pass that removed nothing logged:\n%s", logs.String())
	}
	f.err = errors.New("disk I/O error")
	m.pass(context.Background())
	if !strings.Contains(logs.String(), "storage maintenance failed") {
		t.Fatalf("a failed pass was not logged:\n%s", logs.String())
	}
}

// One step that fails every pass must not hide the warnings: the pass still
// measured the volume and returned its report.
func TestStorageMaintenanceWarnsWhenAStepFailed(t *testing.T) {
	f := &fakeMaintainer{report: store.StorageReport{UsedBytes: 9 << 30, VolumeBytes: 10 << 30, VolumeFreeBytes: 512 << 20},
		err: errors.New("store: compact legacy briefing: boom")}
	var logs bytes.Buffer
	m := &storageMaintenance{st: f, logger: slog.New(slog.NewTextHandler(&logs, nil)), now: time.Now}
	m.pass(context.Background())
	for _, want := range []string{"storage maintenance failed", "less than 10% free"} {
		if !strings.Contains(logs.String(), want) {
			t.Fatalf("log lacks %q:\n%s", want, logs.String())
		}
	}
}

func TestStorageMaintenanceRunsAtStartThenEveryInterval(t *testing.T) {
	start, interval := storageMaintenanceStart, storageMaintenanceInterval
	t.Cleanup(func() { storageMaintenanceStart, storageMaintenanceInterval = start, interval })
	storageMaintenanceStart, storageMaintenanceInterval = time.Millisecond, 5*time.Millisecond
	f := &fakeMaintainer{}
	m := &storageMaintenance{st: f, logger: slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)), now: time.Now}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	m.run(ctx)
	if f.passes < 3 {
		t.Fatalf("passes = %d in 200ms, want several", f.passes)
	}
}

func TestFormatBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0B", 512: "512B", 1536: "1.5KiB", 50 << 30: "50.0GiB", 3 << 40: "3.0TiB"} {
		if got := formatBytes(n); got != want {
			t.Errorf("formatBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
