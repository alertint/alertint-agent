// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/alertint/alertint-agent/internal/store"
)

// newTestDB creates a real alertint DB and returns its path.
func newTestDB(t *testing.T, dir string) string {
	t.Helper()
	dbPath := filepath.Join(dir, "alertint-agent.db")
	st, err := store.Open(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return dbPath
}

func TestRunBackup_RequiresDBOrConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"backup"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "either --config or --db is required") {
		t.Fatalf("err = %v, want flag-requirement error", err)
	}
}

func TestRunBackup_ExplicitTarget(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDB(t, dir)
	target := filepath.Join(dir, "out.backup.db")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"backup", "--db", dbPath, target}, &stdout, &stderr); err != nil {
		t.Fatalf("backup: %v (stderr=%s)", err, stderr.String())
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("target not written: %v", err)
	}
	if !strings.Contains(stdout.String(), target) {
		t.Errorf("stdout %q does not name the target", stdout.String())
	}
}

func TestRunBackup_DefaultNamingInCwd(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDB(t, dir)
	t.Chdir(dir) // default target lands in cwd

	var stdout, stderr bytes.Buffer
	if err := run([]string{"backup", "--db", dbPath}, &stdout, &stderr); err != nil {
		t.Fatalf("backup: %v", err)
	}
	entries, err := filepath.Glob(filepath.Join(dir, "alertint-agent-*.backup.db"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("default-named backup files = %v (err=%v), want exactly 1", entries, err)
	}
	stampRe := regexp.MustCompile(`alertint-agent-\d{8}T\d{6}Z\.backup\.db$`)
	if !stampRe.MatchString(entries[0]) {
		t.Errorf("default name %q does not match naming contract", entries[0])
	}
}

func TestRunBackup_RefusesOverwriteWithoutForce(t *testing.T) {
	dir := t.TempDir()
	dbPath := newTestDB(t, dir)
	target := filepath.Join(dir, "out.backup.db")

	var stdout, stderr bytes.Buffer
	if err := run([]string{"backup", "--db", dbPath, target}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"backup", "--db", dbPath, target}, &stdout, &stderr)
	if err == nil || !strings.HasPrefix(err.Error(), "backup: ") {
		t.Fatalf("err = %v, want 'backup: ...' overwrite refusal", err)
	}
	if err := run([]string{"backup", "--db", dbPath, "--force", target}, &stdout, &stderr); err != nil {
		t.Fatalf("--force: %v", err)
	}
}
