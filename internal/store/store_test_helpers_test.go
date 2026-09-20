// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

var (
	migratedTestTemplateOnce sync.Once
	migratedTestTemplate     string
	errMigratedTestTemplate  error
)

func newTestStore(t *testing.T) *Store {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "alertint.db")
	if err := writeMigratedTestDatabase(dbPath); err != nil {
		t.Fatalf("prepare migrated test database: %v", err)
	}

	st, err := openTestStoreWithMigrations(context.Background(), dbPath)
	if err != nil {
		t.Fatalf("open migrated test database copy: %v", err)
	}
	t.Cleanup(func() {
		if err := st.Close(); err != nil {
			t.Errorf("close migrated test database copy: %v", err)
		}
	})
	return st
}

func writeMigratedTestDatabase(dbPath string) error {
	template, err := migratedTestDatabaseTemplate()
	if err != nil {
		return err
	}
	if err := os.WriteFile(dbPath, []byte(template), 0o600); err != nil {
		return fmt.Errorf("copy template to %s: %w", dbPath, err)
	}
	return nil
}

func migratedTestDatabaseTemplate() (string, error) {
	migratedTestTemplateOnce.Do(func() {
		migratedTestTemplate, errMigratedTestTemplate = buildMigratedTestDatabaseTemplate()
	})
	return migratedTestTemplate, errMigratedTestTemplate
}

func buildMigratedTestDatabaseTemplate() (template string, err error) {
	templateDir, err := os.MkdirTemp("", "alertint-store-test-template-")
	if err != nil {
		return "", fmt.Errorf("create template directory: %w", err)
	}
	defer func() {
		if cleanupErr := os.RemoveAll(templateDir); cleanupErr != nil && err == nil {
			err = fmt.Errorf("remove template directory: %w", cleanupErr)
		}
	}()

	ctx := context.Background()
	dbPath := filepath.Join(templateDir, "template.db")
	st, err := openTestStoreWithMigrations(ctx, dbPath)
	if err != nil {
		return "", fmt.Errorf("migrate template database: %w", err)
	}

	var busy, logFrames, checkpointedFrames int
	checkpointErr := st.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logFrames, &checkpointedFrames)
	closeErr := st.Close()
	if checkpointErr != nil {
		return "", fmt.Errorf("checkpoint template database: %w", checkpointErr)
	}
	if busy != 0 {
		return "", fmt.Errorf("checkpoint template database: %d connection(s) remained busy", busy)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close template database: %w", closeErr)
	}

	if info, statErr := os.Stat(dbPath + "-wal"); statErr == nil && info.Size() != 0 {
		return "", fmt.Errorf("template WAL still contains %d bytes after checkpoint and close", info.Size())
	} else if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
		return "", fmt.Errorf("inspect template WAL: %w", statErr)
	}

	contents, err := os.ReadFile(dbPath)
	if err != nil {
		return "", fmt.Errorf("read template database: %w", err)
	}
	if len(contents) == 0 {
		return "", errors.New("template database is empty")
	}
	return string(contents), nil
}

func TestMigratedTestDatabaseSupportsConcurrentCopies(t *testing.T) {
	const copyCount = 8

	ctx := context.Background()
	dir := t.TempDir()
	start := make(chan struct{})
	errs := make(chan error, copyCount)
	var workers sync.WaitGroup
	workers.Add(copyCount)
	for i := range copyCount {
		go func() {
			defer workers.Done()
			<-start

			dbPath := filepath.Join(dir, fmt.Sprintf("copy-%d.db", i))
			if err := writeMigratedTestDatabase(dbPath); err != nil {
				errs <- fmt.Errorf("copy %d: %w", i, err)
				return
			}
			st, err := openTestStoreWithMigrations(ctx, dbPath)
			if err != nil {
				errs <- fmt.Errorf("open copy %d: %w", i, err)
				return
			}
			var migrationCount int
			queryErr := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&migrationCount)
			closeErr := st.Close()
			if queryErr != nil {
				errs <- fmt.Errorf("query copy %d: %w", i, queryErr)
				return
			}
			if closeErr != nil {
				errs <- fmt.Errorf("close copy %d: %w", i, closeErr)
				return
			}
			migrations, err := loadMigrations()
			if err != nil {
				errs <- fmt.Errorf("load migrations for copy %d: %w", i, err)
				return
			}
			if migrationCount != len(migrations) {
				errs <- fmt.Errorf("copy %d migration count = %d, want %d", i, migrationCount, len(migrations))
			}
		}()
	}
	close(start)
	workers.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}
}

// openTestStoreWithMigrations is the one explicit direct-Open exception in
// store tests. Use it only when a test covers migration, upgrade, reopen, or
// persistence behavior. Ordinary tests must use newTestStore so they copy the
// process-wide migrated schema instead of replaying every migration.
func openTestStoreWithMigrations(ctx context.Context, dbPath string) (*Store, error) {
	return Open(ctx, dbPath)
}
