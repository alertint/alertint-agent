// SPDX-License-Identifier: FSL-1.1-ALv2

package backup

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAdmissionCheck(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	valid := newStoreDB(t, dir, "valid.db")

	garbage := filepath.Join(dir, "garbage.db")
	if err := os.WriteFile(garbage, []byte("this is not a sqlite file at all"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A perfectly healthy SQLite DB that is not an alertint database.
	foreign := filepath.Join(dir, "foreign.db")
	fdb, err := sql.Open("sqlite", "file:"+foreign)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fdb.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	_ = fdb.Close()

	// A valid alertint DB claiming a future schema version.
	future := newStoreDB(t, dir, "future.db")
	fdb2, err := sql.Open("sqlite", "file:"+future)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fdb2.Exec(
		`INSERT INTO schema_migrations (version, applied_at) VALUES (9999, '2026-07-28T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	_ = fdb2.Close()

	cases := []struct {
		name, file, wantSubstr string
		wantOK                 bool
	}{
		{"valid alertint db passes", valid, "", true},
		{"garbage file rejected", garbage, "", false},
		{"foreign sqlite db rejected", foreign, "not an alertint database", false},
		{"newer schema rejected", future, "newer than this binary", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := admissionCheck(ctx, tc.file)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("admissionCheck = %v, want ok", err)
				}
				return
			}
			if err == nil {
				t.Fatal("admissionCheck = ok, want failure")
			}
			var adm *AdmissionError
			if !errors.As(err, &adm) {
				t.Fatalf("error %v is not an *AdmissionError", err)
			}
			if tc.wantSubstr != "" && !strings.Contains(err.Error(), tc.wantSubstr) {
				t.Errorf("error %q does not contain %q", err, tc.wantSubstr)
			}
		})
	}
}
