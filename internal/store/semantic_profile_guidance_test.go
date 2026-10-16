// SPDX-License-Identifier: FSL-1.1-ALv2

package store

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"modernc.org/sqlite"

	profilemodel "github.com/alertint/alertint-agent/internal/semanticprofile/model"
)

// Slow result consumption represents storage/decoding work while the connection
// is occupied. Availability must depend on the size of a page, not total history.
func TestProfileGuidanceLeavesConnectionAvailable(t *testing.T) {
	st := newTestStore(t)
	ids := seedGuidanceProfiles(t, st, 1500)
	started := make(chan struct{})
	var first sync.Once
	observeGuidance(t, st, &guidanceObserver{next: func() {
		first.Do(func() { close(started) })
		time.Sleep(time.Millisecond)
	}})
	done := make(chan struct{})
	probeDone := make(chan error, 1)
	go func() {
		select {
		case <-started:
		case <-done:
			probeDone <- nil
			return
		}
		var failure error
		for {
			select {
			case <-done:
				probeDone <- failure
				return
			default:
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			err := st.DB().PingContext(ctx)
			cancel()
			if err != nil {
				failure = err
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	// Reverse and repeat across pages: input order and duplicates must not
	// affect the signature ordering or the parallel frozen-version slice.
	requested := make([]string, 0, 2*len(ids))
	for n := len(ids) - 1; n >= 0; n-- {
		requested = append(requested, ids[n])
	}
	requested = append(requested, ids...)
	guidance, versions, err := st.LoadProfileGuidanceForDeliveries(context.Background(), requested)
	close(done)
	probeErr := <-probeDone
	if err != nil {
		t.Fatal(err)
	}
	if probeErr != nil {
		t.Fatalf("readiness ping timed out while guidance occupied the connection: %v", probeErr)
	}
	if len(guidance) != len(ids) || len(versions) != len(ids) {
		t.Fatalf("guidance=%d versions=%d, want %d complete results", len(guidance), len(versions), len(ids))
	}
	for n, entry := range guidance {
		if entry.SignatureKey != fmt.Sprintf("guidance-signature-%04d", n) || entry.VersionID != versions[n] {
			t.Fatalf("unordered or unpaired guidance at %d: %+v version=%s", n, entry, versions[n])
		}
	}
}

func TestProfileGuidanceKeepsHeadAcrossDeletionAndReinsertion(t *testing.T) {
	for _, reinsert := range []bool{false, true} {
		t.Run(fmt.Sprintf("reinsert-%t", reinsert), func(t *testing.T) {
			st := newTestStore(t)
			ids := seedGuidanceProfiles(t, st, 1)
			writer := guidanceWriter(t, st)
			var mutationErr error
			observeGuidance(t, st, &guidanceObserver{closed: func() {
				tx, err := writer.BeginTx(context.Background(), nil)
				if err != nil {
					mutationErr = err
					return
				}
				defer func() { _ = tx.Rollback() }()
				if _, err := tx.ExecContext(context.Background(), `DELETE FROM semantic_profile_heads WHERE signature_key='guidance-signature-0000'`); err != nil {
					mutationErr = err
					return
				}
				if reinsert {
					if _, err := tx.ExecContext(context.Background(), `INSERT INTO semantic_profile_heads(signature_key,current_version,version_id,updated_at) VALUES ('guidance-signature-0000',1,'guidance-version-0000','2026-10-15T00:00:00Z')`); err != nil {
						mutationErr = err
						return
					}
				}
				mutationErr = tx.Commit()
			}})
			_, versions, err := st.LoadProfileGuidanceForDeliveries(context.Background(), ids)
			if err != nil || mutationErr != nil || len(versions) != 1 || versions[0] != "guidance-version-0000" {
				t.Fatalf("fenced deleted head: versions=%v err=%v mutation=%v", versions, err, mutationErr)
			}
			_, versions, err = st.LoadProfileGuidanceForDeliveries(context.Background(), ids)
			want := 0
			if reinsert {
				want = 1
			}
			if err != nil || len(versions) != want {
				t.Fatalf("next snapshot: versions=%v err=%v, want %d", versions, err, want)
			}
		})
	}
}

func TestProfileGuidanceKeepsCommittedMappingAndHeadSnapshot(t *testing.T) {
	st := newTestStore(t)
	ids := seedGuidanceProfiles(t, st, 3)
	ctx := context.Background()
	// The second requested delivery initially has no mapping or profile head.
	// Its immutable version exists, but is not published yet.
	if _, err := st.db.ExecContext(ctx, `DELETE FROM semantic_profile_heads WHERE signature_key='guidance-signature-0001'`); err != nil {
		t.Fatal(err)
	}
	unmapped := deliveryFixture("guidance-unmapped", "fp-guidance-unmapped", time.Now().UTC())
	lateMapping := deliveryFixture("guidance-late-mapping", "fp-guidance-late-mapping", time.Now().UTC())
	if _, err := st.AcceptDeliveries(ctx, []DeliveryInput{unmapped, lateMapping}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.ExecContext(ctx, `INSERT INTO semantic_profile_versions(id,signature_key,version,schema_version,prompt_version,semantic_input_digest,origin,profile_json,created_at,asserted_by)
		SELECT 'guidance-version-new',signature_key,2,1,1,'digest','correction',profile_json,created_at,asserted_by FROM semantic_profile_versions WHERE id='guidance-version-0000'`); err != nil {
		t.Fatal(err)
	}
	writer := guidanceWriter(t, st)
	var mutationErr error
	mutated := false
	observeGuidance(t, st, &guidanceObserver{closed: func() {
		mutated = true
		tx, err := writer.BeginTx(ctx, nil)
		if err != nil {
			mutationErr = err
			return
		}
		defer func() { _ = tx.Rollback() }()
		for _, statement := range []struct {
			sql  string
			args []any
		}{
			{`UPDATE semantic_profile_heads SET current_version=2,version_id='guidance-version-new' WHERE signature_key='guidance-signature-0000'`, nil},
			{`INSERT INTO delivery_semantic_signatures(delivery_id,signature_key,signature_digest,schema_version,material_json,mode,advisory_only,created_at) VALUES (?,'guidance-signature-0001','digest',1,'{}','fallback',1,'2026-10-15T00:00:00Z')`, []any{unmapped.ID}},
			{`INSERT INTO semantic_profile_heads(signature_key,current_version,version_id,updated_at) VALUES ('guidance-signature-0001',1,'guidance-version-0001','2026-10-15T00:00:00Z')`, nil},
			// This signature already had a published head at snapshot time.
			// Its late mapping must be excluded independently of head fencing.
			{`INSERT INTO delivery_semantic_signatures(delivery_id,signature_key,signature_digest,schema_version,material_json,mode,advisory_only,created_at) VALUES (?,'guidance-signature-0002','digest',1,'{}','fallback',1,'2026-10-15T00:00:00Z')`, []any{lateMapping.ID}},
		} {
			if _, err := tx.ExecContext(ctx, statement.sql, statement.args...); err != nil {
				mutationErr = err
				return
			}
		}
		mutationErr = tx.Commit()
	}})
	// Put the unmapped ID first and the mapped ID last, across page boundaries.
	requested := []string{unmapped.ID, lateMapping.ID}
	for n := 0; n < 300; n++ {
		requested = append(requested, fmt.Sprintf("absent-%03d", n))
	}
	requested = append(requested, ids[0])
	guidance, versions, err := st.LoadProfileGuidanceForDeliveries(ctx, requested)
	if err != nil {
		t.Fatal(err)
	}
	if !mutated || mutationErr != nil {
		t.Fatalf("concurrent atomic publication: happened=%v err=%v", mutated, mutationErr)
	}
	if len(guidance) != 1 || len(versions) != 1 || versions[0] != "guidance-version-0000" {
		t.Fatalf("mixed committed states: guidance=%+v versions=%v; want original mapping/head snapshot", guidance, versions)
	}
}

func TestProfileGuidanceCancellationReturnsNoPartialResult(t *testing.T) {
	st := newTestStore(t)
	ids := seedGuidanceProfiles(t, st, 200)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	count := 0
	observeGuidance(t, st, &guidanceObserver{next: func() {
		count++
		if count == 50 {
			cancel()
		}
	}})
	guidance, versions, err := st.LoadProfileGuidanceForDeliveries(ctx, ids)
	if !errors.Is(err, context.Canceled) || guidance != nil || versions != nil {
		t.Fatalf("canceled read: guidance=%v versions=%v err=%v", guidance, versions, err)
	}
}

func seedGuidanceProfiles(t *testing.T, st *Store, count int) []string {
	t.Helper()
	now := time.Date(2026, 10, 15, 0, 0, 0, 0, time.UTC)
	deliveries := make([]DeliveryInput, count)
	ids := make([]string, count)
	for n := range deliveries {
		ids[n] = fmt.Sprintf("guidance-delivery-%04d", n)
		deliveries[n] = deliveryFixture(ids[n], "guidance-fingerprint", now)
	}
	if _, err := st.AcceptDeliveries(context.Background(), deliveries); err != nil {
		t.Fatal(err)
	}
	profile, err := json.Marshal(profilemodel.Profile{SubjectKind: "service", EventKind: "availability", PossibleRole: "symptom", CandidateScope: []string{"service"}, HorizonTier: "minutes"})
	if err != nil {
		t.Fatal(err)
	}
	tx, err := st.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for n, id := range ids {
		signature := fmt.Sprintf("guidance-signature-%04d", n)
		version := fmt.Sprintf("guidance-version-%04d", n)
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO delivery_semantic_signatures(delivery_id,signature_key,signature_digest,schema_version,material_json,mode,advisory_only,created_at) VALUES (?,?,'digest',1,'{}','fallback',1,?)`, id, signature, canonicalTime(now)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO semantic_profile_versions(id,signature_key,version,schema_version,prompt_version,semantic_input_digest,origin,profile_json,created_at,asserted_by) VALUES (?,?,1,1,1,'digest','correction',?,?,'operator:fixture')`, version, signature, string(profile), canonicalTime(now)); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(context.Background(), `INSERT INTO semantic_profile_heads(signature_key,current_version,version_id,updated_at) VALUES (?,1,?,?)`, signature, version, canonicalTime(now)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return ids
}

func guidanceWriter(t *testing.T, st *Store) *sql.DB {
	t.Helper()
	var seq int
	var name, path string
	if err := st.db.QueryRowContext(context.Background(), `PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type guidanceObserver struct {
	next   func()
	closed func()
	once   sync.Once
}

func observeGuidance(t *testing.T, st *Store, observer *guidanceObserver) {
	t.Helper()
	var seq int
	var name, path string
	if err := st.db.QueryRowContext(context.Background(), `PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if err := st.db.Close(); err != nil {
		t.Fatal(err)
	}
	driverName := "guidance-observer-" + uuid.NewString()
	sql.Register(driverName, guidanceDriver{observer: observer})
	db, err := sql.Open(driverName, buildDSN(path))
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	st.db = db
}

type guidanceDriver struct{ observer *guidanceObserver }

func (d guidanceDriver) Open(dsn string) (driver.Conn, error) {
	c, err := (&sqlite.Driver{}).Open(dsn)
	if err != nil {
		return nil, err
	}
	return &guidanceConn{Conn: c, observer: d.observer}, nil
}

type guidanceConn struct {
	driver.Conn

	observer *guidanceObserver
}

func (c *guidanceConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	querier, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	rows, err := querier.QueryContext(ctx, query, args)
	if err != nil {
		return nil, err
	}
	return &guidanceRows{Rows: rows, observer: c.observer}, nil
}

func (c *guidanceConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	execer, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return execer.ExecContext(ctx, query, args)
}

func (c *guidanceConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	beginner, ok := c.Conn.(driver.ConnBeginTx)
	if !ok {
		return nil, errors.New("guidance observer requires context-aware transactions")
	}
	return beginner.BeginTx(ctx, opts)
}

func (c *guidanceConn) Ping(ctx context.Context) error {
	pinger, ok := c.Conn.(driver.Pinger)
	if !ok {
		return errors.New("guidance observer requires database pings")
	}
	return pinger.Ping(ctx)
}

func (c *guidanceConn) ResetSession(ctx context.Context) error {
	if resetter, ok := c.Conn.(driver.SessionResetter); ok {
		return resetter.ResetSession(ctx)
	}
	return nil
}

func (c *guidanceConn) IsValid() bool {
	if validator, ok := c.Conn.(driver.Validator); ok {
		return validator.IsValid()
	}
	return true
}

type guidanceRows struct {
	driver.Rows

	observer *guidanceObserver
}

func (r *guidanceRows) Next(dest []driver.Value) error {
	err := r.Rows.Next(dest)
	if err == nil && r.observer.next != nil {
		r.observer.next()
	}
	return err
}

func (r *guidanceRows) Close() error {
	err := r.Rows.Close()
	if r.observer.closed != nil {
		r.observer.once.Do(r.observer.closed)
	}
	return err
}
