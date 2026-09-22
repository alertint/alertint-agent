// SPDX-License-Identifier: FSL-1.1-ALv2

package ingress

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alertint/alertint-agent/internal/audit"
	"github.com/alertint/alertint-agent/internal/correlator"
	"github.com/alertint/alertint-agent/internal/situation"
	"github.com/alertint/alertint-agent/internal/store"
)

// The production server's write timeout is 10 seconds. Keep the automated
// ceiling below it while allowing for the heavy scheduler contention of the
// repository-wide race suite; dedicated acceptance runs record the actual
// percentile latencies, which should remain far below this guard.
const deliveryAcceptanceAckLimit = 8 * time.Second

type deliveryAttemptResult struct {
	status  int
	latency time.Duration
	err     error
}

func deliveryAcceptancePayload(batch, members int, at time.Time) AlertmanagerPayload {
	group := fmt.Sprintf("load-%03d", batch)
	p := AlertmanagerPayload{
		Version:     "4",
		GroupKey:    fmt.Sprintf(`{}:{service=%q}`, group),
		Status:      "firing",
		Receiver:    "alertint-load-acceptance",
		GroupLabels: map[string]string{"service": group},
		Alerts:      make([]AlertmanagerAlert, 0, members),
	}
	for member := 0; member < members; member++ {
		p.Alerts = append(p.Alerts, AlertmanagerAlert{
			Status: "firing",
			Labels: map[string]string{
				"alertname": "DeliveryAcceptance",
				"service":   group,
			},
			Annotations: map[string]string{"summary": "delivery acceptance load fixture"},
			StartsAt:    at,
			Fingerprint: fmt.Sprintf("load-%03d-%03d", batch, member),
		})
	}
	return p
}

func runDeliveryAttempts(ctx context.Context, client *http.Client, url string, bodies [][]byte, concurrency int) []deliveryAttemptResult {
	results := make([]deliveryAttemptResult, len(bodies))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, body := range bodies {
		wg.Add(1)
		go func(i int, body []byte) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/webhook/alertmanager", bytes.NewReader(body))
			if err != nil {
				results[i].err = err
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+testToken)
			started := time.Now()
			resp, err := client.Do(req)
			results[i].latency = time.Since(started)
			if err != nil {
				results[i].err = err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			results[i].status = resp.StatusCode
		}(i, body)
	}
	wg.Wait()
	return results
}

func requireAcceptedAttempts(t *testing.T, label string, results []deliveryAttemptResult) []time.Duration {
	t.Helper()
	latencies := make([]time.Duration, 0, len(results))
	for i, result := range results {
		if result.err != nil || result.status != http.StatusNoContent {
			t.Fatalf("%s attempt %d = status %d, err %v; want 204", label, i, result.status, result.err)
		}
		if result.latency >= deliveryAcceptanceAckLimit {
			t.Fatalf("%s attempt %d acknowledgement = %s, want below %s", label, i, result.latency, deliveryAcceptanceAckLimit)
		}
		latencies = append(latencies, result.latency)
	}
	return latencies
}

func percentileDuration(values []time.Duration, percentile float64) time.Duration {
	if len(values) == 0 {
		return 0
	}
	ordered := append([]time.Duration(nil), values...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	index := int(float64(len(ordered)-1) * percentile)
	return ordered[index]
}

func loadCount(t *testing.T, st *store.Store, query string) int {
	t.Helper()
	var count int
	if err := st.DB().QueryRowContext(context.Background(), query).Scan(&count); err != nil {
		t.Fatalf("count load acceptance rows: %v", err)
	}
	return count
}

func waitForLoadCount(t *testing.T, st *store.Store, query string, want int) {
	t.Helper()
	// Full-repository race runs can starve the background workers while many
	// other test binaries are runnable. This is a convergence assertion, not an
	// acknowledgement-latency bound, so allow the workers time to catch up.
	deadline := time.Now().Add(30 * time.Second)
	for {
		if got := loadCount(t, st, query); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for count %d from %q", want, query)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestDeliveryAcceptanceCompressedBurstAndDrain is the repeatable issue #99
// load gate. It compresses the reported 250-alert hourly cardinality into a
// short run, deliberately leaves downstream correlation stopped during
// intake, retries every base batch concurrently, then restarts on the same
// file and drains every accepted delivery.
func TestDeliveryAcceptanceCompressedBurstAndDrain(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "delivery-load.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open load store: %v", err)
	}

	quietLogger := slog.New(slog.DiscardHandler)
	host, err := New(Options{
		Store:     st,
		Auditor:   audit.New(st.DB()),
		Receivers: []Receiver{NewAlertReceiver(st, testToken, nil, quietLogger)},
		Logger:    quietLogger,
	})
	if err != nil {
		t.Fatalf("new load host: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(func() {
		srv.Close()
		_ = st.Close()
	})

	base := time.Date(2026, 9, 22, 18, 0, 0, 0, time.UTC)
	const baseBatches = 25
	const membersPerBaseBatch = 10
	baseBodies := make([][]byte, 0, baseBatches*2)
	for batch := 0; batch < baseBatches; batch++ {
		body := mustMarshal(t, deliveryAcceptancePayload(batch, membersPerBaseBatch, base))
		baseBodies = append(baseBodies, body, body)
	}

	allLatencies := requireAcceptedAttempts(t, "250-alert burst with concurrent retries",
		runDeliveryAttempts(ctx, srv.Client(), srv.URL, baseBodies, 8))
	uniqueAlerts := baseBatches * membersPerBaseBatch
	attempts := len(baseBodies)

	nextBatch := baseBatches
	for _, concurrency := range []int{1, 4, 8, 16} {
		bodies := make([][]byte, 0, concurrency)
		for i := 0; i < concurrency; i++ {
			bodies = append(bodies, mustMarshal(t, deliveryAcceptancePayload(nextBatch, 3, base)))
			nextBatch++
		}
		label := fmt.Sprintf("stress concurrency %d", concurrency)
		latencies := requireAcceptedAttempts(t, label, runDeliveryAttempts(ctx, srv.Client(), srv.URL, bodies, concurrency))
		allLatencies = append(allLatencies, latencies...)
		uniqueAlerts += len(bodies) * 3
		attempts += len(bodies)
		t.Logf("%s: attempts=%d p50=%s p95=%s max=%s", label, len(bodies),
			percentileDuration(latencies, 0.50), percentileDuration(latencies, 0.95), percentileDuration(latencies, 1.0))
	}

	if got := loadCount(t, st, `SELECT COUNT(*) FROM alert_deliveries`); got != uniqueAlerts {
		t.Fatalf("durable deliveries = %d, want %d unique accepted alerts", got, uniqueAlerts)
	}
	if got := loadCount(t, st, `SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status = 'pending'`); got != uniqueAlerts {
		t.Fatalf("pending backlog = %d, want %d while downstream is stopped", got, uniqueAlerts)
	}
	waitForLoadCount(t, st, `SELECT COUNT(*) FROM audit_log WHERE kind = 'alert.received'`, attempts)

	t.Logf("intake: attempts=%d unique_alerts=%d p50=%s p95=%s p99=%s max=%s",
		attempts, uniqueAlerts,
		percentileDuration(allLatencies, 0.50), percentileDuration(allLatencies, 0.95),
		percentileDuration(allLatencies, 0.99), percentileDuration(allLatencies, 1.0))

	// Abrupt-stop shape: no downstream worker was started, so every accepted
	// delivery is pending when the process resources close.
	srv.Close()
	if err := st.Close(); err != nil {
		t.Fatalf("close before restart: %v", err)
	}

	reopened, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("reopen after intake: %v", err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if got := loadCount(t, reopened, `SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status = 'pending'`); got != uniqueAlerts {
		t.Fatalf("pending backlog after restart = %d, want %d", got, uniqueAlerts)
	}

	drainStarted := time.Now()
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, reopened, nil, quietLogger)
	dispatch := correlator.NewDispatchWorker(reopened, cor, correlator.WorkerConfig{Owner: "issue-99:dispatch"}, nil)
	dispatched, err := dispatch.Drain(ctx)
	if err != nil {
		t.Fatalf("drain delivery backlog: %v", err)
	}
	inputs := situation.NewInputWorker(reopened, situation.WorkerConfig{Owner: "issue-99:input"}, nil)
	applied, err := inputs.Drain(ctx)
	if err != nil {
		t.Fatalf("drain Situation inputs: %v", err)
	}
	if got := loadCount(t, reopened, `SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status != 'applied'`); got != 0 {
		t.Fatalf("undrained delivery dispatches = %d, want 0", got)
	}
	if got := loadCount(t, reopened, `SELECT COUNT(*) FROM situation_input_outbox WHERE status != 'applied'`); got != 0 {
		t.Fatalf("undrained Situation inputs = %d, want 0", got)
	}
	if dispatched != uniqueAlerts || applied != uniqueAlerts {
		t.Fatalf("drain handled dispatches=%d inputs=%d, want %d each", dispatched, applied, uniqueAlerts)
	}
	t.Logf("drain: deliveries=%d situation_inputs=%d elapsed=%s situations=%d",
		dispatched, applied, time.Since(drainStarted), loadCount(t, reopened, `SELECT COUNT(*) FROM situations`))
}

// TestDeliveryAcceptanceWithLiveWorkers covers the contention shape from
// issue #99: webhook intake shares one SQLite connection with the real
// dispatch and Situation input workers while they actively drain accepted
// deliveries. Slow analysis is downstream of this durable handoff and is not
// started here.
func TestDeliveryAcceptanceWithLiveWorkers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	dbPath := filepath.Join(t.TempDir(), "live-workers.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open live-worker store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	quietLogger := slog.New(slog.DiscardHandler)
	cor := correlator.New(correlator.Config{WindowSeconds: 60}, st, nil, quietLogger)
	inputs := situation.NewInputWorker(st, situation.WorkerConfig{
		Owner:    "issue-99:live-input",
		Interval: 5 * time.Millisecond,
	}, quietLogger)
	dispatch := correlator.NewDispatchWorker(st, cor, correlator.WorkerConfig{
		Owner:    "issue-99:live-dispatch",
		Interval: 5 * time.Millisecond,
	}, quietLogger)
	inputs.Start(ctx)
	dispatch.Start(ctx)
	t.Cleanup(func() {
		cancel()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer stopCancel()
		if err := dispatch.Stop(stopCtx); err != nil {
			t.Errorf("stop live dispatch worker: %v", err)
		}
		if err := inputs.Stop(stopCtx); err != nil {
			t.Errorf("stop live input worker: %v", err)
		}
	})

	host, err := New(Options{
		Store:     st,
		Auditor:   audit.New(st.DB()),
		Receivers: []Receiver{NewAlertReceiver(st, testToken, dispatch.Wake, quietLogger)},
		Logger:    quietLogger,
	})
	if err != nil {
		t.Fatalf("new live-worker host: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(srv.Close)

	const attempts = 50
	bodies := make([][]byte, 0, attempts)
	base := time.Date(2026, 9, 22, 19, 30, 0, 0, time.UTC)
	for batch := 0; batch < attempts; batch++ {
		bodies = append(bodies, mustMarshal(t, deliveryAcceptancePayload(1000+batch, 1, base)))
	}
	latencies := requireAcceptedAttempts(t, "live downstream workers",
		runDeliveryAttempts(ctx, srv.Client(), srv.URL, bodies, 8))

	waitForLoadCount(t, st, `SELECT COUNT(*) FROM audit_log WHERE kind = 'alert.received'`, attempts)
	waitForLoadCount(t, st, `SELECT COUNT(*) FROM alert_delivery_dispatches WHERE status != 'applied'`, 0)
	waitForLoadCount(t, st, `SELECT COUNT(*) FROM situation_input_outbox`, attempts)
	waitForLoadCount(t, st, `SELECT COUNT(*) FROM situation_input_outbox WHERE status != 'applied'`, 0)
	if got := loadCount(t, st, `SELECT COUNT(*) FROM alert_deliveries`); got != attempts {
		t.Fatalf("durable deliveries = %d, want %d", got, attempts)
	}

	t.Logf("live workers: attempts=%d p50=%s p95=%s p99=%s max=%s",
		attempts, percentileDuration(latencies, 0.50), percentileDuration(latencies, 0.95),
		percentileDuration(latencies, 0.99), percentileDuration(latencies, 1.0))
}

// TestDeliveryAcceptanceDisconnectAfterCommitIsRetrySafe cancels the client
// at the exact post-commit wake boundary. Whether the client observed 204 is
// deliberately irrelevant; the committed batch survives, and replay is a
// successful no-op.
func TestDeliveryAcceptanceDisconnectAfterCommitIsRetrySafe(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "disconnect.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open disconnect store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	committed := make(chan struct{})
	release := make(chan struct{})
	var first atomic.Bool
	wake := func() {
		if first.CompareAndSwap(false, true) {
			close(committed)
			<-release
		}
	}
	host, err := New(Options{
		Store:     st,
		Auditor:   audit.New(st.DB()),
		Receivers: []Receiver{NewAlertReceiver(st, testToken, wake, slog.New(slog.DiscardHandler))},
	})
	if err != nil {
		t.Fatalf("new disconnect host: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(srv.Close)

	payload := deliveryAcceptancePayload(900, 4, time.Date(2026, 9, 22, 19, 0, 0, 0, time.UTC))
	body := mustMarshal(t, payload)
	requestCtx, cancel := context.WithCancel(ctx)
	uncertain := make(chan deliveryAttemptResult, 1)
	go func() {
		uncertain <- runDeliveryAttempts(requestCtx, srv.Client(), srv.URL, [][]byte{body}, 1)[0]
	}()
	select {
	case <-committed:
	case <-time.After(2 * time.Second):
		t.Fatal("delivery did not reach the durable commit boundary")
	}
	cancel()
	close(release)
	<-uncertain

	if got := loadCount(t, st, `SELECT COUNT(*) FROM alert_deliveries`); got != 4 {
		t.Fatalf("deliveries after disconnect = %d, want 4", got)
	}
	retry := requireAcceptedAttempts(t, "retry after uncertain response",
		runDeliveryAttempts(ctx, srv.Client(), srv.URL, [][]byte{body}, 1))
	if len(retry) != 1 {
		t.Fatalf("retry results = %d, want 1", len(retry))
	}
	if got := loadCount(t, st, `SELECT COUNT(*) FROM alert_deliveries`); got != 4 {
		t.Fatalf("deliveries after retry = %d, want 4 without duplicates", got)
	}
}

// TestDeliveryAcceptanceStorageContentionReturnsBounded503 holds SQLite's
// writer lock through an independent connection. The real receiver must ask
// a connected sender to retry before the server's 10-second write deadline.
func TestDeliveryAcceptanceStorageContentionReturnsBounded503(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "contention.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open contention store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	blocker, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open contention blocker: %v", err)
	}
	t.Cleanup(func() { _ = blocker.Close() })

	tx, err := blocker.DB().BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin blocking transaction: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO audit_log (ts, actor, kind, payload_json, prev_hash, hash)
		VALUES ('2026-09-22T00:00:00Z', 'test', 'lock', '{}', NULL, 'lock')`); err != nil {
		_ = tx.Rollback()
		t.Fatalf("acquire SQLite writer lock: %v", err)
	}

	host, err := New(Options{
		Store:     st,
		Auditor:   audit.New(st.DB()),
		Receivers: []Receiver{NewAlertReceiver(st, testToken, nil, slog.New(slog.DiscardHandler))},
	})
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("new contention host: %v", err)
	}
	srv := httptest.NewServer(host.Handler())
	t.Cleanup(srv.Close)

	body := mustMarshal(t, deliveryAcceptancePayload(950, 2, time.Date(2026, 9, 22, 20, 0, 0, 0, time.UTC)))
	result := runDeliveryAttempts(ctx, srv.Client(), srv.URL, [][]byte{body}, 1)[0]
	if err := tx.Rollback(); err != nil {
		t.Fatalf("release SQLite writer lock: %v", err)
	}
	if result.err != nil || result.status != http.StatusServiceUnavailable {
		t.Fatalf("contention response = status %d, err %v; want 503", result.status, result.err)
	}
	if result.latency >= 8*time.Second {
		t.Fatalf("contention response took %s, want a retryable response before the 10s write deadline", result.latency)
	}
	if got := loadCount(t, st, `SELECT COUNT(*) FROM alert_deliveries`); got != 0 {
		t.Fatalf("contention persisted %d partial deliveries, want 0", got)
	}
	t.Logf("storage contention: status=503 latency=%s", result.latency)
}
