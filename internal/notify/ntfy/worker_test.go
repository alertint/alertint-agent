// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type testQueue struct {
	claims          []Claim
	outcome, reason string
	retry           time.Time
}

func (q *testQueue) ClaimNTFY(context.Context, string, time.Time, time.Duration) ([]Claim, error) {
	claims := q.claims
	q.claims = nil
	return claims, nil
}
func (q *testQueue) FinishNTFY(_ context.Context, _ Claim, status, reason string, retry, _ time.Time) error {
	q.outcome = status
	q.reason = reason
	q.retry = retry
	return nil
}

func TestWorkerRecordsRealHTTPOutcomes(t *testing.T) {
	for _, code := range []int{200, 401, 429, 503} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Header().Set("Retry-After", "60"); w.WriteHeader(code) }))
			defer srv.Close()
			now := time.Now().UTC()
			q := &testQueue{claims: []Claim{{ID: "n", Destination: srv.URL, Message: Message{ID: "n", Title: "test", Body: "test", Priority: 3}, Attempts: 1}}}
			w := NewWorker(q, NewClient(""), "worker", nil, nil)
			if err := w.Round(context.Background(), now); err != nil {
				t.Fatal(err)
			}
			want := "pending"
			if code == 200 {
				want = "delivered"
			}
			if code == 401 {
				want = "blocked"
			}
			if q.outcome != want {
				t.Fatalf("outcome %s, want %s", q.outcome, want)
			}
			if code == 429 && q.retry.Before(now.Add(time.Minute)) {
				t.Fatal("rate limit ignored")
			}
		})
	}
}

func TestRetryAfterStartsAtResponseCompletion(t *testing.T) {
	completed := make(chan time.Time, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		completed <- time.Now().UTC()
		w.Header().Set("Retry-After", "60")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	q := &testQueue{claims: []Claim{{Destination: srv.URL, Message: Message{Title: "test"}, Attempts: 1}}}
	w := NewWorker(q, NewClient(""), "worker", nil, nil)
	if err := w.Round(context.Background(), time.Now().Add(-2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	responseAt := <-completed
	if q.retry.Before(responseAt.Add(time.Minute)) {
		t.Fatalf("retry %s precedes response delay %s", q.retry, responseAt.Add(time.Minute))
	}
}
