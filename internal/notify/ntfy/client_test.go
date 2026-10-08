// SPDX-License-Identifier: FSL-1.1-ALv2

package ntfy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientAuthenticationAndFailureClassification(t *testing.T) {
	status := 200
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lab" || r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Markdown") != "yes" {
			t.Errorf("bad request: %s %v", r.URL.Path, r.Header)
		}
		w.Header().Set("Retry-After", "20")
		w.WriteHeader(status)
	}))
	defer srv.Close()
	c := NewClient("secret")
	if err := c.Send(context.Background(), srv.URL+"/lab", Message{ID: "n-1", Title: "Test", Body: "test", Priority: 4}); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{401, 403, 429, 500} {
		status = code
		err := c.Send(context.Background(), srv.URL+"/lab", Message{Title: "Test", Body: "test"})
		var failure *DeliveryError
		if !errors.As(err, &failure) || failure.Blocked != (code == 401 || code == 403) {
			t.Fatalf("code %d: %v", code, err)
		}
		if code == 429 && failure.RetryAfter != 20*time.Second {
			t.Fatal("Retry-After not honored")
		}
	}
}
