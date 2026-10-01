// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestQueryInstantWithAnnotations(t *testing.T) {
	const data = `{"resultType":"vector","result":[]}`
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/api/v1/query" || r.URL.Query().Get("query") != "rate(x[5m])" || r.URL.Query().Get("limit") != "7" || r.URL.Query().Get("time") == "" || r.Header.Get("Authorization") != "Bearer test" || r.Header.Get("X-Scope-OrgID") != "tenant" {
			t.Errorf("unexpected request: %v %v", r.URL, r.Header)
		}
		_, _ = w.Write([]byte(`{"status":"success","data":` + data + `,"warnings":["partial data"],"infos":["metric might not be a counter"]}`))
	}))
	defer srv.Close()
	c := NewClient(Config{BaseURL: srv.URL, BearerToken: "test", OrgID: "tenant"})
	result, err := c.QueryInstantWithAnnotations(context.Background(), "rate(x[5m])", time.Now(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || string(result.Data) != data || !reflect.DeepEqual(result.Warnings, []string{"partial data"}) || !reflect.DeepEqual(result.Infos, []string{"metric might not be a counter"}) {
		t.Fatalf("calls=%d result=%+v", calls, result)
	}
	raw, err := c.QueryInstant(context.Background(), "rate(x[5m])", time.Now(), 7)
	if err != nil || string(raw) != data || calls != 2 {
		t.Fatalf("legacy result=%s calls=%d err=%v", raw, calls, err)
	}
}
