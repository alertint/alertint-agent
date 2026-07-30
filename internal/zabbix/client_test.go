// SPDX-License-Identifier: FSL-1.1-ALv2
package zabbix_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/alertint/alertint-agent/internal/zabbix"
)

func TestAPIVersion_SendsNoAuthAndUnwrapsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ct := r.Header.Get("Content-Type"); ct != "application/json-rpc" {
			t.Errorf("content-type: got %q", ct)
		}
		if auth := r.Header.Get("Authorization"); auth != "" {
			t.Errorf("apiinfo.version must not send auth, got %q", auth)
		}
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":"7.0.0","id":1}`))
	}))
	defer srv.Close()
	c := zabbix.NewClient(zabbix.Config{BaseURL: srv.URL, APIToken: "tok"})
	v, err := c.APIVersion(context.Background())
	if err != nil || v != "7.0.0" {
		t.Fatalf("got (%q,%v) want (7.0.0,nil)", v, err)
	}
}
