// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
)

func TestPprofDisabledByDefaultStartsNothing(t *testing.T) {
	addr, stop, err := startPprof(context.Background(), "", slog.New(slog.DiscardHandler))
	if err != nil || addr != "" || stop == nil {
		t.Fatalf("startPprof(\"\") = %q, stop nil %v, %v; want no listener and a no-op stop", addr, stop == nil, err)
	}
	stop()
}

func TestPprofServesProfilesOnItsOwnListener(t *testing.T) {
	addr, stop, err := startPprof(context.Background(), "127.0.0.1:0", slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	defer stop()

	get := func(path string) (int, string) {
		t.Helper()
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(body)
	}
	if code, body := get("/debug/pprof/heap?debug=1"); code != http.StatusOK || !strings.Contains(body, "heap profile") {
		t.Fatalf("heap profile: status %d, body %.80q", code, body)
	}
	if code, _ := get("/debug/pprof/profile?seconds=1"); code != http.StatusOK {
		t.Fatalf("CPU profile: status %d", code)
	}
	// The command line can carry arguments an operator never meant to share.
	if code, _ := get("/debug/pprof/cmdline"); code == http.StatusOK {
		t.Fatal("/debug/pprof/cmdline is served; it must not be")
	}
}
