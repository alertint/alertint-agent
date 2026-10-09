// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestNTFYRuntimeRequiresConfiguredSecret(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "agent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	cfg := config.Defaults()
	cfg.Notify.NTFY.Enabled = true
	cfg.Notify.NTFY.Topic = "lab"
	cfg.Notify.NTFY.TokenEnv = "NTFY_TEST_MISSING_TOKEN"
	t.Setenv("NTFY_TEST_MISSING_TOKEN", "")
	if _, err := buildNTFYRuntime(context.Background(), &cfg, st, nil, "worker", nil); err == nil {
		t.Fatal("missing token accepted")
	}
	t.Setenv("NTFY_TEST_MISSING_TOKEN", "test")
	w, err := buildNTFYRuntime(context.Background(), &cfg, st, nil, "worker", nil)
	if err != nil || w == nil {
		t.Fatalf("build: %v", err)
	}
	cfg.Notify.NTFY.Enabled = false
	w, err = buildNTFYRuntime(context.Background(), &cfg, st, nil, "worker", nil)
	if err != nil || w != nil {
		t.Fatalf("disabled runtime %v %v", w, err)
	}
}
