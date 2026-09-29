// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/alertint/alertint-agent/internal/config"
	"github.com/alertint/alertint-agent/internal/store"
)

func TestConfiguredSlackAPIBaseURLRoutesSituationAndSystemCalls(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/auth.test":
			_, _ = io.WriteString(w, `{"ok":true,"user_id":"U-test"}`)
		case "/chat.postMessage":
			_, _ = io.WriteString(w, `{"ok":true,"channel":"C-test","ts":"1.1"}`)
		default:
			t.Errorf("unexpected Slack path %s", r.URL.Path)
			_, _ = io.WriteString(w, `{"ok":false,"error":"unknown_method"}`)
		}
	}))
	defer srv.Close()
	t.Setenv("SLACK_BOT_TOKEN_TEST", "xoxb-mock-only")
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := fmt.Sprintf(`
receivers:
  address: ":9911"
alertmanager:
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN
storage:
  sqlite_path: %q
llm:
  provider: anthropic
  api_key_env: ANTHROPIC_API_KEY
  model: claude-haiku-4-5-20251001
correlator:
  window_seconds: 90
  min_alerts: 1
notify:
  stdout: true
  slack:
    enabled: true
    bot_token_env: SLACK_BOT_TOKEN_TEST
    channel: C-test
    api_base_url: %q
`, filepath.Join(t.TempDir(), "agent.db"), srv.URL)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = st.Close() }()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	probe, worker := buildSituationSlackWorker(cfg, st, "test", nil, logger)
	if probe == nil || worker == nil {
		t.Fatal("Situation Slack worker was not built")
	}
	if err := probe.Probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, publisher := buildNotifier(cfg, st, nil, logger, false)
	if publisher == nil {
		t.Fatal("system publisher was not built")
	}
	if _, _, err := publisher.PostSystemMessage(context.Background(), "mock only"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "/auth.test" || paths[1] != "/chat.postMessage" {
		t.Fatalf("Slack calls went to %v, want mock auth and post", paths)
	}
}
