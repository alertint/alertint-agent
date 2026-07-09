// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// validYAML uses a pod-destined sqlite path that does not exist on the test
// machine: the offline validation must not care (the R10 headline case).
const validYAML = `
receivers:
  address: ":9911"
alertmanager:
  webhook_token_env: ALERTINT_WEBHOOK_TOKEN
storage:
  sqlite_path: /data/alertint.db
llm:
  provider: anthropic
  api_key_env: ANTHROPIC_API_KEY
  model: claude-sonnet-5
correlator:
  window_seconds: 90
  min_alerts: 1
  group_labels: ["cluster", "namespace", "service"]
`

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

func TestRunValidate_ValidConfig(t *testing.T) {
	path := writeTempConfig(t, validYAML)
	for _, args := range [][]string{
		{"validate", path},
		{"validate", "--config", path},
	} {
		var stdout, stderr bytes.Buffer
		if err := run(args, &stdout, &stderr); err != nil {
			t.Fatalf("run(%v) = %v, want nil", args, err)
		}
		if !strings.Contains(stdout.String(), path) || !strings.Contains(stdout.String(), "is valid") {
			t.Fatalf("stdout = %q, want confirmation naming %s", stdout.String(), path)
		}
	}
}

func TestRunValidate_PrintsVolatileLabelWarning(t *testing.T) {
	body := strings.Replace(validYAML,
		`group_labels: ["cluster", "namespace", "service"]`,
		`group_labels: ["cluster", "namespace", "pod"]`, 1)
	path := writeTempConfig(t, body)
	var stdout, stderr bytes.Buffer
	if err := run([]string{"validate", path}, &stdout, &stderr); err != nil {
		t.Fatalf("run = %v, want nil (a volatile label warns, not fails)", err)
	}
	out := stdout.String()
	if !strings.Contains(out, "warning:") || !strings.Contains(out, "pod") || !strings.Contains(out, "rarely match") {
		t.Fatalf("stdout = %q, want a volatile-label warning naming pod and the consequence", out)
	}
	if !strings.Contains(out, "is valid") {
		t.Fatalf("stdout = %q, want the config still reported valid", out)
	}
}

func TestRunValidate_UnknownKeyRejected(t *testing.T) {
	path := writeTempConfig(t, validYAML+"\nbogus_key: true\n")
	var stdout, stderr bytes.Buffer
	err := run([]string{"validate", path}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "bogus_key") {
		t.Fatalf("run = %v, want parse error naming bogus_key", err)
	}
}

func TestRunValidate_AggregatesValidationErrors(t *testing.T) {
	body := strings.Replace(validYAML, "window_seconds: 90", "window_seconds: 0", 1) + "\nlog_level: bogus\n"
	path := writeTempConfig(t, body)
	var stdout, stderr bytes.Buffer
	err := run([]string{"validate", path}, &stdout, &stderr)
	if err == nil {
		t.Fatal("run = nil, want validation error")
	}
	for _, want := range []string{"window_seconds", "log_level"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q (errors must aggregate, not stop at first)", err.Error(), want)
		}
	}
}

func TestRunValidate_UsageErrors(t *testing.T) {
	t.Run("missing path", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run([]string{"validate"}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "config path required") {
			t.Fatalf("run = %v, want config-path-required error", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		var stdout, stderr bytes.Buffer
		err := run([]string{"validate", filepath.Join(t.TempDir(), "nope.yaml")}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "open") {
			t.Fatalf("run = %v, want open error", err)
		}
	})

	t.Run("extra arguments", func(t *testing.T) {
		path := writeTempConfig(t, validYAML)
		var stdout, stderr bytes.Buffer
		err := run([]string{"validate", path, "extra"}, &stdout, &stderr)
		if err == nil || !strings.Contains(err.Error(), "unexpected extra arguments") {
			t.Fatalf("run = %v, want extra-arguments error", err)
		}
	})
}
