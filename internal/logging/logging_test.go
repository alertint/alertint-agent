// SPDX-License-Identifier: FSL-1.1-ALv2

package logging

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
)

func TestNew_JSONHandlerEmitsStructuredOutput(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(Options{Level: "info", Format: FormatJSON, Writer: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info("hello", "k", "v")

	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output is not valid JSON: %v\nraw: %s", err, buf.String())
	}
	if got["msg"] != "hello" {
		t.Errorf("msg = %v, want %q", got["msg"], "hello")
	}
	if got["k"] != "v" {
		t.Errorf("k = %v, want %q", got["k"], "v")
	}
}

func TestNew_RejectsTextFormat(t *testing.T) {
	// "text" was removed (no alias): a loud error beats silently re-rendering
	// raw key=value output as console and breaking a parser.
	if _, err := New(Options{Format: Format("text")}); err == nil {
		t.Fatal("expected error for removed 'text' format")
	}
}

func TestResolve_AutoOffTTY(t *testing.T) {
	var buf bytes.Buffer
	if got := Resolve(FormatAuto, &buf, func(io.Writer) bool { return true }); got != FormatConsole {
		t.Errorf("auto on TTY = %q, want console", got)
	}
	if got := Resolve(FormatAuto, &buf, func(io.Writer) bool { return false }); got != FormatJSON {
		t.Errorf("auto on non-TTY = %q, want json", got)
	}
	// Concrete formats pass through unchanged regardless of TTY-ness.
	if got := Resolve(FormatConsole, &buf, func(io.Writer) bool { return false }); got != FormatConsole {
		t.Errorf("console passthrough = %q, want console", got)
	}
	if got := Resolve(FormatJSON, &buf, func(io.Writer) bool { return true }); got != FormatJSON {
		t.Errorf("json passthrough = %q, want json", got)
	}
}

func TestNew_LevelFiltersDebug(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(Options{Level: "info", Format: FormatJSON, Writer: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Debug("should not appear")
	if buf.Len() != 0 {
		t.Errorf("debug message leaked at info level: %q", buf.String())
	}
}

func TestNew_RejectsUnknownLevel(t *testing.T) {
	if _, err := New(Options{Level: "loud"}); err == nil {
		t.Fatal("expected error for unknown level")
	}
}

func TestNew_RejectsUnknownFormat(t *testing.T) {
	if _, err := New(Options{Format: Format("yaml")}); err == nil {
		t.Fatal("expected error for unknown format")
	}
}
