package logging

import (
	"bytes"
	"encoding/json"
	"strings"
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

func TestNew_TextHandlerEmitsTextOutput(t *testing.T) {
	var buf bytes.Buffer
	logger, err := New(Options{Format: FormatText, Writer: &buf})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	logger.Info("hello")
	if !strings.Contains(buf.String(), "msg=hello") {
		t.Errorf("text output missing msg=hello: %q", buf.String())
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
