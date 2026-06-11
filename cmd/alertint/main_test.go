// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_VersionFlagPrintsVersionAndExitsCleanly(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := run([]string{"--version"}, &stdout, &stderr); err != nil {
		t.Fatalf("run --version: %v (stderr=%q)", err, stderr.String())
	}
	got := strings.TrimSpace(stdout.String())
	if got == "" {
		t.Fatal("--version produced empty output")
	}
}

func TestRun_RejectsUnknownLogLevel(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--log-level", "loud"}, &stdout, &stderr)
	if err == nil {
		t.Fatal("expected error for unknown log level")
	}
}
