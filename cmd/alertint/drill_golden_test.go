// SPDX-License-Identifier: FSL-1.1-ALv2

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDrillGoldenStub(t *testing.T) {
	var stderr bytes.Buffer
	if err := runDrillGolden(nil, &bytes.Buffer{}, &stderr); err != nil {
		t.Fatalf("runDrillGolden: %v", err)
	}
	if stderr.Len() == 0 {
		t.Fatal("expected stderr output from stub")
	}
}

func TestDrillGolden_EndToEnd(t *testing.T) {
	// Locate the config example and the storm scenario.
	cfgPath := findConfigExample(t)
	scenarioPath := filepath.Join("..", "..", "internal", "triage", "testdata", "scenarios", "storm-collapse.yaml")
	responsesPath := filepath.Join("..", "..", "internal", "triage", "testdata", "scenarios", "storm-collapse.responses.json")
	outPath := filepath.Join(t.TempDir(), "storm-collapse.json")

	var stdout, stderr bytes.Buffer
	args := []string{
		"--config=" + cfgPath,
		"--scenario=" + scenarioPath,
		"--responses=" + responsesPath,
		"--out=" + outPath,
	}
	if err := runDrillGolden(args, &stdout, &stderr); err != nil {
		t.Fatalf("runDrillGolden: %v\nstderr: %s", err, stderr.String())
	}

	// Verify the golden was written and is valid JSON.
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	if len(b) == 0 {
		t.Fatal("golden file is empty")
	}
	if !bytes.Contains(b, []byte("storm-collapse")) {
		t.Fatalf("golden missing scenario id: %s", b)
	}
}

func findConfigExample(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"config.example.yaml",
		"../../config.example.yaml",
		"../../../config.example.yaml",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("config.example.yaml not found")
	return ""
}
