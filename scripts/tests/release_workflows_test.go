package tests

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func loadWorkflow(t *testing.T, name string) map[string]any {
	t.Helper()

	path := filepath.Join("..", "..", ".github", "workflows", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var workflow map[string]any
	if err := yaml.Unmarshal(data, &workflow); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return workflow
}

func object(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want mapping", path, value)
	}
	return result
}

func list(t *testing.T, value any, path string) []any {
	t.Helper()
	result, ok := value.([]any)
	if !ok {
		t.Fatalf("%s is %T, want sequence", path, value)
	}
	return result
}

func scalar(t *testing.T, value any, path string) string {
	t.Helper()
	result, ok := value.(string)
	if !ok {
		t.Fatalf("%s is %T, want string", path, value)
	}
	return result
}

func TestChartReleaseWorkflowPublishesDirectAndCalledReleases(t *testing.T) {
	workflow := loadWorkflow(t, "chart-release.yml")
	on := object(t, workflow["on"], "on")
	push := object(t, on["push"], "on.push")
	tags := list(t, push["tags"], "on.push.tags")
	if len(tags) != 1 || scalar(t, tags[0], "on.push.tags[0]") != "chart-v*" {
		t.Fatalf("on.push.tags = %#v, want [chart-v*]", tags)
	}
	if _, ok := on["workflow_call"]; !ok {
		t.Fatal("on.workflow_call is missing; app releases cannot reuse chart publication")
	}

	permissions := object(t, workflow["permissions"], "permissions")
	if got := scalar(t, permissions["packages"], "permissions.packages"); got != "write" {
		t.Fatalf("permissions.packages = %q, want write", got)
	}

	jobs := object(t, workflow["jobs"], "jobs")
	publish := object(t, jobs["publish"], "jobs.publish")
	steps := list(t, publish["steps"], "jobs.publish.steps")
	var commands strings.Builder
	for _, raw := range steps {
		step := object(t, raw, "jobs.publish.steps")
		if run, ok := step["run"].(string); ok {
			commands.WriteString(run)
			commands.WriteByte('\n')
		}
	}

	wantCommands := []string{
		"chart-release-validate.sh",
		"helm lint",
		"helm package",
		"helm registry login ghcr.io",
		"helm push",
		"oci://ghcr.io/alertint/charts",
	}
	for _, want := range wantCommands {
		if !strings.Contains(commands.String(), want) {
			t.Errorf("publish commands omit %q", want)
		}
	}
}

func TestApplicationWorkflowPublishesChartOnlyAfterGoReleaser(t *testing.T) {
	workflow := loadWorkflow(t, "release.yml")
	jobs := object(t, workflow["jobs"], "jobs")
	publish := object(t, jobs["publish-chart"], "jobs.publish-chart")

	if got := scalar(t, publish["needs"], "jobs.publish-chart.needs"); got != "release" {
		t.Fatalf("jobs.publish-chart.needs = %q, want release", got)
	}
	if got := scalar(t, publish["uses"], "jobs.publish-chart.uses"); got != "./.github/workflows/chart-release.yml" {
		t.Fatalf("jobs.publish-chart.uses = %q, want local chart release workflow", got)
	}
	permissions := object(t, publish["permissions"], "jobs.publish-chart.permissions")
	if got := scalar(t, permissions["packages"], "jobs.publish-chart.permissions.packages"); got != "write" {
		t.Fatalf("chart caller packages permission = %q, want write", got)
	}
}

func TestCIExecutesReleaseContractTests(t *testing.T) {
	workflow := loadWorkflow(t, "ci.yml")
	jobs := object(t, workflow["jobs"], "jobs")
	releaseScripts := object(t, jobs["release-scripts"], "jobs.release-scripts")
	steps := list(t, releaseScripts["steps"], "jobs.release-scripts.steps")

	var commands strings.Builder
	for _, raw := range steps {
		step := object(t, raw, "jobs.release-scripts.steps")
		if run, ok := step["run"].(string); ok {
			commands.WriteString(run)
			commands.WriteByte('\n')
		}
	}
	for _, want := range []string{
		"bash scripts/tests/release-scripts-test.sh",
		"go test ./scripts/tests",
	} {
		if !strings.Contains(commands.String(), want) {
			t.Errorf("release-scripts job omits %q", want)
		}
	}
}
