// SPDX-License-Identifier: FSL-1.1-ALv2

package tests

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func repoFile(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "..", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return body
}

func workflow(t *testing.T, name string) map[string]any {
	t.Helper()
	var result map[string]any
	if err := yaml.Unmarshal(repoFile(t, filepath.Join(".github", "workflows", name)), &result); err != nil {
		t.Fatalf("parse workflow %s: %v", name, err)
	}
	return result
}

func mapping(t *testing.T, value any, path string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want mapping", path, value)
	}
	return result
}

func sequence(t *testing.T, value any, path string) []any {
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

func TestChartReleaseWorkflowPublishesDirectAndCalledStableReleases(t *testing.T) {
	wf := workflow(t, "chart-release.yml")
	on := mapping(t, wf["on"], "on")
	push := mapping(t, on["push"], "on.push")
	tags := sequence(t, push["tags"], "on.push.tags")
	if len(tags) != 1 || scalar(t, tags[0], "on.push.tags[0]") != "chart-v*" {
		t.Fatalf("on.push.tags = %#v, want [chart-v*]", tags)
	}
	if _, ok := on["workflow_call"]; !ok {
		t.Fatal("on.workflow_call is missing; stable application releases cannot reuse chart publication")
	}
	permissions := mapping(t, wf["permissions"], "permissions")
	if got := scalar(t, permissions["packages"], "permissions.packages"); got != "write" {
		t.Fatalf("permissions.packages = %q, want write", got)
	}
	jobs := mapping(t, wf["jobs"], "jobs")
	publish := mapping(t, jobs["publish"], "jobs.publish")
	steps := sequence(t, publish["steps"], "jobs.publish.steps")
	var commands strings.Builder
	for _, raw := range steps {
		if run, ok := mapping(t, raw, "jobs.publish.steps[]")["run"].(string); ok {
			commands.WriteString(run)
			commands.WriteByte('\n')
		}
	}
	for _, want := range []string{"chart-release-validate.sh", "helm lint", "helm package", "helm registry login ghcr.io", "helm push", "cosign sign", "cosign verify"} {
		if !strings.Contains(commands.String(), want) {
			t.Errorf("chart publication omits %q", want)
		}
	}
}

func TestRCGoReleaserConfigCannotPublishStableAliases(t *testing.T) {
	rc := string(repoFile(t, ".goreleaser.rc.yaml"))
	for _, want := range []string{
		`ghcr.io/alertint/alertint-agent:{{ .Tag }}-amd64`,
		`ghcr.io/alertint/alertint-agent:{{ .Tag }}-arm64`,
		`ghcr.io/alertint/alertint-agent:{{ .Tag }}`,
		"make_latest: false",
		"compare/v0.13.9...{{ .Tag }}",
	} {
		if !strings.Contains(rc, want) {
			t.Errorf("RC config omits %q", want)
		}
	}
	for _, forbidden := range []string{"latest-amd64", "latest-arm64", "alertint-agent:latest\""} {
		if strings.Contains(rc, forbidden) {
			t.Errorf("RC config contains stable alias %q", forbidden)
		}
	}

	stable := string(repoFile(t, ".goreleaser.yaml"))
	for _, want := range []string{"latest-amd64", "latest-arm64", `alertint-agent:latest"`} {
		if !strings.Contains(stable, want) {
			t.Errorf("stable config lost %q", want)
		}
	}
}

func TestRCGoReleaserConfigKeepsStableBuildAndArchiveContract(t *testing.T) {
	load := func(name string) map[string]any {
		t.Helper()
		var result map[string]any
		if err := yaml.Unmarshal(repoFile(t, name), &result); err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		return result
	}
	stable := load(".goreleaser.yaml")
	rc := load(".goreleaser.rc.yaml")
	for _, key := range []string{"project_name", "before", "builds", "archives", "checksum", "changelog"} {
		if !reflect.DeepEqual(rc[key], stable[key]) {
			t.Errorf("RC config %s differs from stable config", key)
		}
	}
}

func TestReleaseArchivesIncludeSituationWorkflowGuide(t *testing.T) {
	for _, name := range []string{".goreleaser.yaml", ".goreleaser.rc.yaml"} {
		body := string(repoFile(t, name))
		if !strings.Contains(body, "docs/concepts/situation-workflow.html") {
			t.Errorf("%s omits the standalone Situation workflow guide", name)
		}
		if !strings.Contains(body, "client-skills/**/*") {
			t.Errorf("%s omits the client investigation skill", name)
		}
	}
}

func TestReleaseWorkflowSelectsRCConfigAndPublishesChartOnlyForStableTags(t *testing.T) {
	wf := workflow(t, "release.yml")
	jobs := mapping(t, wf["jobs"], "jobs")
	release := mapping(t, jobs["release"], "jobs.release")
	outputs := mapping(t, release["outputs"], "jobs.release.outputs")
	if got, _ := outputs["publish_chart"].(string); !strings.Contains(got, "publish_chart") {
		t.Fatalf("jobs.release.outputs.publish_chart = %q, want release-config output", got)
	}
	steps := sequence(t, release["steps"], "jobs.release.steps")
	var all strings.Builder
	for _, raw := range steps {
		step := mapping(t, raw, "jobs.release.steps[]")
		for _, key := range []string{"name", "run"} {
			if value, ok := step[key].(string); ok {
				all.WriteString(value)
				all.WriteByte('\n')
			}
		}
		if with, ok := step["with"].(map[string]any); ok {
			if args, ok := with["args"].(string); ok {
				all.WriteString(args)
				all.WriteByte('\n')
			}
		}
	}
	text := all.String()
	for _, want := range []string{"Select release configuration", ".goreleaser.rc.yaml", "publish_chart=false", "publish_chart=true", "--config"} {
		if !strings.Contains(text, want) {
			t.Errorf("release workflow omits %q", want)
		}
	}
	publish := mapping(t, jobs["publish-chart"], "jobs.publish-chart")
	if got, _ := publish["needs"].(string); got != "release" {
		t.Fatalf("jobs.publish-chart.needs = %q, want release", got)
	}
	if got, _ := publish["if"].(string); !strings.Contains(got, "needs.release.outputs.publish_chart == 'true'") {
		t.Fatalf("jobs.publish-chart.if = %q, want stable-only output condition", got)
	}
	if got, _ := publish["uses"].(string); got != "./.github/workflows/chart-release.yml" {
		t.Fatalf("jobs.publish-chart.uses = %q", got)
	}
}

func TestCIExecutesReleaseContractTests(t *testing.T) {
	body := repoFile(t, filepath.Join(".github", "workflows", "ci.yml"))
	wf := workflow(t, "ci.yml")
	jobs := mapping(t, wf["jobs"], "jobs")
	job := mapping(t, jobs["release-scripts"], "jobs.release-scripts")
	steps := sequence(t, job["steps"], "jobs.release-scripts.steps")
	var commands strings.Builder
	for _, raw := range steps {
		step := mapping(t, raw, "jobs.release-scripts.steps[]")
		if run, ok := step["run"].(string); ok {
			commands.WriteString(run)
			commands.WriteByte('\n')
		}
		if with, ok := step["with"].(map[string]any); ok {
			if args, ok := with["args"].(string); ok {
				commands.WriteString(args)
				commands.WriteByte('\n')
			}
		}
	}
	for _, want := range []string{
		"bash scripts/tests/release-scripts-test.sh",
		"bash scripts/tests/release-rc-test.sh",
		"go test ./scripts/tests",
		"goreleaser/goreleaser-action@v7",
		"check .goreleaser.yaml .goreleaser.rc.yaml",
	} {
		if !strings.Contains(commands.String(), want) && !strings.Contains(string(body), want) {
			t.Errorf("release-scripts job omits %q", want)
		}
	}
}
