// SPDX-License-Identifier: FSL-1.1-ALv2

package config

// Drift gate: the three surfaces that describe configuration — the code
// defaults (Defaults()), the shipped example (config.example.yaml), and the
// reference page (docs/getting-started/configuration.md) — must tell the same
// story. Runs as a plain test so it gates CI regardless of which side moved.
//
//  1. config.example.yaml loads through the strict parser (KnownFields), so a
//     renamed or removed key fails immediately.
//  2. Every default in the reference page's Field/Type/Default tables matches
//     Defaults(). Cell conventions: `auto` = presence-based tri-state (the key
//     must be omitted from the marshaled defaults), `—` = no default (omitted
//     or zero value), anything else is compared literally after stripping
//     backticks and quotes.
//  3. Every key shipped in config.example.yaml is documented: under a
//     reference-page table row for sections the page covers, or in the
//     integration guide named in documentedElsewhere for sections it
//     delegates.

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

const (
	drillExamplePath   = "../../config.example.yaml"
	drillReferencePath = "../../docs/getting-started/configuration.md"
)

// documentedElsewhere names the doc that covers a top-level section the
// reference page intentionally delegates. Removing an entry (after adding the
// section to configuration.md) tightens the gate.
var documentedElsewhere = map[string]string{
	"logs":   "../../docs/integrations/loki.md",
	"sentry": "../../docs/integrations/sentry.md",
}

func TestDriftGate_ExampleConfigLoads(t *testing.T) {
	if _, err := LoadOffline(drillExamplePath); err != nil {
		t.Fatalf("config.example.yaml must load through the strict parser: %v", err)
	}
}

func TestDriftGate_ReferenceDefaultsMatchCode(t *testing.T) {
	flat := flattenDefaults(t)
	rows := parseReferenceTables(t)
	if len(rows) == 0 {
		t.Fatal("no Field/Type/Default tables found in the reference page — parser or page structure changed")
	}
	for _, row := range rows {
		cell := strings.TrimSpace(strings.ReplaceAll(row.def, "`", ""))
		got, present := flat[row.path]
		switch cell {
		case "auto":
			if present {
				t.Errorf("%s: reference says default is auto (presence-based), but Defaults() sets %v", row.path, got)
			}
		case "—", "":
			if present && !isZeroValue(got) {
				t.Errorf("%s: reference says no default (—), but Defaults() sets %v", row.path, got)
			}
		default:
			want := strings.Trim(cell, `"`)
			if !present {
				t.Errorf("%s: reference says default %q, but Defaults() omits the key", row.path, want)
				continue
			}
			if rendered := renderValue(got); rendered != want {
				t.Errorf("%s: reference says default %q, Defaults() has %q", row.path, want, rendered)
			}
		}
	}
}

func TestDriftGate_ExampleKeysDocumented(t *testing.T) {
	raw, err := os.ReadFile(drillExamplePath)
	if err != nil {
		t.Fatal(err)
	}
	var example map[string]any
	if err := yaml.Unmarshal(raw, &example); err != nil {
		t.Fatal(err)
	}
	leaves := map[string]any{}
	flattenInto("", example, leaves)

	documented := map[string]bool{}
	for _, row := range parseReferenceTables(t) {
		documented[row.path] = true
	}
	reference := readFileString(t, drillReferencePath)
	elsewhere := map[string]string{}
	for section, path := range documentedElsewhere {
		elsewhere[section] = readFileString(t, path)
	}

	for path := range leaves {
		section, rest, _ := strings.Cut(path, ".")
		if rest == "" {
			// Top-level scalar (log_level, log_format): a `## key` heading
			// documents it.
			if !strings.Contains(reference, "## `"+section+"`") {
				t.Errorf("%s: shipped in config.example.yaml but has no `## %s` heading in the reference page", path, section)
			}
			continue
		}
		if body, ok := elsewhere[section]; ok {
			// Delegated section: some segment of the path must appear in the
			// integration guide (map keys under e.g. label_map are user data,
			// so the parent name counts).
			if !anySegmentMentioned(rest, body) {
				t.Errorf("%s: shipped in config.example.yaml but not mentioned in %s", path, documentedElsewhere[section])
			}
			continue
		}
		if !documentedOrAncestor(documented, path) {
			t.Errorf("%s: shipped in config.example.yaml but has no table row in the reference page", path)
		}
	}
}

// --- helpers ---

type referenceRow struct {
	path string // dotted path: section + "." + field cell
	def  string // raw Default cell
}

var sectionHeading = regexp.MustCompile("^## `([a-z_]+)`$")

// parseReferenceTables extracts every row of every Field/Type/Default table,
// keyed to the `## section` heading it appears under.
func parseReferenceTables(t *testing.T) []referenceRow {
	t.Helper()
	var rows []referenceRow
	section := ""
	inTable := false
	for _, line := range strings.Split(readFileString(t, drillReferencePath), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "## ") {
			section = ""
			if m := sectionHeading.FindStringSubmatch(line); m != nil {
				section = m[1]
			}
			inTable = false
			continue
		}
		if strings.HasPrefix(line, "| Field | Type | Default |") {
			inTable = section != ""
			continue
		}
		if !inTable {
			continue
		}
		if !strings.HasPrefix(line, "|") {
			inTable = false
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) < 5 || strings.HasPrefix(strings.TrimSpace(cells[1]), "---") {
			continue
		}
		field := strings.Trim(strings.TrimSpace(cells[1]), "`")
		rows = append(rows, referenceRow{path: section + "." + field, def: cells[3]})
	}
	return rows
}

// flattenDefaults marshals Defaults() to YAML and flattens it to dotted leaf
// paths, so tri-state fields (omitempty pointers) simply vanish when unset.
func flattenDefaults(t *testing.T) map[string]any {
	t.Helper()
	raw, err := yaml.Marshal(Defaults())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := yaml.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	flat := map[string]any{}
	flattenInto("", m, flat)
	return flat
}

func flattenInto(prefix string, v any, out map[string]any) {
	m, ok := v.(map[string]any)
	if !ok || len(m) == 0 {
		out[prefix] = v
		return
	}
	for k, child := range m {
		p := k
		if prefix != "" {
			p = prefix + "." + k
		}
		flattenInto(p, child, out)
	}
}

func renderValue(v any) string {
	if list, ok := v.([]any); ok {
		parts := make([]string, len(list))
		for i, item := range list {
			parts[i] = fmt.Sprint(item)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	}
	return fmt.Sprint(v)
}

func isZeroValue(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case bool:
		return !x
	case int:
		return x == 0
	case []any:
		return len(x) == 0
	default:
		return false
	}
}

func documentedOrAncestor(documented map[string]bool, path string) bool {
	for p := path; p != ""; {
		if documented[p] {
			return true
		}
		i := strings.LastIndex(p, ".")
		if i < 0 {
			break
		}
		p = p[:i]
	}
	return false
}

func anySegmentMentioned(rest, body string) bool {
	for _, seg := range strings.Split(rest, ".") {
		if strings.Contains(body, seg) {
			return true
		}
	}
	return false
}

func readFileString(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(raw)
}
