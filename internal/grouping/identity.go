// SPDX-License-Identifier: FSL-1.1-ALv2

// Package grouping builds stable, readable incident grouping identities.
package grouping

import (
	"sort"
	"strings"
)

// RenderLabels renders every label as sorted key=value pairs joined by commas.
func RenderLabels(labels map[string]string) string {
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	return render(labels, keys)
}

// RenderSelectedLabels renders the labels whose keys appear in selected.
func RenderSelectedLabels(labels map[string]string, selected []string) string {
	keys := make([]string, 0, len(selected))
	for _, key := range selected {
		if _, ok := labels[key]; ok {
			keys = append(keys, key)
		}
	}
	return render(labels, keys)
}

// Ensure returns identity when non-empty, otherwise falling back first to the
// alertname label and then to a fingerprint-scoped identity.
func Ensure(identity string, labels map[string]string, fingerprint string) string {
	if identity != "" {
		return identity
	}
	if alertname := labels["alertname"]; alertname != "" {
		return "alertname=" + alertname
	}
	return "fingerprint=" + fingerprint
}

func render(labels map[string]string, keys []string) string {
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}
