// SPDX-License-Identifier: FSL-1.1-ALv2

// Package semanticprofile builds and stores advisory L0 semantic profiles.
// It has no membership, lifecycle, policy, or notification authority.
package semanticprofile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"

	"github.com/alertint/alertint-agent/internal/store"
)

// Signature returns the deterministic cache key for a source shape. Concrete
// host, episode, and other label values are deliberately excluded.
func Signature(d store.AlertDelivery) string {
	key, _ := signatureMaterial(d)
	return key
}

func signatureMaterial(d store.AlertDelivery) (string, json.RawMessage) {
	source := strings.ToLower(strings.TrimSpace(d.Source))
	if source == "" {
		source = "unknown"
	}
	triggerID := strings.TrimSpace(firstValue(d.Alert.Labels, "zabbix_trigger_id", "trigger_id"))
	template := templateIdentity(d)
	if source == "zabbix" && triggerID != "" {
		material := map[string]any{"source": source, "trigger_id": triggerID, "template_identity": template}
		return source + ":trigger=" + triggerID + ":template=" + template, mustJSON(material)
	}
	material := map[string]any{
		"source": source, "alert_name": d.Alert.Labels["alertname"],
		"label_schema": sortedKeys(d.Alert.Labels), "annotation_schema": sortedKeys(d.Alert.Annotations),
		"template_identity": template,
	}
	encoded := mustJSON(material)
	return source + ":schema=sha256:" + digest(string(encoded)), encoded
}

func templateIdentity(d store.AlertDelivery) string {
	v := firstValue(d.Alert.Annotations, "template_identity", "template_version", "trigger_version", "zabbix_template")
	if v == "" {
		v = firstValue(d.Alert.Labels, "template_identity", "template_version", "trigger_version", "zabbix_template")
	}
	if strings.HasPrefix(strings.ToLower(v), "sha256:") {
		return "sha256:" + strings.ToLower(strings.TrimPrefix(v, "sha256:"))
	}
	if v == "" {
		v = d.Alert.Labels["alertname"]
	}
	return "sha256:" + digest(v)
}

func firstValue(values map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(values[key]); value != "" {
			return value
		}
	}
	return ""
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func digest(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])[:12]
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
