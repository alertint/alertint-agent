// SPDX-License-Identifier: FSL-1.1-ALv2

package triage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// jsonUnmarshal is a thin wrapper so schema.go doesn't need to import
// encoding/json directly (keeps the import surface narrow).
func jsonUnmarshal(data json.RawMessage, v any) error {
	return json.Unmarshal(data, v)
}

// PromptHash returns a stable "sha256:<hex>" hash of the supplied prompt
// text. Used by the scripted LLM in drill-golden and replay to match
// scripted responses to the prompt that triggered them.
func PromptHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}
