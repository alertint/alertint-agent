// SPDX-License-Identifier: FSL-1.1-ALv2

package model

import "errors"

// CoverageLimitation is frozen source-run metadata for operator diagnostics.
// It does not depend on an LLM selecting a limitation and is not an authority
// claim about the alert. Omitted counts may be lower bounds or unknown.
type CoverageLimitation struct {
	RunID          string   `json:"run_id"`
	Capability     string   `json:"capability"`
	Codes          []string `json:"codes"`
	Returned       int      `json:"returned"`
	Omitted        int      `json:"omitted"`
	OmittedAtLeast bool     `json:"omitted_at_least"`
}

func (l CoverageLimitation) Validate() error {
	if l.RunID == "" || len(l.RunID) > maxIdentifierLength || l.Capability != "prometheus_query" || len(l.Codes) == 0 || len(l.Codes) > 16 || l.Returned < 0 || l.Omitted < 0 {
		return errors.New("coverage_limitation: invalid source-run metadata")
	}
	for _, code := range l.Codes {
		if code == "" || len(code) > 128 {
			return errors.New("coverage_limitation: invalid code")
		}
	}
	return nil
}
