// SPDX-License-Identifier: FSL-1.1-ALv2

package situation

import (
	"fmt"
	"slices"
	"strings"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
	"github.com/alertint/alertint-agent/internal/situation/model"
)

func coverageLimitationsOf(results []CapabilityResult) []model.CoverageLimitation {
	var out []model.CoverageLimitation
	for _, r := range results {
		if r.Capability != "prometheus_query" || r.RunID == "" || len(r.LimitationCodes) == 0 {
			continue
		}
		atLeast := slices.ContainsFunc(r.LimitationCodes, func(code string) bool {
			return code == "truncated" || code == "response_too_large" || strings.HasPrefix(code, "diagnostics_")
		})
		out = append(out, model.CoverageLimitation{RunID: r.RunID, Capability: r.Capability, Codes: append([]string(nil), r.LimitationCodes...), Returned: r.Returned, Omitted: r.Omitted, OmittedAtLeast: atLeast})
		if len(out) == 32 {
			break
		}
	}
	return out
}

// CoverageLimitationLines explains frozen observation metadata, independently
// of assessment prose. Renderers must escape these lines for their transport.
func CoverageLimitationLines(p model.ProjectionFacts) []string {
	lines := make([]string, 0, len(p.CoverageLimitations))
	for _, l := range p.CoverageLimitations {
		counts := fmt.Sprintf("retained %d series; omitted %d", l.Returned, l.Omitted)
		if l.OmittedAtLeast {
			counts = fmt.Sprintf("retained %d series; omitted at least %d", l.Returned, l.Omitted)
		}
		var reasons []string
		for _, code := range l.Codes {
			switch code {
			case "truncated":
				reasons = append(reasons, "Prometheus series limit reached: "+counts+".")
			case "fact_bytes_capped":
				reasons = append(reasons, fmt.Sprintf("Prometheus summary size limit (%d KiB) reached: %s.", observationmodel.MaxFactBytes/1024, counts))
			case "response_too_large":
				text := fmt.Sprintf("Prometheus response size limit (%d MiB) reached: rejected response supplied no usable metrics; omitted count unknown.", observationmodel.MaxDecodedResponseBytes/(1024*1024))
				if l.Returned > 0 {
					text += fmt.Sprintf(" Retained %d series from other reads.", l.Returned)
				}
				reasons = append(reasons, text)
			case "diagnostics_withheld_by_budget":
				reasons = append(reasons, fmt.Sprintf("Additional diagnostic metrics were not read: request budget exhausted; retained %d series; omitted count unknown.", l.Returned))
			case "diagnostics_withheld_by_limit":
				reasons = append(reasons, fmt.Sprintf("Additional diagnostic metrics were not read: evidence limit reached; retained %d series; omitted count unknown.", l.Returned))
			case "diagnostics_withheld_by_series_limit":
				reasons = append(reasons, fmt.Sprintf("Additional diagnostic metrics were not read: series limit reached; retained %d series; omitted count unknown.", l.Returned))
			case "diagnostics_withheld_by_summary_limit":
				reasons = append(reasons, fmt.Sprintf("Additional diagnostic metrics were not read: summary size limit (%d KiB) reached; retained %d series; omitted count unknown.", observationmodel.MaxFactBytes/1024, l.Returned))
			case "diagnostics_failed":
				reasons = append(reasons, fmt.Sprintf("Additional diagnostic metrics could not be read; retained %d series; omitted count unknown.", l.Returned))
			case "rule_metrics_ambiguous_rule":
				reasons = append(reasons, "Current alert rule is ambiguous; used bounded scope metrics as fallback.")
			case "rule_metrics_response_too_large":
				reasons = append(reasons, "Current rule lookup exceeded the 1 MiB response size limit; used bounded scope metrics as fallback.")
			case "rule_metrics_empty":
				reasons = append(reasons, "Current rule metrics returned no series in the configured scope; additional diagnostics were attempted.")
			default:
				if strings.HasPrefix(code, "rule_metrics_") {
					reasons = append(reasons, "Current rule metrics unavailable ("+strings.ReplaceAll(strings.TrimPrefix(code, "rule_metrics_"), "_", " ")+"); used bounded scope metrics as fallback.")
				} else {
					reasons = append(reasons, "Prometheus collection limited: "+strings.ReplaceAll(code, "_", " ")+".")
				}
			}
		}
		lines = append(lines, "Observation: "+l.RunID+". "+strings.Join(reasons, " "))
	}
	return lines
}

// CoverageLimitationCodes is semantic coverage state. Collection identities and
// small count fluctuations are diagnostic provenance and must not page people.
func CoverageLimitationCodes(p model.ProjectionFacts) []string {
	var codes []string
	for _, l := range p.CoverageLimitations {
		for _, code := range l.Codes {
			codes = append(codes, l.Capability+":"+code)
		}
	}
	slices.Sort(codes)
	return slices.Compact(codes)
}
