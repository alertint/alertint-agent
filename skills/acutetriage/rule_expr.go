// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"net/url"
	"sort"

	"github.com/alertint/alertint-agent/internal/prometheus"
)

// ruleExpressions extracts bounded, valid PromQL from stored generator URLs.
// It parses query strings only; it never contacts the URL host.
func ruleExpressions(urls []string) []string {
	seen := map[string]bool{}
	for _, raw := range urls {
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		expr := u.Query().Get("g0.expr")
		if expr == "" || len(expr) > 2048 || prometheus.ValidateExpr(expr) != nil {
			continue
		}
		seen[expr] = true
	}
	out := make([]string, 0, len(seen))
	for expr := range seen {
		out = append(out, expr)
	}
	sort.Strings(out)
	if len(out) > 3 {
		out = out[:3]
	}
	return out
}
