// SPDX-License-Identifier: FSL-1.1-ALv2

package prometheus

import (
	"context"
	"encoding/json"
	"sort"

	"github.com/prometheus/prometheus/model/labels"
	parser "github.com/prometheus/prometheus/promql/parser"
)

// AlertRuleMetrics discovers exact metric names in one uniquely named current
// rule. Without a firing alert matching every frozen scope label, names are
// returned with an explicit current-definition hint. Selection is advisory,
// never proof of lifecycle state or the rule that emitted an older delivery.
// The caller must reserve/settle this single bounded physical request.
func (c *Client) AlertRuleMetrics(ctx context.Context, alertName string, scope map[string]string) ([]string, string, error) {
	raw, err := c.apiGetBounded(ctx, "/api/v1/rules", nil)
	if err != nil {
		return nil, "api_unavailable", err
	}
	type rule struct {
		Type   string `json:"type"`
		Name   string `json:"name"`
		Query  string `json:"query"`
		Alerts []struct {
			State  string            `json:"state"`
			Labels map[string]string `json:"labels"`
		} `json:"alerts"`
	}
	var payload struct {
		Groups []struct {
			Rules []rule `json:"rules"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, "api_unavailable", err
	}
	var matches []rule
	recording := map[string]bool{}
	for _, group := range payload.Groups {
		for _, r := range group.Rules {
			if r.Type == "recording" {
				recording[r.Name] = true
			}
			if r.Type == "alerting" && r.Name == alertName {
				matches = append(matches, r)
			}
		}
	}
	if len(matches) == 0 {
		return nil, "rule_not_found", nil
	}
	if len(matches) != 1 {
		return nil, "ambiguous_rule", nil
	}
	firing := false
	for _, a := range matches[0].Alerts {
		if a.State != "firing" {
			continue
		}
		match := len(scope) > 0
		for k, v := range scope {
			if a.Labels[k] != v {
				match = false
				break
			}
		}
		firing = firing || match
	}
	reason := ""
	if !firing {
		reason = "current_definition_hint"
	}
	exprText := matches[0].Query
	if len(exprText) > 8192 {
		return nil, "unsupported_expression", nil
	}
	expr, err := parser.NewParser(parser.Options{}).ParseExpr(exprText)
	if err != nil {
		return nil, "unsupported_expression", nil
	}
	names := map[string]bool{}
	unsupported := false
	parser.Inspect(expr, func(node parser.Node, _ []parser.Node) error {
		v, ok := node.(*parser.VectorSelector)
		if !ok {
			return nil
		}
		name := v.Name
		for _, m := range v.LabelMatchers {
			if m.Name == "__name__" && m.Type == labels.MatchEqual {
				name = m.Value
			}
		}
		if name == "" || len(name) > 256 {
			unsupported = true
		} else {
			names[name] = true
		}
		return nil
	})
	if unsupported || len(names) == 0 || len(names) > 32 {
		return nil, "unsupported_expression", nil
	}
	out := make([]string, 0, len(names))
	for name := range names {
		if recording[name] {
			return nil, "recording_dependency", nil
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, reason, nil
}
