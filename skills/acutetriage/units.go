// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"github.com/prometheus/prometheus/promql/parser"
)

// metricBaseUnit recognizes explicit conventional suffixes only. Recording-rule
// names and contradictory suffixes do not supply a trustworthy base unit.
func metricBaseUnit(name string) string {
	if strings.Contains(name, ":") {
		return ""
	}
	name = strings.TrimSuffix(strings.TrimSuffix(name, "_total"), "_sum")
	if strings.HasSuffix(name, "_percent_ratio") {
		return ""
	}
	for _, unit := range []string{"nanoseconds", "microseconds", "milliseconds", "seconds", "bytes", "ratio", "cores"} {
		if strings.HasSuffix(name, "_"+unit) {
			return unit
		}
	}
	return ""
}

// promQLUnit follows only operations preserving the selected value's units.
// cpuScale is seconds' divisor for an explicit CPU-time rate, not other rates.
func promQLUnit(query string) (string, float64) {
	expr, err := parser.NewParser(parser.Options{}).ParseExpr(query)
	if err != nil {
		return "", 0
	}
	return expressionUnit(expr)
}

func expressionUnit(expr parser.Expr) (string, float64) {
	switch e := expr.(type) {
	case *parser.ParenExpr:
		return expressionUnit(e.Expr)
	case *parser.AggregateExpr:
		if e.Op != parser.COUNT && e.Op != parser.COUNT_VALUES && e.Op != parser.GROUP && e.Op != parser.STDVAR {
			return expressionUnit(e.Expr)
		}
	case *parser.BinaryExpr:
		if e.Op.IsComparisonOperator() && !e.ReturnBool {
			if e.LHS.Type() == parser.ValueTypeScalar {
				return expressionUnit(e.RHS)
			}
			return expressionUnit(e.LHS)
		}
	case *parser.VectorSelector:
		if unit := metricBaseUnit(vectorMetricName(e)); unit != "" {
			return "[" + unit + "] ", 0
		}
	case *parser.Call:
		if e.Func.Name != "rate" && e.Func.Name != "irate" && e.Func.Name != "increase" {
			return "", 0
		}
		var name string
		var window time.Duration
		var unit string
		switch arg := e.Args[0].(type) {
		case *parser.MatrixSelector:
			window = arg.Range
			if selector, ok := arg.VectorSelector.(*parser.VectorSelector); ok {
				name = vectorMetricName(selector)
			}
		case *parser.SubqueryExpr:
			window = arg.Range
			inner, _ := expressionUnit(arg.Expr)
			unit = strings.TrimSuffix(strings.TrimPrefix(inner, "["), "] ")
		}
		if name != "" {
			unit = metricBaseUnit(name)
		}
		if e.Func.Name == "increase" {
			if window <= 0 {
				return "", 0
			}
			if unit == "" {
				unit = "count"
			}
			return "[" + unit + " over " + model.Duration(window).String() + "] ", 0
		}
		if unit == "" {
			return "[per second] ", 0
		}
		var cpuScale float64
		if strings.HasSuffix(name, "_cpu_usage_"+unit+"_total") || strings.HasSuffix(name, "_cpu_"+unit+"_total") {
			cpuScale = map[string]float64{
				"seconds": 1, "milliseconds": 1e3,
				"microseconds": 1e6, "nanoseconds": 1e9,
			}[unit]
		}
		return "[" + unit + " per second] ", cpuScale
	}
	return "", 0
}
