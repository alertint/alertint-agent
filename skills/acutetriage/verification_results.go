// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"time"
)

// verificationResult retains transient labels for bounded rendering only.
type verificationResult struct {
	MetricSnapshot

	labels map[string]string
}

// decodeVerificationResults preserves the numeric shapes an instant API call
// can return. Range vectors are summaries, not invented instant measurements.
func decodeVerificationResults(raw json.RawMessage) ([]verificationResult, error) {
	var envelope struct {
		ResultType string          `json:"resultType"`
		Result     json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, err
	}
	switch envelope.ResultType {
	case "", "vector":
		var entries []struct {
			Metric map[string]string `json:"metric"`
		}
		if err := json.Unmarshal(envelope.Result, &entries); err != nil {
			return nil, err
		}
		results := decodeInstantResults(raw)
		if len(results) != len(entries) {
			return nil, errors.New("unsupported vector sample")
		}
		out := make([]verificationResult, 0, len(results))
		for i, result := range results {
			if _, err := strconv.ParseFloat(result.Value, 64); err != nil {
				return nil, err
			}
			out = append(out, verificationResult{MetricSnapshot: result, labels: entries[i].Metric})
		}
		return out, nil
	case "scalar":
		var sample [2]any
		if err := json.Unmarshal(envelope.Result, &sample); err != nil {
			return nil, err
		}
		value, ok := sample[1].(string)
		timestamp, timestampOK := sample[0].(float64)
		if !ok || !timestampOK || math.IsNaN(timestamp) || math.IsInf(timestamp, 0) {
			return nil, errors.New("unsupported scalar sample")
		}
		if _, err := strconv.ParseFloat(value, 64); err != nil {
			return nil, err
		}
		return []verificationResult{{MetricSnapshot: MetricSnapshot{Series: "{}", Value: value}}}, nil
	case "matrix":
		var series []struct {
			Metric     map[string]string `json:"metric"`
			Values     [][2]any          `json:"values"`
			Histograms []json.RawMessage `json:"histograms"`
		}
		if err := json.Unmarshal(envelope.Result, &series); err != nil {
			return nil, err
		}
		if len(series) > maxSnapshotsPerScope {
			series = series[:maxSnapshotsPerScope]
		}
		out := make([]verificationResult, 0, len(series))
		for _, s := range series {
			if len(s.Histograms) > 0 {
				return nil, errors.New("unsupported range histogram sample")
			}
			if len(s.Values) == 0 {
				continue
			}
			summary, err := summarizeRangeSamples(s.Values)
			if err != nil {
				return nil, err
			}
			out = append(out, verificationResult{MetricSnapshot: MetricSnapshot{Series: formatSeriesIdentity(s.Metric), Value: summary}, labels: s.Metric})
		}
		return out, nil
	default:
		return nil, errors.New("unsupported Prometheus result type")
	}
}

// summarizeRangeSamples scans all returned samples. Decreasing steps concern
// adjacent finite samples only; nonfinite values interrupt that comparison.
func summarizeRangeSamples(samples [][2]any) (string, error) {
	minimum, maximum := math.Inf(1), math.Inf(-1)
	var previous float64
	var previousFinite bool
	var first, last string
	decreases, nonfinite := 0, 0
	for i, sample := range samples {
		timestamp, timestampOK := sample[0].(float64)
		value, valueOK := sample[1].(string)
		if !timestampOK || !valueOK || math.IsNaN(timestamp) || math.IsInf(timestamp, 0) {
			return "", errors.New("unsupported range sample")
		}
		number, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return "", err
		}
		last = value + "@" + time.UnixMilli(int64(math.Round(timestamp*1000))).UTC().Format(time.RFC3339Nano)
		if i == 0 {
			first = last
		}
		finite := !math.IsNaN(number) && !math.IsInf(number, 0)
		if finite {
			minimum, maximum = math.Min(minimum, number), math.Max(maximum, number)
			if previousFinite && number < previous {
				decreases++
			}
		} else {
			nonfinite++
		}
		previous, previousFinite = number, finite
	}
	minText, maxText := "unknown", "unknown"
	if nonfinite < len(samples) {
		minText = strconv.FormatFloat(minimum, 'g', -1, 64)
		maxText = strconv.FormatFloat(maximum, 'g', -1, 64)
	}
	return fmt.Sprintf("[range summary; not full trajectory] samples=%d first=%s last=%s min=%s max=%s decreasing_steps=%d nonfinite=%d", len(samples), first, last, minText, maxText, decreases, nonfinite), nil
}
