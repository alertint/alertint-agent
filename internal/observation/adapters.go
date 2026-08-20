// SPDX-License-Identifier: FSL-1.1-ALv2

package observation

import (
	"context"

	observationmodel "github.com/alertint/alertint-agent/internal/observation/model"
)

// Executor is the reduction boundary between a connector and the Situation
// controller. Implementations return normalized facts, never raw connector
// responses.
type Executor interface {
	Execute(context.Context, observationmodel.Plan) ([]observationmodel.Fact, Cost, error)
}

// Adapters supplies one read-only reducer per closed initial capability. A nil
// adapter keeps the capability visible but classifies execution as unavailable.
type Adapters struct {
	StoreRead            Executor
	PrometheusQuery      Executor
	ZabbixMetricRange    Executor
	ZabbixProblemHistory Executor
	LokiQuery            Executor
	SentryIssues         Executor
	ChangeEvents         Executor
}

type unavailableExecutor struct{}

func (unavailableExecutor) Execute(context.Context, observationmodel.Plan) ([]observationmodel.Fact, Cost, error) {
	return nil, Cost{}, ErrUnavailable
}

func configuredExecutor(value Executor) Executor {
	if value == nil {
		return unavailableExecutor{}
	}
	return value
}
