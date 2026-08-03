// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"context"
	"log/slog"
	"sort"
	"strings"

	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/store"
)

// mergeSelectorKeys returns a fresh slice of base followed by extras — the
// "built-in core ∪ operator extras" pattern every selector-building site
// applies to its own base set (ADR-0035: allowedSelectorKeys uses the
// built-in six, parentScope uses broadScopeKeys). base is never aliased or
// mutated.
func mergeSelectorKeys(base, extras []string) []string {
	return append(append(make([]string, 0, len(base)+len(extras)), base...), extras...)
}

// allowedSelectorKeys returns the effective selector allowlist: the built-in
// keys plus the operator-configured extra selector labels (ADR-0035). Extras
// arrive pre-validated (syntax, no duplicates against the built-ins), so a
// plain append is safe.
func allowedSelectorKeys(extras []string) []string {
	return mergeSelectorKeys(logs.AllowedSelectorKeys, extras)
}

// logDroppedSelectorKeys emits the discoverability breadcrumb (ADR-0035): at
// debug level, name the shared label keys the selector allowlist dropped, so
// an operator can see why a label is absent from evidence queries without
// reading source. Guarded by Enabled so the recomputation costs nothing at
// info level.
func logDroppedSelectorKeys(ctx context.Context, logger *slog.Logger, surface string, alerts []store.Alert, extras []string, incidentID string) {
	if logger == nil || !logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	allowed := make(map[string]bool)
	for _, k := range allowedSelectorKeys(extras) {
		allowed[k] = true
	}
	var dropped []string
	for k := range sharedLabelValues(alerts) {
		if !allowed[k] {
			dropped = append(dropped, k)
		}
	}
	if len(dropped) == 0 {
		return
	}
	sort.Strings(dropped)
	logger.Debug("acutetriage: "+surface+": shared labels dropped by selector allowlist",
		"dropped", strings.Join(dropped, ","), "incident", incidentID)
}
