// SPDX-License-Identifier: FSL-1.1-ALv2

package acutetriage

import (
	"reflect"
	"testing"

	"github.com/alertint/alertint-agent/internal/logs"
	"github.com/alertint/alertint-agent/internal/store"
)

func clusterAlerts() []store.Alert {
	return []store.Alert{
		{Labels: map[string]string{
			"alertname": "CheckoutHighErrorRate", "cluster": "eu-west",
			"namespace": "payments", "service": "checkout", "severity": "critical",
		}},
		{Labels: map[string]string{
			"alertname": "CheckoutHighErrorRate", "cluster": "eu-west",
			"namespace": "payments", "service": "checkout", "severity": "critical",
		}},
	}
}

func TestAllowedSelectorKeys_ExtendsBuiltins(t *testing.T) {
	got := allowedSelectorKeys([]string{"cluster", "region"})
	want := append(append([]string{}, logs.AllowedSelectorKeys...), "cluster", "region")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
	// nil extras must not alias or mutate the built-in slice
	if !reflect.DeepEqual(allowedSelectorKeys(nil), logs.AllowedSelectorKeys) {
		t.Fatal("nil extras must yield exactly the built-in allowlist")
	}
}

func TestBuildMetricSelector_ExtraIncluded(t *testing.T) {
	sel := buildMetricSelector(clusterAlerts(), []string{"cluster"})
	if !reflect.DeepEqual(sel["cluster"], []string{"eu-west"}) {
		t.Fatalf("cluster missing from selector: %v", sel)
	}
	if _, ok := sel["severity"]; ok {
		t.Fatalf("alert-metadata key leaked into selector: %v", sel)
	}
}

func TestBuildMetricSelector_NoExtras_Unchanged(t *testing.T) {
	sel := buildMetricSelector(clusterAlerts(), nil)
	if _, ok := sel["cluster"]; ok {
		t.Fatalf("cluster must be dropped without extras: %v", sel)
	}
}

func TestBuildLogSelector_ExtraIncluded(t *testing.T) {
	sel := buildLogSelector(clusterAlerts(), []string{"cluster"})
	if !reflect.DeepEqual(sel.Labels["cluster"], []string{"eu-west"}) {
		t.Fatalf("cluster missing from log selector: %v", sel.Labels)
	}
}
