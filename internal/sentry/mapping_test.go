// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"testing"
	"time"
)

// strptr builds a *string for optional Deploy.Environment values in tests.
func strptr(s string) *string { return &s }

const (
	testBaseURL = "https://sentry.io"
	testOrg     = "acme"
)

func TestMapping_DeployFull(t *testing.T) {
	finished := time.Date(2026, 6, 25, 10, 6, 0, 0, time.UTC)
	d := Deploy{ID: "d-1", Environment: strptr("production"), DateFinished: finished}

	c := mapDeploy(testBaseURL, testOrg, "checkout", "checkout@1.2.0", d)

	if c.Source != "sentry" || c.Kind != "deploy" {
		t.Errorf("source/kind = %q/%q", c.Source, c.Kind)
	}
	if c.Labels["project"] != "checkout" || c.Labels["environment"] != "production" {
		t.Errorf("labels = %v, want project=checkout environment=production", c.Labels)
	}
	if !c.OccurredAt.Equal(finished) {
		t.Errorf("OccurredAt = %v, want %v (dateFinished)", c.OccurredAt, finished)
	}
	if c.Version != "checkout@1.2.0" {
		t.Errorf("Version = %q", c.Version)
	}
	// Covers R12: title carries project + version + environment, reads standalone.
	if c.Title != "checkout deployed checkout@1.2.0 to production" {
		t.Errorf("Title = %q", c.Title)
	}
	wantLink := "https://sentry.io/organizations/acme/releases/checkout@1.2.0/?project=checkout"
	if c.Link != wantLink {
		t.Errorf("Link = %q, want %q", c.Link, wantLink)
	}
	if c.ID != "" {
		t.Errorf("ID = %q, want empty (poller stamps it)", c.ID)
	}
}

func TestMapping_DeployNilEnvironmentDegrades(t *testing.T) {
	d := Deploy{ID: "d-2", Environment: nil, DateFinished: time.Now().UTC()}
	c := mapDeploy(testBaseURL, testOrg, "checkout", "v9", d)

	if _, ok := c.Labels["environment"]; ok {
		t.Errorf("environment label present for nil environment: %v", c.Labels)
	}
	if c.Labels["project"] != "checkout" {
		t.Errorf("project label missing: %v", c.Labels)
	}
	if c.Title != "checkout deployed v9" {
		t.Errorf("Title = %q, want degraded form without environment", c.Title)
	}

	// An empty (non-nil) environment string degrades the same way.
	d.Environment = strptr("")
	if c2 := mapDeploy(testBaseURL, testOrg, "checkout", "v9", d); c2.Title != "checkout deployed v9" {
		t.Errorf("empty-string env Title = %q", c2.Title)
	}
}

func TestMapping_DeployMultiEnv(t *testing.T) {
	// Covers AE9: a release deployed to staging and production yields two
	// changes, each with its own environment label and finish time.
	staging := Deploy{ID: "d-s", Environment: strptr("staging"), DateFinished: time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)}
	prod := Deploy{ID: "d-p", Environment: strptr("production"), DateFinished: time.Date(2026, 6, 25, 10, 5, 0, 0, time.UTC)}

	cs := mapDeploy(testBaseURL, testOrg, "checkout", "v1", staging)
	cp := mapDeploy(testBaseURL, testOrg, "checkout", "v1", prod)

	if cs.Labels["environment"] != "staging" || cp.Labels["environment"] != "production" {
		t.Errorf("env labels = %q / %q", cs.Labels["environment"], cp.Labels["environment"])
	}
	if cs.OccurredAt.Equal(cp.OccurredAt) {
		t.Errorf("expected distinct finish times, both %v", cs.OccurredAt)
	}
}

func TestMapping_ReleaseFallbackTimestamp(t *testing.T) {
	created := time.Date(2026, 6, 25, 9, 0, 0, 0, time.UTC)
	released := time.Date(2026, 6, 25, 9, 30, 0, 0, time.UTC)

	withReleased := Release{Version: "v2", DateCreated: created, DateReleased: &released}
	c := mapRelease(testBaseURL, testOrg, "checkout", withReleased)
	if c.Kind != "release" || !c.OccurredAt.Equal(released) {
		t.Errorf("with dateReleased: kind=%q OccurredAt=%v, want release / %v", c.Kind, c.OccurredAt, released)
	}
	if c.Labels["project"] != "checkout" {
		t.Errorf("labels = %v", c.Labels)
	}
	if _, ok := c.Labels["environment"]; ok {
		t.Errorf("release change should carry no environment label: %v", c.Labels)
	}
	if c.Title != "checkout released v2" {
		t.Errorf("Title = %q", c.Title)
	}

	noReleased := Release{Version: "v3", DateCreated: created, DateReleased: nil}
	c2 := mapRelease(testBaseURL, testOrg, "checkout", noReleased)
	if !c2.OccurredAt.Equal(created) {
		t.Errorf("null dateReleased: OccurredAt = %v, want dateCreated %v", c2.OccurredAt, created)
	}
}

func TestMapping_ChangeLinkEncodes(t *testing.T) {
	got := changeLink("https://de.sentry.io/", "ac/me", "v1.0/rc@2", "check out")
	want := "https://de.sentry.io/organizations/ac%2Fme/releases/v1.0%2Frc@2/?project=check+out"
	if got != want {
		t.Errorf("changeLink = %q, want %q", got, want)
	}

	// Without a known project, no ?project= suffix.
	if got := changeLink("https://sentry.io", "acme", "v1", ""); got != "https://sentry.io/organizations/acme/releases/v1/" {
		t.Errorf("changeLink no-project = %q", got)
	}
}
