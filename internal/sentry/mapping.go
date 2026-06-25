// SPDX-License-Identifier: FSL-1.1-ALv2

package sentry

import (
	"net/url"
	"strings"

	"github.com/alertint/alertint-agent/internal/store"
)

// mapDeploy turns one Sentry deploy into a store.Change (deploys-primary). The
// project is supplied by the caller (the poller iterates per project) because
// the deploy object carries environment but not project (KTD3); this also
// guarantees a non-empty project label so the row passes validateChange. The
// environment label is included only when the deploy actually carries one — a
// nil/empty environment degrades the title to "<project> deployed <version>".
// OccurredAt is the deploy's dateFinished (the stable sort/timestamp). The
// change ID is left empty; the poller stamps the boundary key at insert.
func mapDeploy(baseURL, org, project, version string, d Deploy) store.Change {
	labels := map[string]string{}
	if project != "" {
		labels["project"] = project
	}
	env := ""
	if d.Environment != nil {
		env = strings.TrimSpace(*d.Environment)
	}
	if env != "" {
		labels["environment"] = env
	}

	title := titlePrefix(project) + " deployed " + version
	if env != "" {
		title += " to " + env
	}

	return store.Change{
		Source:     "sentry",
		Kind:       "deploy",
		Title:      title,
		Labels:     labels,
		Version:    version,
		Link:       changeLink(baseURL, org, version, project),
		OccurredAt: d.DateFinished,
	}
}

// mapRelease turns a Sentry release with no deploys into a store.Change
// (release-fallback). OccurredAt prefers dateReleased and falls back to
// dateCreated when the release was never explicitly released. The change ID is
// left empty; the poller stamps the boundary key at insert.
func mapRelease(baseURL, org, project string, r Release) store.Change {
	labels := map[string]string{}
	if project != "" {
		labels["project"] = project
	}

	occurred := r.DateCreated
	if r.DateReleased != nil {
		occurred = *r.DateReleased
	}

	return store.Change{
		Source:     "sentry",
		Kind:       "release",
		Title:      titlePrefix(project) + " released " + r.Version,
		Labels:     labels,
		Version:    r.Version,
		Link:       changeLink(baseURL, org, r.Version, project),
		OccurredAt: occurred,
	}
}

// titlePrefix is the subject of the title sentence: the project slug when known,
// otherwise a generic "sentry" so the title still reads standalone.
func titlePrefix(project string) string {
	if project == "" {
		return "sentry"
	}
	return project
}

// changeLink builds the Sentry UI permalink for a release from the host-root
// base URL (KTD6): <base>/organizations/<org>/releases/<version>/, with the
// version path-encoded and ?project= appended when known. The release object has
// no usable permalink, so we construct the link ourselves.
func changeLink(baseURL, org, version, project string) string {
	link := strings.TrimRight(baseURL, "/") +
		"/organizations/" + url.PathEscape(org) +
		"/releases/" + url.PathEscape(version) + "/"
	if project != "" {
		link += "?project=" + url.QueryEscape(project)
	}
	return link
}
