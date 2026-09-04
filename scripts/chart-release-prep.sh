#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Roll the Helm chart changelog and update Chart.yaml plus the generated README
# badges. Supplying an application version is the application-coupled path; it
# also records the changed default image in the chart changelog.
#
# Usage: scripts/chart-release-prep.sh <chart-version> [app-version]
set -euo pipefail

fail() { echo "chart-release-prep: $*" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

chart_version="${1:-}"
app_version="${2:-}"
chart_version="${chart_version#v}"
app_version="${app_version#v}"

[ -n "$chart_version" ] \
  || fail "usage: chart-release-prep.sh <chart-version> [app-version]"
printf '%s' "$chart_version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "chart version must be x.y.z (got \"$chart_version\")"
if [ -n "$app_version" ]; then
  printf '%s' "$app_version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
    || fail "application version must be x.y.z (got \"$app_version\")"
fi

chart_dir="charts/alertint-agent"
chart_yaml="$chart_dir/Chart.yaml"
changelog="$chart_dir/CHANGELOG.md"
readme="$chart_dir/README.md"

current_chart_version="$(sed -n 's/^version: *//p' "$chart_yaml")"
current_app_version="$(sed -n 's/^appVersion: *"\{0,1\}\([^" ]*\)"\{0,1\}$/\1/p' "$chart_yaml")"
[ -n "$current_chart_version" ] || fail "cannot read version from $chart_yaml"
[ -n "$current_app_version" ] || fail "cannot read appVersion from $chart_yaml"

if grep -q "^## \[$chart_version\]" "$changelog"; then
  fail "section [$chart_version] already exists in $changelog"
fi

effective_app_version="${app_version:-$current_app_version}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
pending_changelog="$tmp_dir/CHANGELOG.pending.md"

if [ -n "$app_version" ] && [ "$app_version" != "$current_app_version" ]; then
  awk -v note="- Update the default alertint-agent image to \`v$app_version\`." '
    /^## \[Unreleased\]$/ { in_unreleased = 1; print; next }
    in_unreleased && /^## / {
      if (!inserted) {
        print ""
        print "### Changed"
        print ""
        print note
        print ""
        inserted = 1
      }
      in_unreleased = 0
      print
      next
    }
    in_unreleased && /^### Changed$/ && !inserted {
      print
      print ""
      print note
      inserted = 1
      next
    }
    { print }
    END {
      if (in_unreleased && !inserted) {
        print ""
        print "### Changed"
        print ""
        print note
      }
    }
  ' "$changelog" > "$pending_changelog"
else
  cp "$changelog" "$pending_changelog"
fi

if ! awk '
  /^## \[Unreleased\]$/ { in_unreleased = 1; next }
  in_unreleased && /^## / { exit }
  in_unreleased && NF && $0 !~ /^#/ { found = 1 }
  END { exit !found }
' "$pending_changelog"; then
  fail "[Unreleased] section is empty — nothing to release"
fi

today="$(date +%Y-%m-%d)"
awk -v version="$chart_version" -v date="$today" '
  /^## \[Unreleased\]$/ {
    print
    print ""
    print "## [" version "] - " date
    next
  }
  { print }
' "$pending_changelog" > "$tmp_dir/CHANGELOG.md"

awk -v chart_version="$chart_version" -v app_version="$effective_app_version" '
  /^version:/    { print "version: " chart_version; next }
  /^appVersion:/ { print "appVersion: \"" app_version "\""; next }
  { print }
' "$chart_yaml" > "$tmp_dir/Chart.yaml"

awk -v chart_version="$chart_version" -v app_version="$effective_app_version" '
  {
    gsub(/!\[Version: [0-9]+\.[0-9]+\.[0-9]+\]/,
         "![Version: " chart_version "]")
    gsub(/shields\.io\/badge\/Version-[0-9]+\.[0-9]+\.[0-9]+-informational/,
         "shields.io/badge/Version-" chart_version "-informational")
    gsub(/!\[AppVersion: [0-9]+\.[0-9]+\.[0-9]+\]/,
         "![AppVersion: " app_version "]")
    gsub(/shields\.io\/badge\/AppVersion-[0-9]+\.[0-9]+\.[0-9]+-informational/,
         "shields.io/badge/AppVersion-" app_version "-informational")
    print
  }
' "$readme" > "$tmp_dir/README.md"

grep -Fq "version: $chart_version" "$tmp_dir/Chart.yaml" \
  || fail "failed to update chart version in $chart_yaml"
grep -Fq "appVersion: \"$effective_app_version\"" "$tmp_dir/Chart.yaml" \
  || fail "failed to update appVersion in $chart_yaml"
grep -Fq "![Version: $chart_version]" "$tmp_dir/README.md" \
  || fail "failed to update chart version badge label in $readme"
grep -Fq "Version-$chart_version-informational" "$tmp_dir/README.md" \
  || fail "failed to update chart version badge in $readme"
grep -Fq "![AppVersion: $effective_app_version]" "$tmp_dir/README.md" \
  || fail "failed to update appVersion badge label in $readme"
grep -Fq "AppVersion-$effective_app_version-informational" "$tmp_dir/README.md" \
  || fail "failed to update appVersion badge in $readme"

mv "$tmp_dir/Chart.yaml" "$chart_yaml"
mv "$tmp_dir/CHANGELOG.md" "$changelog"
mv "$tmp_dir/README.md" "$readme"

echo "chart-release-prep: rolled [$chart_version] - $today (appVersion: $effective_app_version)"
