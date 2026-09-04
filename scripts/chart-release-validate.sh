#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Validate the chart metadata at an application or chart release tag.
# Usage: scripts/chart-release-validate.sh <vX.Y.Z|chart-vX.Y.Z>
set -euo pipefail

fail() { echo "chart-release-validate: $*" >&2; exit 1; }

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

release_ref="${1:-}"
[ -n "$release_ref" ] \
  || fail "usage: chart-release-validate.sh <vX.Y.Z|chart-vX.Y.Z>"

chart_yaml="charts/alertint-agent/Chart.yaml"
chart_version="$(sed -n 's/^version: *//p' "$chart_yaml")"
app_version="$(sed -n 's/^appVersion: *"\{0,1\}\([^" ]*\)"\{0,1\}$/\1/p' "$chart_yaml")"
[ -n "$chart_version" ] || fail "cannot read version from $chart_yaml"
[ -n "$app_version" ] || fail "cannot read appVersion from $chart_yaml"

case "$release_ref" in
  chart-v*)
    ref_version="${release_ref#chart-v}"
    [ "$ref_version" = "$chart_version" ] \
      || fail "$release_ref does not match Chart.yaml version $chart_version"
    ;;
  v*)
    ref_version="${release_ref#v}"
    [ "$ref_version" = "$app_version" ] \
      || fail "$release_ref does not match Chart.yaml appVersion $app_version"
    ;;
  *)
    fail "release ref must be vX.Y.Z or chart-vX.Y.Z (got \"$release_ref\")"
    ;;
esac

printf '%s' "$chart_version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "Chart.yaml version must be x.y.z (got \"$chart_version\")"
printf '%s' "$app_version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "Chart.yaml appVersion must be x.y.z (got \"$app_version\")"

git rev-parse -q --verify "refs/tags/v$app_version" >/dev/null \
  || fail "referenced application tag v$app_version does not exist"

./scripts/release-notes.sh "$chart_version" charts/alertint-agent/CHANGELOG.md >/dev/null \
  || fail "chart changelog has no release notes for $chart_version"

echo "chart-release-validate: $release_ref selects chart $chart_version and app v$app_version"
