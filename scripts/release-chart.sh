#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# One-command chart-only release. It preserves Chart.yaml appVersion, rolls
# chart release metadata when needed, and pushes a chart-vX.Y.Z tag. If the
# requested metadata already exists (the initial 0.1.0 bootstrap), it tags the
# existing main commit without manufacturing an empty release commit.
#
# Usage: scripts/release-chart.sh <version|vversion> [--yes]
set -euo pipefail

fail() { echo "release-chart: $*" >&2; exit 1; }

chart_version="${1:-}"
[ -n "$chart_version" ] \
  || fail "usage: release-chart.sh <chart-version> [--yes]"
chart_version="${chart_version#v}"
shift

assume_yes=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --yes)
      assume_yes="--yes"
      shift
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

printf '%s' "$chart_version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "chart version must be x.y.z (got \"$chart_version\")"

[ -z "$(git status --porcelain -uno)" ] \
  || fail "working tree has uncommitted changes — commit or stash first"

git fetch origin main --tags
if git rev-parse -q --verify "refs/tags/chart-v$chart_version" >/dev/null; then
  fail "tag chart-v$chart_version already exists"
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$branch" != "main" ]; then
  echo "release-chart: switching to main (was on \"$branch\")"
  git checkout -q main
fi
git merge --ff-only -q origin/main \
  || fail "main and origin/main have diverged — reconcile first"
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
  || fail "main is ahead of origin/main — push (or drop) the extra commits first"

chart_yaml="charts/alertint-agent/Chart.yaml"
current_chart_version="$(sed -n 's/^version: *//p' "$chart_yaml")"
app_version="$(sed -n 's/^appVersion: *"\{0,1\}\([^" ]*\)"\{0,1\}$/\1/p' "$chart_yaml")"
[ -n "$current_chart_version" ] || fail "cannot read version from $chart_yaml"
[ -n "$app_version" ] || fail "cannot read appVersion from $chart_yaml"
git rev-parse -q --verify "refs/tags/v$app_version" >/dev/null \
  || fail "referenced application tag v$app_version does not exist"

release_files=(
  charts/alertint-agent/Chart.yaml
  charts/alertint-agent/CHANGELOG.md
  charts/alertint-agent/README.md
)
metadata_touched=0
restore_metadata() {
  if [ "$metadata_touched" -eq 1 ]; then
    git checkout -- "${release_files[@]}"
  fi
}
trap restore_metadata ERR INT TERM

if [ "$chart_version" = "$current_chart_version" ]; then
  [ "$chart_version" = "0.1.0" ] \
    || fail "chart $chart_version is already current — choose a new chart version"
  ./scripts/release-notes.sh "$chart_version" charts/alertint-agent/CHANGELOG.md >/dev/null
  echo "release-chart: using existing chart $chart_version release metadata"
else
  metadata_touched=1
  ./scripts/chart-release-prep.sh "$chart_version"
fi

echo
echo "release-chart: chart $chart_version release body:"
echo "----------------------------------------"
./scripts/release-notes.sh "$chart_version" charts/alertint-agent/CHANGELOG.md
echo "----------------------------------------"
echo

if [ "$assume_yes" != "--yes" ]; then
  printf 'release-chart: commit metadata if needed, tag chart-v%s, and push? [y/N] ' "$chart_version"
  read -r answer || answer=""
  case "$answer" in
    y | Y | yes | YES) ;;
    *)
      restore_metadata
      metadata_touched=0
      fail "aborted — chart release metadata restored"
      ;;
  esac
fi

if [ "$metadata_touched" -eq 1 ]; then
  git commit -s -m "chore: prepare chart $chart_version release" -- "${release_files[@]}"
  metadata_touched=0
  git push origin main
fi
trap - ERR INT TERM

git tag "chart-v$chart_version"
git push origin "chart-v$chart_version"

echo
echo "release-chart: chart $chart_version tagged for publication"
echo "release-chart: the chart workflow takes it from here:"
echo "  https://github.com/alertint/alertint-agent/actions/workflows/chart-release.yml"
