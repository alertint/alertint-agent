#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# One-command application release: roll both changelogs, update the chart's
# independent version plus appVersion, show both release bodies, and on
# confirmation commit the deterministic release metadata to main, tag, and
# push. The tag triggers GoReleaser and then chart publication. See
# RELEASING.md.
#
# Runs from any branch: switches to main and fast-forwards it first.
#
# Usage: scripts/release.sh <version|vversion> --chart <version|vversion> [--yes]
set -euo pipefail

fail() { echo "release: $*" >&2; exit 1; }

version="${1:-}"
[ -n "$version" ] || fail "usage: release.sh <app-version> --chart <chart-version> [--yes]"
version="${version#v}"
shift

chart_version=""
assume_yes=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --chart)
      [ "$#" -ge 2 ] || fail "--chart requires a version"
      [ -z "$chart_version" ] || fail "--chart may only be provided once"
      chart_version="${2#v}"
      shift 2
      ;;
    --yes)
      assume_yes="--yes"
      shift
      ;;
    *)
      fail "unknown argument: $1"
      ;;
  esac
done

printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "application version must be x.y.z (got \"$version\")"
[ -n "$chart_version" ] \
  || fail "chart version is required — e.g. task release -- 0.14.0 --chart 0.2.0"
printf '%s' "$chart_version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "chart version must be x.y.z (got \"$chart_version\")"

[ -z "$(git status --porcelain -uno)" ] \
  || fail "working tree has uncommitted changes — commit or stash first"

git fetch origin main --tags
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  fail "tag v$version already exists"
fi

branch="$(git rev-parse --abbrev-ref HEAD)"
if [ "$branch" != "main" ]; then
  echo "release: switching to main (was on \"$branch\")"
  git checkout -q main
fi
git merge --ff-only -q origin/main \
  || fail "main and origin/main have diverged — reconcile first"
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
  || fail "main is ahead of origin/main — push (or drop) the extra commits first"

release_files=(
  CHANGELOG.md
  charts/alertint-agent/Chart.yaml
  charts/alertint-agent/CHANGELOG.md
  charts/alertint-agent/README.md
)
metadata_touched=1
restore_metadata() {
  if [ "$metadata_touched" -eq 1 ]; then
    git checkout -- "${release_files[@]}"
  fi
}
trap restore_metadata ERR INT TERM

./scripts/release-prep.sh "$version"
./scripts/chart-release-prep.sh "$chart_version" "$version"

echo
echo "release: v$version release body:"
echo "----------------------------------------"
./scripts/release-notes.sh "$version"
echo "----------------------------------------"
echo

echo "release: chart $chart_version release body:"
echo "----------------------------------------"
./scripts/release-notes.sh "$chart_version" charts/alertint-agent/CHANGELOG.md
echo "----------------------------------------"
echo

if [ "$assume_yes" != "--yes" ]; then
  printf 'release: commit app v%s + chart %s metadata to main, tag v%s, and push? [y/N] ' \
    "$version" "$chart_version" "$version"
  read -r answer || answer=""
  case "$answer" in
    y | Y | yes | YES) ;;
    *)
      restore_metadata
      metadata_touched=0
      fail "aborted — release metadata restored"
      ;;
  esac
fi

git commit -s -m "chore: prepare app v$version and chart $chart_version releases" -- "${release_files[@]}"
metadata_touched=0
trap - ERR INT TERM
git push origin main
git tag "v$version"
git push origin "v$version"

echo
echo "release: application v$version and chart $chart_version tagged for publication"
echo "release: the workflow publishes the application first, then the chart:"
echo "  https://github.com/alertint/alertint-agent/actions/workflows/release.yml"
