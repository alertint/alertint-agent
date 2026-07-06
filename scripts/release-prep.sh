#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Roll CHANGELOG.md [Unreleased] into a new "## [x.y.z] - YYYY-MM-DD" section
# and refresh the compare links at the bottom. Run via
# `task release:prep VERSION=<x.y.z>` before tagging a release; the release
# workflow refuses to publish a version whose section is missing.
#
# Usage: scripts/release-prep.sh <version|vversion> [changelog-path]
set -euo pipefail

version="${1:?usage: release-prep.sh <version> [changelog]}"
version="${version#v}"
changelog="${2:-CHANGELOG.md}"
repo_url="https://github.com/alertint/alertint-agent"

if ! printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "release-prep: version must be x.y.z (got \"$version\") — pass it explicitly: task release:prep VERSION=0.7.0" >&2
  exit 64
fi

if grep -q "^## \[$version\]" "$changelog"; then
  echo "release-prep: section [$version] already exists in $changelog — nothing to do" >&2
  exit 1
fi

# The [Unreleased] section must carry content; releasing nothing is a mistake.
if ! awk '/^## \[Unreleased\]/ { on = 1; next }
          on && /^## /         { exit }
          on && NF             { found = 1 }
          END                  { exit !found }' "$changelog"; then
  echo "release-prep: [Unreleased] section is empty — nothing to release" >&2
  exit 1
fi

prev="$(sed -n 's|^\[Unreleased\]: .*/compare/v\(.*\)\.\.\.HEAD$|\1|p' "$changelog")"
if [ -z "$prev" ]; then
  echo "release-prep: cannot find the [Unreleased] compare link in $changelog" >&2
  exit 1
fi

today="$(date +%Y-%m-%d)"
tmp="$(mktemp)"
awk -v ver="$version" -v date="$today" -v prev="$prev" -v url="$repo_url" '
  /^## \[Unreleased\]$/ {
    print
    print ""
    print "## [" ver "] - " date
    next
  }
  /^\[Unreleased\]: / {
    print "[Unreleased]: " url "/compare/v" ver "...HEAD"
    print "[" ver "]: " url "/compare/v" prev "...v" ver
    next
  }
  { print }
' "$changelog" > "$tmp"
mv "$tmp" "$changelog"

echo "release-prep: rolled [Unreleased] -> [$version] - $today (previous: v$prev)"
