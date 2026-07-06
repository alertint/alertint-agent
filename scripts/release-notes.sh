#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Print the CHANGELOG.md section for one released version — the GitHub
# Release body. Fails when the section is missing, which is the release
# pipeline's guard: you cannot cut a release whose changelog was not rolled
# (run `task release:prep VERSION=<x.y.z>` first).
#
# Usage: scripts/release-notes.sh <version|vversion> [changelog-path]
set -euo pipefail

version="${1:?usage: release-notes.sh <version> [changelog]}"
version="${version#v}"
changelog="${2:-CHANGELOG.md}"

notes="$(awk -v ver="$version" '
  index($0, "## [" ver "]") == 1 { on = 1; next }
  on && /^## /                   { exit }
  on && /^\[/ && /\]: http/      { exit }
  on                             { print }
' "$changelog")"

# Trim leading and trailing blank lines.
notes="$(printf '%s' "$notes" | sed -e '/./,$!d')"

if [ -z "$notes" ]; then
  {
    echo "release-notes: no \"## [$version]\" section found in $changelog."
    echo "release-notes: roll the changelog first: task release:prep VERSION=$version"
  } >&2
  exit 1
fi

printf '%s\n' "$notes"
