#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# One-command release: roll the CHANGELOG, show the release body, and on
# confirmation commit the roll to main, tag, and push. The changelog roll is
# a prose-only commit, so it goes straight to main (repository admins bypass
# the main-protection ruleset; CI still runs on the push). The tag push
# triggers the release workflow, which re-validates the CHANGELOG section
# and runs GoReleaser. See RELEASING.md.
#
# Runs from any branch: switches to main and fast-forwards it first.
#
# Usage: scripts/release.sh <version|vversion> [--yes]
set -euo pipefail

fail() { echo "release: $*" >&2; exit 1; }

version="${1:-}"
[ -n "$version" ] || fail "usage: release.sh <version> [--yes] — e.g. task release -- 0.7.0"
version="${version#v}"
assume_yes="${2:-}"

printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "version must be x.y.z (got \"$version\") — e.g. task release -- 0.7.0"

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

./scripts/release-prep.sh "$version"

echo
echo "release: v$version release body:"
echo "----------------------------------------"
./scripts/release-notes.sh "$version"
echo "----------------------------------------"
echo

if [ "$assume_yes" != "--yes" ]; then
  printf 'release: commit the roll to main, tag v%s, and push? [y/N] ' "$version"
  read -r answer || answer=""
  case "$answer" in
    y | Y | yes | YES) ;;
    *)
      git checkout -- CHANGELOG.md
      fail "aborted — CHANGELOG.md restored"
      ;;
  esac
fi

git commit -s -m "chore: roll CHANGELOG unreleased into $version" -- CHANGELOG.md
git push origin main
git tag "v$version"
git push origin "v$version"

echo
echo "release: v$version tagged and pushed — the release workflow takes it from here:"
echo "  https://github.com/alertint/alertint-agent/actions/workflows/release.yml"
