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
# Usage: scripts/release.sh <version|vversion> [--yes]
set -euo pipefail

version="${1:?usage: release.sh <version> [--yes]}"
version="${version#v}"
assume_yes="${2:-}"

fail() { echo "release: $*" >&2; exit 1; }

printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' \
  || fail "version must be x.y.z (got \"$version\") — e.g. task release VERSION=0.7.0"

branch="$(git rev-parse --abbrev-ref HEAD)"
[ "$branch" = "main" ] || fail "must run on main (currently on \"$branch\")"
[ -z "$(git status --porcelain)" ] || fail "working tree is dirty — commit or stash first"

git fetch origin main --tags
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
  || fail "main is not in sync with origin/main — pull (or push) first"
if git rev-parse -q --verify "refs/tags/v$version" >/dev/null; then
  fail "tag v$version already exists"
fi

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
