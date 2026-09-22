#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
#
# Publish one reviewed release-candidate commit without switching branches,
# preparing metadata, or invoking the stable release helper. The changelog
# section must already be reviewed on the candidate commit.
#
# Usage: scripts/release-rc.sh <x.y.z-rcN> <full-candidate-sha> [--dry-run|--yes]
set -euo pipefail

fail() { echo "release-rc: $*" >&2; exit 1; }

version="${1:-}"
expected_sha="${2:-}"
mode="${3:-}"
version="${version#v}"

printf '%s' "$version" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+-rc[1-9][0-9]*$' \
  || fail "version must be x.y.z-rcN (got \"$version\")"
printf '%s' "$expected_sha" | grep -qE '^[0-9a-f]{40}$' \
  || fail "expected candidate must be a full lowercase 40-character commit SHA"
case "$mode" in
  "" | --dry-run | --yes) ;;
  *) fail "unknown argument: $mode" ;;
esac

[ -z "$(git status --porcelain)" ] \
  || fail "working tree has uncommitted or untracked changes"

head_sha="$(git rev-parse HEAD)"
[ "$head_sha" = "$expected_sha" ] \
  || fail "HEAD $head_sha does not match expected candidate $expected_sha"

tag="v$version"
if [ "$mode" != "--dry-run" ]; then
  git fetch origin --tags
fi
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
  fail "tag $tag already exists"
fi

notes_file="$(mktemp)"
trap 'rm -f "$notes_file"' EXIT
./scripts/release-notes.sh "$version" >"$notes_file"

echo "release-rc: validated $tag at $head_sha"
echo "release-rc: release body:"
echo "----------------------------------------"
cat "$notes_file"
echo "----------------------------------------"

if [ "$mode" = "--dry-run" ]; then
  echo "release-rc: dry run: would create and push tag $tag"
  exit 0
fi

if [ "$mode" != "--yes" ]; then
  printf 'release-rc: create and push immutable tag %s at %s? [y/N] ' "$tag" "$head_sha"
  read -r answer || answer=""
  case "$answer" in
    y | Y | yes | YES) ;;
    *) fail "aborted — no tag created" ;;
  esac
fi

git tag -a "$tag" "$head_sha" -m "$tag"
if ! git push origin "refs/tags/$tag"; then
  git tag -d "$tag" >/dev/null
  fail "tag push failed; local tag removed"
fi

echo "release-rc: $tag pushed — verify the prerelease and pinned artifacts before inviting testers"
