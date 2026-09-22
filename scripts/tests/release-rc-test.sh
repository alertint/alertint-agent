#!/usr/bin/env bash
# SPDX-License-Identifier: FSL-1.1-ALv2
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp_root="$(mktemp -d)"
trap 'rm -rf "$tmp_root"' EXIT

tests=0

fail() {
  echo "not ok $tests - $*" >&2
  exit 1
}

pass() {
  echo "ok $tests - $*"
}

assert_contains() {
  local file="$1"
  local expected="$2"
  grep -Fq -- "$expected" "$file" || fail "$file does not contain: $expected"
}

new_changelog() {
  local path="$1"
  cat >"$path" <<'EOF'
# Changelog

## [Unreleased]

### Added

- Candidate feature.

## [0.13.9] - 2026-09-16

- Previous release.

[Unreleased]: https://github.com/alertint/alertint-agent/compare/v0.13.9...HEAD
[0.13.9]: https://github.com/alertint/alertint-agent/compare/v0.13.8...v0.13.9
EOF
}

tests=$((tests + 1))
changelog="$tmp_root/CHANGELOG.md"
new_changelog "$changelog"
"$repo_root/scripts/release-prep.sh" 0.14.0-rc1 "$changelog" >"$tmp_root/prep-output"
assert_contains "$changelog" "## [0.14.0-rc1] - "
assert_contains "$changelog" "[Unreleased]: https://github.com/alertint/alertint-agent/compare/v0.14.0-rc1...HEAD"
assert_contains "$changelog" "[0.14.0-rc1]: https://github.com/alertint/alertint-agent/compare/v0.13.9...v0.14.0-rc1"
"$repo_root/scripts/release-notes.sh" v0.14.0-rc1 "$changelog" >"$tmp_root/notes"
assert_contains "$tmp_root/notes" "- Candidate feature."
pass "RC changelog preparation and exact note extraction"

tests=$((tests + 1))
for invalid in 0.14.0-rc 0.14.0-rc0 0.14.0-RC1 0.14.0-rc1-extra; do
  new_changelog "$changelog"
  if "$repo_root/scripts/release-prep.sh" "$invalid" "$changelog" >"$tmp_root/output" 2>&1; then
    fail "release-prep accepted malformed RC version $invalid"
  fi
done
pass "malformed RC versions are rejected"

tests=$((tests + 1))
new_changelog "$changelog"
"$repo_root/scripts/release-prep.sh" 0.14.0-rc1 "$changelog" >/dev/null
if "$repo_root/scripts/release-prep.sh" 0.14.0-rc1 "$changelog" >"$tmp_root/output" 2>&1; then
  fail "release-prep accepted an existing RC section"
fi
assert_contains "$tmp_root/output" "section [0.14.0-rc1] already exists"
pass "existing RC versions are rejected"

new_release_repo() {
  local name="$1"
  local fixture="$tmp_root/$name"
  mkdir -p "$fixture/scripts"
  cp "$repo_root/scripts/release-rc.sh" "$fixture/scripts/release-rc.sh"
  cp "$repo_root/scripts/release-notes.sh" "$fixture/scripts/release-notes.sh"
  chmod +x "$fixture/scripts/"*.sh
  new_changelog "$fixture/CHANGELOG.md"
  "$repo_root/scripts/release-prep.sh" 0.14.0-rc1 "$fixture/CHANGELOG.md" >/dev/null
  (
    cd "$fixture"
    git init -q -b candidate
    git config user.name "Release Test"
    git config user.email "release-test@example.com"
    git config commit.gpgsign false
    git add .
    git commit -q -m "candidate"
  )
  printf '%s\n' "$fixture"
}

tests=$((tests + 1))
fixture="$(new_release_repo exact-candidate)"
head="$(git -C "$fixture" rev-parse HEAD)"
(
  cd "$fixture"
  ./scripts/release-rc.sh v0.14.0-rc1 "$head" --dry-run >"$tmp_root/exact-output"
)
assert_contains "$tmp_root/exact-output" "validated v0.14.0-rc1 at $head"
assert_contains "$tmp_root/exact-output" "dry run: would create and push tag v0.14.0-rc1"
if git -C "$fixture" rev-parse -q --verify refs/tags/v0.14.0-rc1 >/dev/null; then
  fail "dry run created the tag"
fi
pass "RC publication validates the exact candidate without mutation"

tests=$((tests + 1))
fixture="$(new_release_repo reject-wrong-sha)"
head="$(git -C "$fixture" rev-parse HEAD)"
wrong="0000000000000000000000000000000000000000"
if (cd "$fixture" && ./scripts/release-rc.sh 0.14.0-rc1 "$wrong" --dry-run) >"$tmp_root/wrong-output" 2>&1; then
  fail "RC publication accepted the wrong candidate SHA"
fi
assert_contains "$tmp_root/wrong-output" "does not match expected candidate"
pass "RC publication rejects the wrong candidate SHA"

tests=$((tests + 1))
fixture="$(new_release_repo reject-stable)"
head="$(git -C "$fixture" rev-parse HEAD)"
if (cd "$fixture" && ./scripts/release-rc.sh 0.14.0 "$head" --dry-run) >"$tmp_root/stable-output" 2>&1; then
  fail "RC publication accepted a stable version"
fi
assert_contains "$tmp_root/stable-output" "version must be x.y.z-rcN"
pass "RC publication rejects stable versions"

tests=$((tests + 1))
fixture="$(new_release_repo reject-existing-tag)"
head="$(git -C "$fixture" rev-parse HEAD)"
git -C "$fixture" tag v0.14.0-rc1
if (cd "$fixture" && ./scripts/release-rc.sh 0.14.0-rc1 "$head" --dry-run) >"$tmp_root/tag-output" 2>&1; then
  fail "RC publication accepted an existing tag"
fi
assert_contains "$tmp_root/tag-output" "tag v0.14.0-rc1 already exists"
pass "RC publication rejects an existing tag"

echo "1..$tests"
