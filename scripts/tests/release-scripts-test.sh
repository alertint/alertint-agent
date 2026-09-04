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
  grep -Fq -- "$expected" "$file" \
    || fail "$file does not contain: $expected"
}

assert_not_contains() {
  local file="$1"
  local unexpected="$2"
  if grep -Fq -- "$unexpected" "$file"; then
    fail "$file unexpectedly contains: $unexpected"
  fi
}

new_fixture() {
  local name="$1"
  local fixture="$tmp_root/$name"

  mkdir -p "$fixture/charts/alertint-agent" "$fixture/scripts"
  cp "$repo_root/charts/alertint-agent/Chart.yaml" "$fixture/charts/alertint-agent/Chart.yaml"
  cp "$repo_root/charts/alertint-agent/CHANGELOG.md" "$fixture/charts/alertint-agent/CHANGELOG.md"
  cp "$repo_root/charts/alertint-agent/README.md" "$fixture/charts/alertint-agent/README.md"
  cp "$repo_root/scripts/release-notes.sh" "$fixture/scripts/release-notes.sh"
  cp "$repo_root/scripts/chart-release-prep.sh" "$fixture/scripts/chart-release-prep.sh"
  cp "$repo_root/scripts/chart-release-validate.sh" "$fixture/scripts/chart-release-validate.sh"
  chmod +x "$fixture/scripts/"*.sh
  printf '%s\n' "$fixture"
}

init_git_fixture() {
  local fixture="$1"
  (
    cd "$fixture"
    git init -q -b main
    git config user.name "Release Test"
    git config user.email "release-test@example.com"
    git config commit.gpgsign false
    git add .
    git commit -q -m "test fixture"
  )
}

new_release_repo() {
  local name="$1"
  local fixture="$tmp_root/$name"
  local remote="$tmp_root/$name-origin.git"

  mkdir -p "$fixture/charts/alertint-agent" "$fixture/scripts"
  cp "$repo_root/CHANGELOG.md" "$fixture/CHANGELOG.md"
  cp "$repo_root/charts/alertint-agent/Chart.yaml" "$fixture/charts/alertint-agent/Chart.yaml"
  cp "$repo_root/charts/alertint-agent/CHANGELOG.md" "$fixture/charts/alertint-agent/CHANGELOG.md"
  cp "$repo_root/charts/alertint-agent/README.md" "$fixture/charts/alertint-agent/README.md"
  cp "$repo_root/scripts/release.sh" "$fixture/scripts/release.sh"
  cp "$repo_root/scripts/release-prep.sh" "$fixture/scripts/release-prep.sh"
  cp "$repo_root/scripts/release-notes.sh" "$fixture/scripts/release-notes.sh"
  cp "$repo_root/scripts/chart-release-prep.sh" "$fixture/scripts/chart-release-prep.sh"
  cp "$repo_root/scripts/chart-release-validate.sh" "$fixture/scripts/chart-release-validate.sh"
  if [ -f "$repo_root/scripts/release-chart.sh" ]; then
    cp "$repo_root/scripts/release-chart.sh" "$fixture/scripts/release-chart.sh"
  fi
  chmod +x "$fixture/scripts/"*.sh

  git init -q --bare "$remote"
  (
    cd "$fixture"
    git init -q -b main
    git config user.name "Release Test"
    git config user.email "release-test@example.com"
    git config commit.gpgsign false
    git add .
    git commit -q -m "initial release fixture"
    git tag v0.13.7
    git remote add origin "$remote"
    git push -q origin main --tags
  )

  printf '%s\n' "$fixture"
}

add_unreleased_note() {
  local changelog="$1"
  local heading="$2"
  local note="$3"
  local tmp="$changelog.tmp"

  awk -v heading="$heading" -v note="$note" '
    { print }
    /^## \[Unreleased\]$/ {
      print ""
      print heading
      print ""
      print note
    }
  ' "$changelog" > "$tmp"
  mv "$tmp" "$changelog"
}

tests=$((tests + 1))
fixture="$(new_fixture app-bump)"
(
  cd "$fixture"
  ./scripts/chart-release-prep.sh 0.1.1 0.13.8 >/dev/null
)
assert_contains "$fixture/charts/alertint-agent/Chart.yaml" 'version: 0.1.1'
assert_contains "$fixture/charts/alertint-agent/Chart.yaml" 'appVersion: "0.13.8"'
assert_contains "$fixture/charts/alertint-agent/CHANGELOG.md" '## [0.1.1] - '
assert_contains "$fixture/charts/alertint-agent/CHANGELOG.md" 'Update the default alertint-agent image to `v0.13.8`.'
assert_contains "$fixture/charts/alertint-agent/README.md" 'Version-0.1.1-informational'
assert_contains "$fixture/charts/alertint-agent/README.md" 'AppVersion-0.13.8-informational'
pass "application release updates and documents both chart metadata versions"

tests=$((tests + 1))
fixture="$(new_fixture chart-only-bump)"
awk '
  { print }
  /^## \[Unreleased\]$/ {
    print ""
    print "### Fixed"
    print ""
    print "- Repair a chart-only template defect."
  }
' "$fixture/charts/alertint-agent/CHANGELOG.md" > "$fixture/changelog.tmp"
mv "$fixture/changelog.tmp" "$fixture/charts/alertint-agent/CHANGELOG.md"
(
  cd "$fixture"
  ./scripts/chart-release-prep.sh v0.1.1 >/dev/null
)
assert_contains "$fixture/charts/alertint-agent/Chart.yaml" 'version: 0.1.1'
assert_contains "$fixture/charts/alertint-agent/Chart.yaml" 'appVersion: "0.13.7"'
assert_contains "$fixture/charts/alertint-agent/CHANGELOG.md" '- Repair a chart-only template defect.'
assert_not_contains "$fixture/charts/alertint-agent/CHANGELOG.md" 'Update the default alertint-agent image'
pass "chart-only release preserves appVersion and rolls pending chart notes"

tests=$((tests + 1))
fixture="$(new_fixture empty-chart-release)"
if (
  cd "$fixture"
  ./scripts/chart-release-prep.sh 0.1.1
) >"$fixture/output" 2>&1; then
  fail "chart-only release accepted an empty Unreleased section"
fi
assert_contains "$fixture/output" '[Unreleased] section is empty'
pass "chart-only release rejects an empty changelog"

tests=$((tests + 1))
fixture="$(new_fixture validate-app-tag)"
(
  cd "$fixture"
  ./scripts/chart-release-prep.sh 0.1.1 0.13.8 >/dev/null
)
init_git_fixture "$fixture"
(
  cd "$fixture"
  git tag v0.13.8
  ./scripts/chart-release-validate.sh v0.13.8 >/dev/null
)
pass "application tag validation accepts matching appVersion and chart notes"

tests=$((tests + 1))
fixture="$(new_fixture validate-chart-tag)"
(
  cd "$fixture"
  ./scripts/chart-release-prep.sh 0.1.1 0.13.8 >/dev/null
)
init_git_fixture "$fixture"
(
  cd "$fixture"
  git tag v0.13.8
  git tag chart-v0.1.1
  ./scripts/chart-release-validate.sh chart-v0.1.1 >/dev/null
)
pass "chart tag validation accepts matching chart version and published app tag"

tests=$((tests + 1))
fixture="$(new_fixture reject-mismatch)"
(
  cd "$fixture"
  ./scripts/chart-release-prep.sh 0.1.1 0.13.8 >/dev/null
)
init_git_fixture "$fixture"
(
  cd "$fixture"
  git tag v0.13.8
)
if (
  cd "$fixture"
  ./scripts/chart-release-validate.sh chart-v0.1.2
) >"$fixture/output" 2>&1; then
  fail "chart tag validation accepted a mismatched Chart.yaml version"
fi
assert_contains "$fixture/output" 'does not match Chart.yaml version 0.1.1'
pass "chart tag validation rejects mismatched chart version"

tests=$((tests + 1))
fixture="$(new_fixture reject-missing-app-tag)"
(
  cd "$fixture"
  ./scripts/chart-release-prep.sh 0.1.1 0.13.8 >/dev/null
)
init_git_fixture "$fixture"
if (
  cd "$fixture"
  ./scripts/chart-release-validate.sh chart-v0.1.1
) >"$fixture/output" 2>&1; then
  fail "chart validation accepted an appVersion with no application tag"
fi
assert_contains "$fixture/output" 'referenced application tag v0.13.8 does not exist'
pass "chart validation rejects an appVersion that was never tagged"

tests=$((tests + 1))
fixture="$(new_release_repo normal-release)"
add_unreleased_note "$fixture/CHANGELOG.md" "### Changed" "- Exercise the coupled release path."
(
  cd "$fixture"
  git add CHANGELOG.md
  git commit -q -m "add pending application notes"
  git push -q origin main
  ./scripts/release.sh 0.13.8 --chart 0.1.1 --yes >release-output
)
assert_contains "$fixture/CHANGELOG.md" '## [0.13.8] - '
assert_contains "$fixture/charts/alertint-agent/Chart.yaml" 'version: 0.1.1'
assert_contains "$fixture/charts/alertint-agent/Chart.yaml" 'appVersion: "0.13.8"'
assert_contains "$fixture/release-output" 'application v0.13.8 and chart 0.1.1 tagged for publication'
(
  cd "$fixture"
  git rev-parse -q --verify refs/tags/v0.13.8 >/dev/null \
    || fail "normal release did not create v0.13.8"
  if git rev-parse -q --verify refs/tags/chart-v0.1.1 >/dev/null; then
    fail "normal release unexpectedly created a chart-only tag"
  fi
  changed="$(git diff-tree --no-commit-id --name-only -r HEAD)"
  printf '%s\n' "$changed" | grep -Fxq CHANGELOG.md \
    || fail "normal release commit omitted CHANGELOG.md"
  printf '%s\n' "$changed" | grep -Fxq charts/alertint-agent/Chart.yaml \
    || fail "normal release commit omitted Chart.yaml"
  printf '%s\n' "$changed" | grep -Fxq charts/alertint-agent/CHANGELOG.md \
    || fail "normal release commit omitted chart CHANGELOG.md"
  printf '%s\n' "$changed" | grep -Fxq charts/alertint-agent/README.md \
    || fail "normal release commit omitted generated chart README.md"
)
pass "normal release commits both metadata sets and creates only the application tag"

tests=$((tests + 1))
fixture="$(new_release_repo chart-only-release)"
add_unreleased_note "$fixture/charts/alertint-agent/CHANGELOG.md" "### Fixed" "- Exercise the chart-only release path."
(
  cd "$fixture"
  git add charts/alertint-agent/CHANGELOG.md
  git commit -q -m "add pending chart notes"
  git push -q origin main
  ./scripts/release-chart.sh 0.1.1 --yes >release-output
)
assert_contains "$fixture/charts/alertint-agent/Chart.yaml" 'version: 0.1.1'
assert_contains "$fixture/charts/alertint-agent/Chart.yaml" 'appVersion: "0.13.7"'
assert_contains "$fixture/release-output" 'chart 0.1.1 tagged for publication'
(
  cd "$fixture"
  git rev-parse -q --verify refs/tags/chart-v0.1.1 >/dev/null \
    || fail "chart-only release did not create chart-v0.1.1"
  if git rev-parse -q --verify refs/tags/v0.13.8 >/dev/null; then
    fail "chart-only release unexpectedly created an application tag"
  fi
  changed="$(git diff-tree --no-commit-id --name-only -r HEAD)"
  printf '%s\n' "$changed" | grep -Fxq charts/alertint-agent/Chart.yaml \
    || fail "chart-only release commit omitted Chart.yaml"
  if printf '%s\n' "$changed" | grep -Fxq CHANGELOG.md; then
    fail "chart-only release changed the application changelog"
  fi
)
pass "chart-only release preserves appVersion and creates only its chart tag"

tests=$((tests + 1))
fixture="$(new_release_repo bootstrap-release)"
before="$(git -C "$fixture" rev-parse HEAD)"
(
  cd "$fixture"
  ./scripts/release-chart.sh 0.1.0 --yes >release-output
)
after="$(git -C "$fixture" rev-parse HEAD)"
[ "$before" = "$after" ] || fail "bootstrap release created an empty metadata commit"
assert_contains "$fixture/release-output" 'using existing chart 0.1.0 release metadata'
(
  cd "$fixture"
  git rev-parse -q --verify refs/tags/chart-v0.1.0 >/dev/null \
    || fail "bootstrap release did not create chart-v0.1.0"
)
pass "bootstrap chart release tags existing metadata without another commit"

tests=$((tests + 1))
fixture="$(new_release_repo reused-chart-version)"
(
  cd "$fixture"
  ./scripts/chart-release-prep.sh 0.1.1 0.13.8 >/dev/null
  git add charts/alertint-agent/Chart.yaml charts/alertint-agent/CHANGELOG.md charts/alertint-agent/README.md
  git commit -q -m "prepare already-published chart metadata"
  git tag v0.13.8
  git push -q origin main --tags
)
if (
  cd "$fixture"
  ./scripts/release-chart.sh 0.1.1 --yes
) >"$fixture/output" 2>&1; then
  fail "chart-only release reused a non-bootstrap current chart version"
fi
assert_contains "$fixture/output" 'choose a new chart version'
pass "chart-only release cannot reuse a version already published by an application release"

echo "1..$tests"
