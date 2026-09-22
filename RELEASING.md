# Releasing

The v0.14 operator lifecycle is summarized in the standalone
[Situation workflow](docs/concepts/situation-workflow.html). Review it with
the RC changelog when validating operator-facing behavior.

The GitHub Release body **is** the `CHANGELOG.md` section for the version
being released. The release workflow extracts it and refuses to publish a
tag whose section is missing — so the changelog roll always happens
*before* the tag, never as an afterthought.

## Version policy

- New feature or connector → **minor** (`0.X.0`)
- Bug fixes / docs / polish only → **patch** (`0.5.X`)

There is no version constant in the source — the binary version comes from
the git tag via ldflags.

## Release candidates

Release candidates are explicitly opt-in and are cut from the reviewed
`state-controller` line. They do not use the normal stable-release command,
which switches to `main`.

1. On a release-preparation branch, roll and review the candidate notes:

   ```bash
   task release:prep VERSION=0.14.0-rc1
   task release:notes VERSION=0.14.0-rc1
   ```

2. Merge the release-preparation PR into `state-controller` after all required
   checks pass. Record its full 40-character commit SHA.

3. From a clean checkout at that exact commit, validate the publication
   without changing anything:

   ```bash
   task release:rc -- 0.14.0-rc1 <full-candidate-sha> --dry-run
   ```

4. After explicit publication approval, run the same command without
   `--dry-run`. It does not switch branches or create a commit. It creates the
   immutable `v0.14.0-rc1` tag only when `HEAD`, the expected SHA, the
   changelog section, and tag availability all agree.

   ```bash
   task release:rc -- 0.14.0-rc1 <full-candidate-sha>
   ```

The tag workflow selects `.goreleaser.rc.yaml`. It marks the GitHub release as
a prerelease, refuses latest-release promotion, and publishes only these image
tags:

```text
ghcr.io/alertint/alertint-agent:v0.14.0-rc1-amd64
ghcr.io/alertint/alertint-agent:v0.14.0-rc1-arm64
ghcr.io/alertint/alertint-agent:v0.14.0-rc1
```

It never writes `latest`, `latest-amd64`, or `latest-arm64`. RC publication
does not publish a Helm chart or change chart defaults. To evaluate the RC with
an existing supported chart, set the image tag explicitly:

```bash
helm upgrade --install alertint oci://ghcr.io/alertint/charts/alertint-agent \
  --version <installed-chart-version> \
  --set image.tag=v0.14.0-rc1
```

Before installing an RC over an existing database, create and retain a
consistent backup with the old binary. Rollback means stopping the RC,
preserving its migrated database separately, restoring that backup, and then
starting the old binary. Never open an RC-migrated database with the old
binary. See [Backup & restore](docs/getting-started/backup-restore.md).

## Cutting a release

1. **Check `[Unreleased]`** in `CHANGELOG.md`. Every merged feature should
   already have an entry there (that's the per-PR habit); tidy the prose if
   needed. Preview what the release body will look like:

   ```bash
   task release:notes VERSION=Unreleased   # preview the pending section
   ```

2. **Release:**

   ```bash
   task release -- 0.7.0
   ```

   This is the whole release, runnable from any branch: the script
   requires a clean working tree, switches to `main` and fast-forwards it,
   rolls `[Unreleased]` into a dated `0.7.0` section, prints the exact
   release body, and asks for one confirmation. On yes it commits the roll
   to `main`, tags `v0.7.0`, and pushes both.

   The roll commit is prose-only (`CHANGELOG.md` and nothing else), so it
   goes straight to `main` under the admin bypass — same policy as
   docs-only commits. CI still runs on the push. Pass `--yes` to skip the
   prompt: `task release -- 0.7.0 --yes`.

3. **The tag push does the rest.** The release workflow extracts the
   `## [0.7.0]` section into the release body, and GoReleaser builds the
   binaries, archives, and GHCR images and appends the
   `**Full Changelog**` compare link.

4. **Verify**: the release page shows the changelog prose, assets are
   attached, and `ghcr.io/alertint/alertint-agent:latest` points at the new
   version.

## Fallback: manual steps

If the direct push to `main` is rejected (no admin bypass), or you want the
roll reviewed, the pieces run individually — the old PR-based path:

```bash
task release:prep VERSION=0.7.0          # roll [Unreleased] + compare links
git checkout -b chore/changelog-0.7.0
git commit -s -am "chore: roll CHANGELOG unreleased into 0.7.0"
# push, PR, merge, then tag the merged commit:
git checkout main && git pull
task release:notes VERSION=0.7.0         # sanity: this is the release body
git tag v0.7.0 && git push origin v0.7.0
```

Creating the tag by publishing a release from the GitHub UI also works: the
UI pre-creates the release, but the workflow replaces its body with the
CHANGELOG section (`release.mode: replace`), so whatever the UI's "Generate
release notes" produced gets overwritten. Prefer the `git tag` path —
nothing misleading ever exists.

## Don'ts

- Don't use the GitHub UI's "Generate release notes" button for the body —
  it lists merged PR titles only (squash merges collapse everything into
  one line) and ignores `CHANGELOG.md`. If you publish from the UI anyway,
  the workflow overwrites the body with the CHANGELOG section.
- Don't tag before the changelog roll is on `main` — the workflow will
  fail by design (and `task release` makes this impossible).
- Don't edit the release body by hand afterwards; fix `CHANGELOG.md`
  instead and re-run the release if it matters.

## State-controller database cutover

Released v0.13.9 owns migration `0013_audit_log_kind_ts_idx.sql`.
State-controller migrations start at `0014_alert_delivery_ledger.sql` and
currently end at `0037_alertmanager_source_provenance.sql`. Released migration
files must retain their numbers and contents; a pinned release-prefix test
checks this alongside the populated v0.13.9 upgrade regression.

Take a database backup before upgrading an existing installation. Old
state-controller prerelease databases that used `0013` for the delivery
ledger are incompatible with the corrected sequence. Startup rejects that
lineage before applying migrations. Preserve the database and either restore
a backup from the released 0.13.x binary or use a fresh database for a lab/RC.
Do not edit `schema_migrations` by hand to bypass the check. A database left
partially migrated by an earlier failed release-to-prerelease upgrade must
also be restored from its released-version backup.

Validate the corrected upgrade path before distributing an RC or using one
for issue #99 acceptance. Fresh-database tests alone do not cover upgrades.
