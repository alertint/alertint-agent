# Releasing

Application releases and Helm chart releases have independent versions, but
the normal maintainer command coordinates both so the chart is not forgotten.
The application changelog tracks application behavior; the chart changelog
tracks packaging, Kubernetes defaults, and the application version selected by
the chart.

The GitHub Release body is the matching section from the root `CHANGELOG.md`.
The release workflow refuses to publish an application tag without that
section. Chart publication has the same gate against
`charts/alertint-agent/CHANGELOG.md`.

## Version policy

Application SemVer:

- New feature or connector → **minor** (`0.X.0`)
- Bug fixes, docs, or polish only → **patch** (`0.13.X`)

Chart SemVer is decided separately:

- Breaking values or rendered-resource change → **major**
- Backward-compatible chart feature → **minor**
- Template fix, documentation fix, or application-version bump → **patch**

The versions do not need to match. For example, application `0.14.0` can ship
in chart `0.1.1`. The chart's `appVersion` records `0.14.0`; its `version`
remains `0.1.1`.

## Normal application release

1. Check `[Unreleased]` in `CHANGELOG.md`. Every merged feature should already
   have an entry there. Add chart-specific changes to
   `charts/alertint-agent/CHANGELOG.md` when there are any; it may otherwise be
   empty because the release command adds the application-version change.

   Preview the pending application notes:

   ```bash
   task release:notes VERSION=Unreleased
   ```

2. Pick the application and chart versions, then run:

   ```bash
   task release -- 0.14.0 --chart 0.1.1
   ```

   `v` prefixes are accepted on either input but are not required. Pass
   `--yes` to skip the confirmation.

3. The command requires a clean tree, switches to `main`, fast-forwards from
   `origin/main`, and prepares four release metadata files:

   - `CHANGELOG.md`
   - `charts/alertint-agent/Chart.yaml`
   - `charts/alertint-agent/CHANGELOG.md`
   - `charts/alertint-agent/README.md`

   It prints both release-note sections before asking for confirmation. On
   approval, it commits the metadata to `main`, pushes `main`, then creates and
   pushes `v0.14.0`.

   This is a deterministic release-metadata commit, not the old prose-only
   changelog commit. Repository administrators still use the documented admin
   bypass for this one release operation; CI runs on the push.

4. The `v*` tag runs `.github/workflows/release.yml` in strict order:

   1. GoReleaser publishes binaries, the GitHub Release, and multi-architecture
      images including `ghcr.io/alertint/alertint-agent:v0.14.0`.
   2. Only after GoReleaser succeeds, the reusable chart workflow validates,
      packages, and pushes chart `0.1.1` to
      `oci://ghcr.io/alertint/charts/alertint-agent`.

5. Verify both products:

   ```bash
   docker buildx imagetools inspect ghcr.io/alertint/alertint-agent:v0.14.0
   helm show chart oci://ghcr.io/alertint/charts/alertint-agent --version 0.1.1
   ```

   Also confirm the GitHub Release body and attached archives look correct.

## Chart-only release

Use this for a chart template, values, or chart documentation change that does
not require a new application build.

1. Add the change under `[Unreleased]` in
   `charts/alertint-agent/CHANGELOG.md`.
2. Pick the next chart SemVer and run:

   ```bash
   task release:chart -- 0.1.2
   ```

3. The command preserves `Chart.yaml`'s existing `appVersion`, rolls only chart
   metadata, pushes the metadata commit to `main`, and creates
   `chart-v0.1.2`. That tag runs only `.github/workflows/chart-release.yml`; it
   does not create a new application release.
4. Verify with `helm show chart` as above, using `--version 0.1.2`.

The command rejects an empty chart `[Unreleased]` section, an existing chart
tag, or a chart whose `appVersion` does not have a corresponding application
tag.

## First chart publication

Chart `0.1.0` was merged with its version and changelog section already rolled,
before OCI publication existed. After this automation reaches `main`, publish
it with:

```bash
task release:chart -- 0.1.0
```

The command recognizes the existing `0.1.0` metadata, shows its release notes,
and creates `chart-v0.1.0` without manufacturing an empty commit.

GHCR creates a package as private by default. After this first push, open the
new `charts/alertint-agent` package under the AlertINT organization, enter
**Package settings**, and change its visibility to **Public**. This is a
one-time action and cannot be reversed, so confirm the package name before
accepting GitHub's visibility warning. The workflow publishes with
`GITHUB_TOKEN`, which links the package back to this repository automatically.

Then smoke-check it without registry credentials:

```bash
helm show chart oci://ghcr.io/alertint/charts/alertint-agent --version 0.1.0
helm template smoke oci://ghcr.io/alertint/charts/alertint-agent \
  --version 0.1.0 \
  --set secret.enabled=false \
  --set persistence.enabled=false >/dev/null
```

Artifact Hub registration can follow after this first artifact exists and is
installable; it is discovery metadata, not part of cutting releases.

## Failure and fallback

- If GoReleaser fails, fix or rerun it first. The chart job cannot start until
  the application release job succeeds.
- If only chart publication fails, rerun the failed chart job. Do not bump a
  version merely to retry an artifact that was never published.
- OCI chart versions are immutable. If the chart was successfully pushed and
  later needs a correction, make the correction under `[Unreleased]` and cut a
  new chart version.
- If direct `main` push is rejected or the metadata should be reviewed, run the
  preparation pieces on a branch, open a PR, merge it, then create the tag from
  the merged commit:

  ```bash
  task release:prep VERSION=0.14.0
  ./scripts/chart-release-prep.sh 0.1.1 0.14.0
  git checkout -b chore/releases-0.14.0-0.1.1
  git add CHANGELOG.md charts/alertint-agent/Chart.yaml \
    charts/alertint-agent/CHANGELOG.md charts/alertint-agent/README.md
  git commit -s -m "chore: prepare app v0.14.0 and chart 0.1.1 releases"
  # Push, open/merge the PR, update local main, then:
  git tag v0.14.0
  git push origin v0.14.0
  ```

For a reviewed chart-only fallback, run
`task release:chart:prep VERSION=0.1.2`, commit the three chart metadata files,
merge them, then tag the merged commit with `chart-v0.1.2`.

## Don'ts

- Don't tag before the matching changelog and chart metadata are on `main`.
- Don't publish the chart manually before the application image exists.
- Don't reuse or overwrite an OCI chart version.
- Don't use the GitHub UI's generated release notes as the application release
  body; the workflow intentionally replaces them with `CHANGELOG.md`.
- Don't edit a published release body by hand. Fix the changelog source and
  rerun the failed workflow when appropriate.
