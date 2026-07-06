# Releasing

The GitHub Release body **is** the `CHANGELOG.md` section for the version
being released. The release workflow extracts it and refuses to publish a
tag whose section is missing — so the changelog roll always happens
*before* the tag, never as an afterthought.

## Version policy

- New feature or connector → **minor** (`0.X.0`)
- Bug fixes / docs / polish only → **patch** (`0.5.X`)

There is no version constant in the source — the binary version comes from
the git tag via ldflags.

## Cutting a release

1. **Check `[Unreleased]`** in `CHANGELOG.md`. Every merged feature should
   already have an entry there (that's the per-PR habit); tidy the prose if
   needed. Preview what the release body will look like:

   ```bash
   task release:notes VERSION=Unreleased   # preview the pending section
   ```

2. **Roll the changelog** — moves `[Unreleased]` into a dated version
   section and updates the compare links:

   ```bash
   task release:prep VERSION=0.7.0
   ```

3. **Commit, PR, merge.** The roll is an ordinary change to `main`:

   ```bash
   git checkout -b chore/changelog-0.7.0
   git commit -s -am "chore: roll CHANGELOG unreleased into 0.7.0"
   ```

4. **Tag the merged commit** (pull `main` first so the tag lands on the
   commit that contains the rolled changelog):

   ```bash
   git checkout main && git pull
   task release:notes VERSION=0.7.0   # sanity: this is the release body
   git tag v0.7.0 && git push origin v0.7.0
   ```

5. **The tag push does the rest.** The release workflow extracts the
   `## [0.7.0]` section into the release body, and GoReleaser builds the
   binaries, archives, and GHCR images and appends the
   `**Full Changelog**` compare link. If the section is missing, the
   workflow fails before building anything — roll the changelog (steps
   2–3) and re-push the tag after deleting it
   (`git tag -d v0.7.0 && git push origin :v0.7.0`).

6. **Verify**: the release page shows the changelog prose, assets are
   attached, and `ghcr.io/alertint/alertint-agent:latest` points at the new
   version.

## Don'ts

- Don't use the GitHub UI's "Generate release notes" button for the body —
  it lists merged PR titles only (squash merges collapse everything into
  one line) and ignores `CHANGELOG.md`.
- Don't tag before the changelog roll is on `main` — the workflow will
  fail by design.
- Don't edit the release body by hand afterwards; fix `CHANGELOG.md`
  instead and re-run the release if it matters.
