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
