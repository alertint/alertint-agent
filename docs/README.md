# AlertINT documentation

This folder is the **canonical source** for all AlertINT documentation. The
website publishes a committed, concise edition at <https://alertint.com/docs>.
Update the reference here first, then synchronize the relevant changes into
the website's `docs-preview/` tree in a corresponding website PR. Its build
can also read this docs tree through an explicit `LOCAL_DOCS_PATH` override.

Because the files are rendered outside GitHub, they must be clean, portable
CommonMark: no GitHub-specific extensions (no GitHub alerts syntax such as
`> [!NOTE]`), and no relative links that assume github.com rendering.

## Layout

```text
docs/
  meta.yaml          global config: site title, section order
  README.md          this file (not rendered on the site)
  assets/            images, referenced relatively from pages
  scripts/           validation tooling (go run ./docs/scripts)
  <section-id>/      one directory per section in meta.yaml
    <page>.md        one page per file
```

Every page lives in a section directory whose name matches a section `id`
in `meta.yaml`. Top-level `.md` files are not rendered — `rules-spec.md`
is the canonical rule-pack specification and is intentionally kept at the
top level.

## Frontmatter

Every page starts with YAML frontmatter; all five fields are required:

```yaml
---
title: "Quickstart"
description: "Get AlertINT running as a single self-hosted binary."
section: "Getting started"   # must match a section title in meta.yaml
order: 1                     # position within the section
slug: "quickstart"           # unique across all docs; used in the URL
---
```

## Contribution rules

- Exactly one H1 (`#`) per file, and it must match the frontmatter `title`.
- Code blocks must declare a language (` ```yaml `, ` ```bash `,
  ` ```text `, ...).
- Images go in `docs/assets/` and are referenced relatively, e.g.
  `![data flow](../assets/data-flow.png)`.
- Slugs are unique across the whole docs tree.
- Plain CommonMark only — if it needs a GitHub extension to render, rewrite
  it.

## Validation

CI validates the docs tree on every push and pull request. To run the same
check locally:

```bash
task docs:validate
# or
go run ./docs/scripts
```

It checks frontmatter completeness, slug uniqueness, that each `section`
exists in `meta.yaml` and matches the directory the file lives in, the
single-H1 rule, and that fenced code blocks declare a language.

## Deployment

When a change under `docs/` lands on `main`, the `Docs Deploy` workflow
re-runs the validator and triggers a rebuild of <https://alertint.com/docs>.
The hook rebuilds the website; it does not update the website's committed
`docs-preview/` edition. Synchronize relevant changes in a website PR and
publish it through the site's normal workflow. The workflow can also be
started by hand from the Actions tab (`workflow_dispatch`) to force a rebuild
without a docs change.
