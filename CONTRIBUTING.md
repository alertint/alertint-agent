# Contributing to AlertINT

Thanks for considering a contribution! This document covers the practical
bits: building, testing, contributing rules and docs, style, and the
sign-off requirement.

## Build and test

Requirements: Go 1.26+ and [Task](https://taskfile.dev).

```bash
task build      # build ./bin/alertint
task test       # go test -race ./...
task lint       # go vet ./...
golangci-lint run ./...   # full lint, same as CI
```

Please run tests and the linter locally before opening a PR — CI runs the
same checks and a red run only slows your review down.

## Contributing rules (the easiest way to help)

Detection rules in the [open rule schema](docs/rules-spec.md) are very
welcome in **`packs/community/`**. A good rule contribution:

1. Adds the rule under `packs/community/rules/` following the schema.
2. Adds a synthetic alert-stream fixture under
   `internal/rules/testdata/streams/` stating the expected decision —
   `go test ./internal/rules/` is the rule QA harness.
3. Uses generic, vendor-neutral labels where possible, and sets
   `applies_to` when the rule is component- or version-specific.

Strong, broadly-useful community rules may be promoted into the curated
community pack (with attribution preserved via git history).

## Contributing documentation

The `/docs` tree in this repo is the canonical source for
<https://alertint.com/docs> — the website fetches and renders it at build
time, so a docs PR here updates the published docs. The structure,
frontmatter requirements, and formatting rules (plain CommonMark, one H1
per page, code blocks with a language) are described in
[`docs/README.md`](docs/README.md). Validate before opening a PR:

```bash
task docs:validate
```

## Code style

- Match the surrounding code: standard `gofmt` formatting, doc comments on
  exported identifiers, design notes at the top of packages where the
  "why" isn't obvious.
- Error messages are lowercase, prefixed with the package or rule id, and
  actionable (`rule <id>: <field>: <reason>`).
- Validation failures should fail loud at startup, not silently at use.

## Sign-off requirement (DCO)

Every commit must carry a `Signed-off-by` trailer certifying the
[Developer Certificate of Origin](https://developercertificate.org/):

```bash
git commit -s -m "feat: my change"
```

CI rejects pull requests containing commits without a sign-off. By signing
off you certify that you have the right to submit the work under the
project license (FSL-1.1-ALv2; see [LICENSE](LICENSE)).

## Reporting security issues

Never via public issues — see [SECURITY.md](SECURITY.md).
