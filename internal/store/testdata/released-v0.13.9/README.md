# Released migration baseline

`sha256.json` pins the filenames and SHA-256 contents of all migrations in
release tag `v0.13.9`. The SQL fixture is that release's migration 0013,
which must remain independent of the embedded migration selected by the
upgrade test. Earlier migrations are covered by the pinned prefix check.

Do not regenerate this baseline from a development branch when a test fails.
Append new migrations after the released sequence instead. Tests use only
these local fixtures and require no Git checkout or network access.
