---
title: "Backup & restore"
description: "Consistent live backups of the agent's SQLite state, and a restore path that works without stopping anything but the agent itself — including on Kubernetes."
section: "Getting started"
order: 3
slug: "backup-restore"
---

# Backup & restore

AlertINT keeps all state — incidents, findings, the audit log — in one
SQLite file. `alertint backup` snapshots it while the agent runs;
`alertint restore` puts a snapshot back.

## Backup (live-safe)

```bash
alertint backup --db /data/alertint-agent.db /backups/snap.backup.db
```

The snapshot is transactionally consistent even while the agent is
ingesting and triaging: the source is opened read-only and copied with
`VACUUM INTO`, so the running agent is never disturbed and the output is
a single compacted `.db` file with no sidecar files.

With no target argument the backup is written to the current directory as
`<db-name>-<UTC-stamp>.backup.db` (e.g.
`alertint-agent-20260728T093000Z.backup.db`). An existing target is never
overwritten without `--force`.

> **In containers:** the working directory is usually not writable — pass
> an explicit target on a writable volume, as in the example above.

Scheduling is deliberately left to tools you already run (cron, systemd
timers, Kubernetes CronJobs): AlertINT adds no scheduler, retention, or
pruning of its own.

## Restore (offline)

```bash
alertint restore --db /data/alertint-agent.db /backups/snap.backup.db
```

Restore is safe by construction:

- **Admission check** — the file must be a healthy alertint database with
  a schema this binary understands. Corrupt files, other apps' databases,
  and backups from a newer alertint are refused before anything is touched.
- **Running-agent guard** — if any process still has the database open
  (even idle), restore refuses with "agent appears to be running". Stop
  the agent, or use the staged restore below.
- **Safety copy** — the previous database is kept at
  `<db>.pre-restore` (one generation). If a restore turned out wrong,
  rename it back. Routine restore scripts that don't want it can simply
  `rm` it afterwards.
- **Atomic install** — no interruption point leaves a torn database at
  the DB path. If a restore is interrupted mid-swap, the previous
  database is intact at `<db>.pre-restore`: rename it back and retry.

After installing, restore verifies the audit chain of the restored
database (a failure is reported loudly but does not abort — the file is
the operator's choice) and appends a `db.restore_applied` row to the
chain, so a restore is always visible in the audit history.

Restoring where no database exists yet is legal — that's how you move an
install to a new host: copy a backup over, restore, start the agent.

## Staged restore (Kubernetes)

Stopping a pod to run a command against its volume is awkward. Instead,
stage the backup file next to the database and restart: at startup —
before it opens the store — the agent applies a file found at the exact
path `<db>.restore` using the same swap logic as offline restore.

Backup (live, no downtime):

```bash
kubectl exec alertint-0 -- alertint backup --db /data/alertint-agent.db /data/snap.backup.db
kubectl cp alertint-0:/data/snap.backup.db ./snap.backup.db
```

Restore (one restart — no scale-to-zero, no helper Job):

```bash
kubectl cp ./snap.backup.db alertint-0:/data/alertint-agent.db.restore
kubectl rollout restart statefulset/alertint
```

The staging file is consumed on success, so a crash-looping pod can never
re-apply an old restore. If the staged file fails the admission check,
it is set aside as `<db>.restore.rejected` (evidence preserved), the pod
exits non-zero once, and the next start serves normally on the untouched
database.

## File names

For a database at `/data/alertint-agent.db`:

| File | Meaning |
|---|---|
| `alertint-agent.db.restore` | staged restore trigger — this exact path and nothing else |
| `alertint-agent.db.pre-restore` | safety copy: the previous database, one generation |
| `alertint-agent.db.restore.rejected` | a staged file that failed the admission check |
