---
title: "Backup & restore"
description: "Consistent live backups of the agent's SQLite state, and a restore path that works without stopping anything but the agent itself — including on Kubernetes."
section: "Getting started"
order: 4
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

## Upgrade and rollback

For a step-by-step v0.13.9 to v0.14.0-rc3 container walkthrough, see
[Upgrade to v0.14.0-rc3](upgrade-0-14-rc3.md).

Create the backup with the version you are currently running, before starting
the new binary:

```bash
alertint backup --db /data/alertint-agent.db /backups/pre-upgrade.backup.db
```

Keep that file outside the live database path. Start the new version against
the live database and let it apply its forward migrations. Verify normal reads
and intake before removing the backup.

Rollback is a restore operation because older binaries do not understand the
new schema:

1. Stop the new AlertINT process.
2. Preserve the migrated database separately for diagnosis.
3. Restore `pre-upgrade.backup.db` with the old binary's `alertint restore`.
4. Start the old binary and verify reads and fresh intake.

Do not point an older binary at the migrated database. Alerts accepted after
the pre-upgrade backup are outside the rollback recovery point, and Slack
messages already delivered cannot be undone.

The v0.14 release line also rejects databases created by old, conflicting
state-controller prereleases before changing them. Preserve such a database
and restore a released v0.13.x backup or use a fresh database for RC testing;
do not edit `schema_migrations` by hand.

After installing, restore verifies the audit chain of the restored
database (a failure is reported loudly but does not abort — the file is
the operator's choice) and appends a `db.restore_applied` row to the
chain, so a restore is always visible in the audit history.

Restoring where no database exists yet is legal — that's how you move an
install to a new host: copy a backup over, restore, start the agent.

## Staged restore (Kubernetes)

The Helm chart runs a **Deployment** with one replica and a persistent volume.
Create a consistent backup on that volume while the agent is running. The
default Deployment name for a `my-alertint` Helm release is
`my-alertint-alertint-agent`; use your actual name if overridden:

```bash
kubectl exec deployment/my-alertint-alertint-agent -c alertint-agent -- \
  /alertint backup --db /data/alertint-agent.db /data/pre-upgrade.backup.db
```

**Export that backup outside the cluster before upgrading.** Use your PVC
snapshot/backup process or a temporary helper pod that mounts the claim. The
published AlertINT container is distroless and has no `tar`, so `kubectl cp`
directly from its pod does not work. A backup left only on the same PVC is not
enough for rollback after a volume failure. Check that the exported file is
present and readable before changing the image.

To restore, stop the agent Deployment, preserve the migrated database, and
place the old backup on its PVC at the exact path
`/data/alertint-agent.db.restore` using your storage workflow or a temporary
helper pod. Remove the helper before restarting the Deployment. Start the
**old binary** with that staged file: at startup, before opening the store,
AlertINT applies it using the same swap logic as offline restore. If you use
Helm, set the image tag back to the old version in your reviewed values file
and upgrade the release; do not start the old image against the migrated
database without staging the restore first. The chart's Deployment uses
`Recreate`, so it does not start a second agent against the same database.

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
