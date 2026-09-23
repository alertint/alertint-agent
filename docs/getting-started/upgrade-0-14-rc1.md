---
title: "Upgrade from v0.13.9 to v0.14.0-rc1"
description: "Back up v0.13.9, upgrade the same SQLite database to the 0.14 release candidate, verify it, and know how to roll back."
section: "Getting started"
order: 5
slug: "upgrade-0-14-rc1"
---

# Upgrade from v0.13.9 to v0.14.0-rc1

This is a release-candidate test, not a stable upgrade. Keep one AlertINT
process on the database at a time. The new binary migrates the existing
database when it starts; the old binary cannot use the migrated database.
Make a [live-safe backup](backup-restore.md) with v0.13.9 first and keep a
copy outside the container or pod.

**Container prerequisite for this RC:** give the agent a writable `/tmp`.
Migration 0023 creates a temporary SQLite table. The published RC1 image
does not provide `/tmp`; without a mount, startup stops with
`migration 0023_notification_reply_supersession: disk I/O error (6410)`.
The database is not lost, but the upgrade does not finish. Use a Docker
`tmpfs` or a Kubernetes `emptyDir` as shown below.

## Docker Compose walkthrough

These commands use the repository's `docker/docker-compose.yaml` and its
`/data/alertint-agent.db` path. Keep your current `.env`, configuration,
volume, and webhook routing. Substitute your database path if it differs.

1. Check that the running agent is v0.13.9, then back it up while it is live:

   ```bash
   docker compose --env-file .env -f docker/docker-compose.yaml exec -T agent /alertint version
   docker compose --env-file .env -f docker/docker-compose.yaml exec -T agent \
     /alertint backup --db /data/alertint-agent.db /data/pre-upgrade-v0139.backup.db
   docker cp alertint-agent:/data/pre-upgrade-v0139.backup.db ./pre-upgrade-v0139.backup.db
   ```

   Confirm the local backup file exists and keep it. The example copies it
   out of the Docker volume so it survives a container or volume mistake.

2. Create `docker/rc1.local.yaml` with an explicit image tag and temporary
   directory:

   ```yaml
   services:
     agent:
       image: ghcr.io/alertint/alertint-agent:v0.14.0-rc1
       tmpfs:
         - /tmp:mode=1777
   ```

3. Replace only the agent container. Compose keeps its existing data volume:

   ```bash
   docker compose --env-file .env -f docker/docker-compose.yaml \
     -f docker/rc1.local.yaml up -d --no-deps agent
   ```

4. Check the result before routing more alerts: `version` must print
   `0.14.0-rc1`; the agent must be healthy; audit verification must pass.
   Send one identifiable test alert and confirm that both the old and new
   alerts are visible in MCP. A webhook's HTTP `204` means its delivery was
   durably accepted, but it is not a completed investigation.

   ```bash
   docker compose --env-file .env -f docker/docker-compose.yaml \
     -f docker/rc1.local.yaml ps agent
   docker compose --env-file .env -f docker/docker-compose.yaml \
     -f docker/rc1.local.yaml exec -T agent /alertint version
   docker compose --env-file .env -f docker/docker-compose.yaml \
     -f docker/rc1.local.yaml exec -T agent \
     /alertint verify-audit --db /data/alertint-agent.db
   ```

## Kubernetes with chart 0.2.2

The chart still defaults to v0.13.9. Pin the RC image explicitly and add
a writable temporary volume to your reviewed values file before
`helm upgrade`:

```yaml
image:
  tag: v0.14.0-rc1
extraVolumes:
  - name: sqlite-tmp
    emptyDir: {}
extraVolumeMounts:
  - name: sqlite-tmp
    mountPath: /tmp
```

Use the [Kubernetes backup and staged-restore procedure](backup-restore.md#staged-restore-kubernetes)
for the persistent volume. Do not deploy a second replica during upgrade.

## If you need to roll back

Stop RC1, preserve its migrated database for diagnosis, then restore the
pre-upgrade backup with the **v0.13.9 binary**. Start v0.13.9 only after
the restore. The [backup and restore guide](backup-restore.md#upgrade-and-rollback)
has the commands and safety checks. Alerts accepted after the backup are
outside that rollback recovery point; already-sent Slack messages cannot
be undone.
