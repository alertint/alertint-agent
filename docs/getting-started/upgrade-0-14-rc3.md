---
title: "Upgrade from v0.13.9 to v0.14.0-rc3"
description: "Back up v0.13.9, upgrade the same SQLite database to the 0.14 release candidate, verify it, and know how to roll back."
section: "Getting started"
order: 5
slug: "upgrade-0-14-rc3"
---

# Upgrade from v0.13.9 to v0.14.0-rc3

This is a release-candidate test, not a stable upgrade. These steps are for a
released v0.13.9 installation; if you run another v0.13.x version, check its
upgrade notes first. Keep one AlertINT process on the database at a time. The
new binary migrates the existing database when it starts; the old binary
cannot use the migrated database. Make a [live-safe backup](backup-restore.md)
with v0.13.9 first and keep a copy outside the container or pod. Plan a short
ingress interruption while the single agent container or pod restarts.

RC3 has a writable temporary directory for its non-root runtime user. Chart
0.2.3 also mounts temporary storage with a read-only root filesystem. No
special `/tmp` mount is needed for the RC3 Docker image. The SQLite database
itself stays on the persistent `/data` volume.

## Docker Compose walkthrough

These commands use the repository's `docker/docker-compose.yaml` and its
`/data/alertint-agent.db` path. Keep your current `.env`, configuration,
volume, and webhook routing. Substitute your database path if it differs.

1. Save your current Compose and configuration files. Check that the running
   agent is v0.13.9, then back it up while it is live:

   ```bash
   docker compose --env-file .env -f docker/docker-compose.yaml exec -T agent /alertint version
   docker compose --env-file .env -f docker/docker-compose.yaml exec -T agent \
     /alertint backup --db /data/alertint-agent.db /data/pre-upgrade-v0139.backup.db
   docker cp alertint-agent:/data/pre-upgrade-v0139.backup.db ./pre-upgrade-v0139.backup.db
   ```

   Confirm the local backup file exists and keep it. The example copies it
   out of the Docker volume so it survives a container or volume mistake.
   Keep any existing scheduled backups running after the upgrade.

2. Create `docker/rc3.local.yaml` with an explicit image tag:

   ```yaml
   services:
     agent:
       image: ghcr.io/alertint/alertint-agent:v0.14.0-rc3
   ```

3. Replace only the agent container. Compose keeps its existing data volume:

   ```bash
   docker compose --env-file .env -f docker/docker-compose.yaml \
     -f docker/rc3.local.yaml up -d --no-deps agent
   ```

4. Check the result before normal traffic resumes: `version` must print
   `0.14.0-rc3`; the agent must be healthy; audit verification must pass.
   Confirm existing Incidents and findings are still readable through MCP.
   Send one identifiable test alert through your configured source and check
   its Situation in MCP and, if enabled, its Slack root and thread. Clear the
   test alert and check recovery. A webhook's HTTP `204` means its delivery
   was durably accepted, but it is not a completed investigation.

   ```bash
   docker compose --env-file .env -f docker/docker-compose.yaml \
     -f docker/rc3.local.yaml ps agent
   docker compose --env-file .env -f docker/docker-compose.yaml \
     -f docker/rc3.local.yaml exec -T agent /alertint version
   docker compose --env-file .env -f docker/docker-compose.yaml \
     -f docker/rc3.local.yaml exec -T agent \
     /alertint verify-audit --db /data/alertint-agent.db
   ```

## Kubernetes with chart 0.2.3

The chart still defaults to v0.13.9. Back up the running database and export
the backup outside the cluster using your PVC backup method; the
[Kubernetes backup guide](backup-restore.md#staged-restore-kubernetes) explains
the chart's distroless-container constraint. Preserve your current Helm values
and Secret. Pin the RC image explicitly in your reviewed values file before
`helm upgrade`:

```yaml
image:
  tag: v0.14.0-rc3
```

Use chart version `0.2.3`; it provides `/tmp` automatically and uses a
single-replica Recreate deployment. Pass your reviewed values file (including
the image tag) to Helm and wait for the rollout:

```bash
helm upgrade my-alertint oci://ghcr.io/alertint/charts/alertint-agent \
  --version 0.2.3 -f values.yaml
kubectl rollout status deployment/my-alertint-alertint-agent
```

Replace `my-alertint` with your Helm release name and use the actual
Deployment name if you set `nameOverride` or `fullnameOverride`. Verify version,
existing records, audit, one new alert, and its recovery as in the Docker
walkthrough. Do not deploy a second replica against the same database.

## If you need to roll back

Stop RC3 and preserve its migrated database for diagnosis. Restore the
pre-upgrade backup with the **v0.13.9 binary**, then start v0.13.9. For the
Compose example above, keep the agent stopped while restoring from the
backup still on the data volume:

```bash
docker compose --env-file .env -f docker/docker-compose.yaml \
  -f docker/rc3.local.yaml stop agent
```

Change the `image` value under `services.agent` in `docker/rc3.local.yaml` to
`ghcr.io/alertint/alertint-agent:v0.13.9`, then run:

```bash
docker compose --env-file .env -f docker/docker-compose.yaml \
  -f docker/rc3.local.yaml run --rm --no-deps --entrypoint /alertint agent \
  restore --db /data/alertint-agent.db /data/pre-upgrade-v0139.backup.db
docker compose --env-file .env -f docker/docker-compose.yaml \
  -f docker/rc3.local.yaml up -d --no-deps agent
```

For Kubernetes, use the [staged-restore
procedure](backup-restore.md#staged-restore-kubernetes) with the v0.13.9
image. Alerts accepted after the backup are outside that rollback recovery
point; already-sent Slack messages cannot be undone.
