# AegisNDR recovery, 17 October 2026

## Incident evidence

The infra account invoked `apt upgrade -y` at 2026-08-19 03:08:55 UTC.
Archived apt and dpkg logs show Docker 29.7.1 upgraded to 29.7.2;
docker-ce configuration ran 03:09:35-03:09:51 UTC. Core containers
finished at 03:09:37-03:09:47 UTC and had restart policy `no`.
A Docker daemon restart during the upgrade is the strongly supported cause;
the old daemon journal was unavailable, so the initiating stop is inferred.

## Recovery

Long-running Compose services use `unless-stopped`, including the provider mock
overlay. Provisioning jobs deliberately retain `no`. Manually stopping a service
still keeps it stopped; recreate/start it explicitly after maintenance.

Other repairs address the updater import path, the collector's required trace
exporter, stock database entrypoint permissions without added runtime capabilities,
Logto's writable migration scratch directory, TLS key access, and MinIO metrics TLS.
A Docker build ignore file prevents local dependencies and runtime secrets from
entering the build context. Frontend dependencies are patched and lockfile pinned.

The existing deployment CA now provisions vendor HTTPS server certificates and
an unregistered health probe client identity. Only its public certificate is shared
with the portal and connector. The gateway requires verified client certificates;
control-plane enrollment verifies the server before the client has an identity.
Server certificates last 90 days. Re-run pki-init and recreate the vendor services
before expiration; Docker restart policy alone does not renew certificates.

A fresh demo deployment was enrolled with operator approval; the existing data
volumes were retained. Identity private files are mode 0600, in a private directory,
owned by the unprivileged service account. No deployment credentials belong in Git.

## Verification

- General/installer Python suite: 40 tests passed.
- Backend Python suite: 171 tests passed, including a final rerun.
- Integration Python suite: 18 tests, with 9 Docker-dependent skips.
- Frontend build and Sites, dashboard, and portal tests passed.
- npm audit reported zero vulnerabilities after dependency updates.
- All 23 persistent services running; one-shot provisioning jobs exited zero.
- All 16 Prometheus targets up after the MinIO TLS repair.
- The new deployment reported online through its authenticated connector.
- The updater process was terminated from inside its container; restart count
  increased from 0 to 1 and health returned to healthy automatically.

## Remaining demo limitations

Sensors replay the deterministic packet fixture rather than capturing a live
network interface. The model provider is a mock, and the default enrolled model
policy is disabled. Logto client and organization settings are placeholders;
interactive dashboard/portal sign-in is not configured or accepted as working.
Several local service passwords remain the original development placeholders.
Replace those passwords through each backing database/service, configure Logto,
choose a live capture interface and a real provider, and validate the complete user
journey before treating this as a production deployment.

## Better maintenance procedure

Back up data and secrets privately, verify the Compose configuration and image
versions, schedule Docker package upgrades, then check every required container
and monitoring target afterward. Alert externally on container absence, stale
connector heartbeats and failed ingestion; local monitoring also stops if the
whole host is down. Keep certificate renewal and restore exercises on the
maintenance calendar. Avoid restarting the shared host daemon just to test one
application's restart policy.
