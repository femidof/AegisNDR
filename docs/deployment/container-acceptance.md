# Container acceptance gate

The open-source deployment is complete only when all checks below pass from a clean Compose project.

## Topology

- Suricata and Zeek process the same deterministic PCAP fixture without privileged host networking.
- Sensor output is written to a customer-local shared volume.
- Vector resumes from a disk buffer/checkpoint and writes normalized records to ClickHouse.
- PostgreSQL owns transactional product state; MinIO owns raw evidence and export/support objects.
- Logto issues organization-scoped identities; the API validates issuer, audience, expiry, organization, deployment access, token type, and permissions.
- Prometheus scrapes product and infrastructure health; Grafana is provisioned without anonymous access.
- Customer databases and object storage have no public host bindings.
- Only the dashboard, local API, control API, identity UI/API, and local Grafana pilot port may bind to loopback.

## Security

- Raw Suricata/Zeek records and PCAP never enter the outbound-control network.
- Cloud/control services cannot reach ClickHouse, customer PostgreSQL, MinIO, or sensor volumes.
- Default credentials are rejected by preflight; generated secret files are mode 0600.
- MinIO buckets are private and deny anonymous access.
- Model requests fail closed if retention, caching, region, certificate, schema, or redaction checks fail.
- Disabled/cloud-offline operation does not stop local sensing, ingestion, detection, cases, or audit.

## End-to-end proof

1. Start a clean stack and wait for every required service to be healthy.
2. Replay the deterministic traffic fixture.
3. Assert Suricata EVE and Zeek connection/DNS records exist locally.
4. Assert normalized events in ClickHouse carry the configured tenant and deployment identifiers.
5. Run local detection and assert a visible port-scan or DNS anomaly alert.
6. Start an investigation by alert ID.
7. Assert each assessment evidence ID exists locally.
8. Assert forbidden identifiers/payload fields are absent from the minimized transmission record.
9. Assert the transmission ledger is visible through the local API/dashboard.
10. Stop outbound-control connectivity and repeat detection to prove local continuity.

`scripts/test-container-stack.sh` is the executable form of this gate.
