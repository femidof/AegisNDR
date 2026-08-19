# Architecture

## Trust-boundary-first design

```text
Customer environment
  Suricata + Zeek -> normalizer -> local event store
                                  -> detection engine
                                  -> local alert + evidence
                                  -> redaction/policy engine
                                  -> minimized package
                                         |
                                         | outbound HTTPS/mTLS only
                                         v
Vendor control plane               model gateway -> zero-retention provider
  enrollment, identity,            (no prompt/evidence persistence)
  health, licensing, updates
```

The runtime never grants the model gateway a database connection, packet-capture handle, unrestricted URL fetcher, arbitrary SQL tool, shell, or filesystem reader. Agent tools are typed and allowlisted. Every evidence claim refers to a known local evidence ID; unknown IDs and unsupported response actions are rejected.

## Runtime components

| Component | Boundary | Responsibility |
|---|---|---|
| Suricata / Zeek | Customer | Network signatures, protocol and transaction metadata |
| Vector / normalizer | Customer | Checkpointed ingestion and normalized contracts |
| ClickHouse | Customer | High-volume event analytics |
| PostgreSQL | Customer | Alerts, cases, policies, users, investigations |
| MinIO | Customer | Raw evidence, PCAP, exports and support bundles |
| Detection engine | Customer | Rules, baselines and anomaly scoring without an LLM |
| Agent runtime | Customer | Evidence retrieval, minimization and response validation |
| Logto + identity PostgreSQL | Customer | OIDC, organizations, RBAC, JWKS and local sign-in administration |
| Local dashboard/API | Customer | Analyst workflow, verified authorization and product audit trail |
| Control API | Vendor | Enrollment, licensing, health, update and policy metadata |
| Model gateway | Vendor | Approved-provider routing and zero-retention enforcement |

## Degraded modes

- Cloud unavailable: local ingestion, detection, search, dashboards, cases, and prior investigations continue. The CI offline-resilience gate (`scripts/test-offline-resilience.sh`) stops the outbound connector and proves detection checkpoints still advance, evidence is retained, and the local API/dashboard stay healthy.
- LLM unavailable: local investigation findings are retained with `assessment_status=unavailable`; alerts are never deleted or closed.
- Entitlement expired within grace period: existing local capabilities continue; model and update actions follow cached policy.
- Privacy policy unverifiable: external model calls fail closed and the attempt is audited locally.
- Air-gapped (no control plane at all): `install.sh --standalone` provisions local identity, a locally signed deployment certificate, and a local RS256 issuer; the local API serves the JWKS and issues short-lived analyst tokens.

## Tenancy

Every production API request resolves its actor, organization, internal tenant,
deployment assignments, role, and permissions from a signature-verified Logto
token. The token audience must identify the local API. Caller headers may select
only a deployment already present in the signed assignment and cannot elevate
identity or permissions. Repository methods require the tenant identifier
explicitly and include it in all reads and writes. Deployment-agent credentials
are accepted only by machine endpoints, not analyst endpoints. Header-based
identity remains available only in the explicit native demo mode.
