# Backend MVP

The native runnable MVP uses the Python standard library and SQLite so the evidence-first workflow works on a clean host. The customer container pins `psycopg` and uses PostgreSQL, ClickHouse, and MinIO for durable product I/O. Pure API handlers are wrapped with WSGI and the boundary contracts perform strict schema validation.

Run the complete backend test suite:

```bash
bash scripts/test-backend.sh
```

Run the local customer API with deterministic demo data:

```bash
python3 apps/local-api/app.py --host 127.0.0.1 --port 8080 --reset-demo
```

Run the vendor control API and create the deterministic one-time demo token:

```bash
python3 apps/control-api/app.py --host 127.0.0.1 --port 8081 --reset-demo
```

Both APIs expose `/healthz`, emit human-readable JSON error envelopes, and allow the standard local Vite/Next preview origins. Native demo-mode local product endpoints require tenant, deployment, actor, and role headers. The Compose profile instead requires a verified Logto organization access token; caller-controlled actor and role headers grant no authority. Control-plane deployment calls require the enrollment-issued certificate fingerprint and tenant/deployment headers.

`PERSISTENCE_PROFILE=demo` selects SQLite plus a local evidence directory.
`PERSISTENCE_PROFILE=production` selects explicit PostgreSQL (`local_state`
schema), ClickHouse (`hybrid_ndr` database), and MinIO evidence-bucket ports.
Their schema/database/bucket checks are included in `/healthz` and can be made
required with `PERSISTENCE_READINESS_REQUIRED=true`. In production, operational
state and the append-only audit chain are stored in PostgreSQL, event ingest,
search, timelines, and computed baselines use ClickHouse, and evidence objects
use tenant/deployment-prefixed MinIO keys with SHA-256 integrity metadata. Every
production point lookup is tenant-and-deployment scoped; there is no SQLite
fallback. `--reset-demo` is intentionally rejected for this profile.

The real-backend acceptance test is opt-in because it writes isolated UUID data
to all three services. Run it from a container attached to the customer Compose
network with `RUN_PRODUCTION_PERSISTENCE_TESTS=1`:

```bash
python3 -m unittest -v tests.integration.test_production_persistence
```
