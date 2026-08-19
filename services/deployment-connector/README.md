# Deployment connector

This customer-resident service makes outbound control-plane requests only. It
has no listener and no cloud dependency in the local detection path.

The connector maintains independent recurring jobs for heartbeat, aggregate
usage, entitlements, model policy, signed update manifests, and certificate
rotation. Its SQLite state preserves schedules, retry counters, cached control
documents, and idempotency keys across restarts. Retry delays use bounded
exponential backoff with jitter. Response bodies are schema-limited; heartbeat
and usage collectors permit only aggregate fields and never transmit network
events, evidence, prompts, responses, credentials, or analyst content.

Production requires HTTPS with normal server verification and the enrolled mTLS
certificate. Plain HTTP and the fingerprint compatibility header are accepted
only for an explicitly enabled loopback development control plane.
