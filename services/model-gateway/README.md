# Standalone model gateway

The vendor `model-gateway` Compose service is separate from `control-api`. It
authenticates enrolled deployments, enforces entitlement and tenant model policy,
rejects sensitive or oversized evidence, calls only a configured zero-retention
and cache-disabled provider, validates schema-constrained responses, and stores
usage metadata only. It has no customer database or object-store network access.

The `.env.example` selects the deterministic provider solely for local vendor
development. Production must configure `MODEL_PROVIDER_MODE=http`, an HTTPS
provider endpoint and secret, verified zero-retention/cache controls, mTLS server
files, and a gateway signing secret supplied through the deployment secret store.

The HTTP provider adapter (`HTTPZeroRetentionProvider`) speaks verified TLS with
a pinned CA (`MODEL_PROVIDER_CA_FILE`), sends the configured authentication
header, and optionally streams OpenAI-compatible chat completions over SSE
(`MODEL_PROVIDER_STREAM=true`). Streaming responses are bounded by the same
`MODEL_PROVIDER_MAX_RESPONSE_BYTES` limit and parsed incrementally; malformed
frames, provider `error` events, and oversized streams fail closed as
`ModelUnavailable`. The live acceptance tests in `tests/backend/test_https_provider_live.py`
exercise both the buffered and streamed paths against a real TLS endpoint.
