# Control API

```bash
python3 apps/control-api/app.py --host 127.0.0.1 --port 8081 --reset-demo
```

This prints the one-time demo enrollment token. Enrollment, heartbeat, usage,
and certificate rotation require an `Idempotency-Key`. Post-enrollment
deployment calls use mTLS-derived identity plus tenant and deployment IDs.

Human cloud-console routes live under `/v1/portal/*`. They require a Logto
organization access token for `https://hybrid-ndr.cloud/api`; tenant and
organization scope come exclusively from signed claims. The routes cover the
current customer organization, enrollment state, deployments, health/version
and sensor status, aggregate usage, entitlements, zero-retention model policy,
signed update visibility, and support-routing metadata. Mutation audit records
store action metadata only.

The portal and gateway stores have no columns or response contracts for raw
events, packet captures, alert evidence, cases, analyst notes, prompts, or
model responses. Nested customer-content keys are rejected at the control
boundary.
