\set ON_ERROR_STOP on

-- PostgreSQL is the durable state store. High-volume network telemetry remains
-- in ClickHouse; the events table below stores only normalized event metadata
-- needed by product workflows and local development adapters.
CREATE SCHEMA IF NOT EXISTS local_state;
CREATE SCHEMA IF NOT EXISTS control_plane;

REVOKE CREATE ON SCHEMA public FROM PUBLIC;

CREATE TABLE IF NOT EXISTS local_state.schema_migrations (
    version bigint PRIMARY KEY,
    description text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS local_state.events (
    event_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    event_time timestamptz NOT NULL,
    event_type text NOT NULL,
    source text NOT NULL,
    src_ip inet,
    dst_ip inet,
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object')
);
CREATE INDEX IF NOT EXISTS events_tenant_time
    ON local_state.events (tenant_id, deployment_id, event_time DESC);
CREATE INDEX IF NOT EXISTS events_tenant_type_time
    ON local_state.events (tenant_id, deployment_id, event_type, event_time DESC);

CREATE TABLE IF NOT EXISTS local_state.alerts (
    alert_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    created_at timestamptz NOT NULL,
    severity text NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status text NOT NULL CHECK (status IN ('open', 'triaged', 'investigating', 'resolved', 'dismissed')),
    entity_id text NOT NULL,
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
    UNIQUE (tenant_id, deployment_id, alert_id)
);
CREATE INDEX IF NOT EXISTS alerts_tenant_created
    ON local_state.alerts (tenant_id, deployment_id, created_at DESC);
CREATE INDEX IF NOT EXISTS alerts_tenant_status
    ON local_state.alerts (tenant_id, deployment_id, status, severity, created_at DESC);

-- Detection state is intentionally local. Checkpoints make scheduled jobs
-- restart-safe, fingerprints make overlapping windows idempotent, and evidence
-- snapshots keep every alert explainable even if high-volume retention expires.
CREATE TABLE IF NOT EXISTS local_state.detection_checkpoints (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    job_name text NOT NULL,
    completed_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, deployment_id, job_name)
);

CREATE TABLE IF NOT EXISTS local_state.detection_alert_keys (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    fingerprint text NOT NULL CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    alert_id text NOT NULL,
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, fingerprint),
    FOREIGN KEY (tenant_id, deployment_id, alert_id)
        REFERENCES local_state.alerts(tenant_id, deployment_id, alert_id)
        DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE IF NOT EXISTS local_state.alert_evidence (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    alert_id text NOT NULL,
    event_id text NOT NULL,
    event_time timestamptz NOT NULL,
    event_type text NOT NULL,
    source text NOT NULL,
    community_id text NOT NULL,
    raw_reference text NOT NULL,
    snapshot_json jsonb NOT NULL CHECK (jsonb_typeof(snapshot_json) = 'object'),
    PRIMARY KEY (tenant_id, deployment_id, alert_id, event_id),
    FOREIGN KEY (tenant_id, deployment_id, alert_id)
        REFERENCES local_state.alerts(tenant_id, deployment_id, alert_id)
);
CREATE INDEX IF NOT EXISTS alert_evidence_event_id
    ON local_state.alert_evidence (tenant_id, deployment_id, event_id);

CREATE TABLE IF NOT EXISTS local_state.investigations (
    investigation_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    alert_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('running', 'completed', 'failed', 'unavailable', 'rejected')),
    response_json jsonb CHECK (response_json IS NULL OR jsonb_typeof(response_json) = 'object'),
    error_code text,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, deployment_id, investigation_id),
    FOREIGN KEY (tenant_id, deployment_id, alert_id)
        REFERENCES local_state.alerts(tenant_id, deployment_id, alert_id)
);
CREATE INDEX IF NOT EXISTS investigations_tenant_created
    ON local_state.investigations (tenant_id, deployment_id, created_at DESC);

CREATE TABLE IF NOT EXISTS local_state.model_transmissions (
    transmission_id text PRIMARY KEY,
    request_id text NOT NULL,
    investigation_id text NOT NULL,
    alert_id text NOT NULL,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    actor_id text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    retention_mode text NOT NULL,
    region text NOT NULL,
    fields_included_json jsonb NOT NULL CHECK (jsonb_typeof(fields_included_json) = 'array'),
    fields_removed_json jsonb NOT NULL CHECK (jsonb_typeof(fields_removed_json) = 'array'),
    fields_tokenized_json jsonb NOT NULL CHECK (jsonb_typeof(fields_tokenized_json) = 'array'),
    prompt_hash text NOT NULL,
    response_hash text NOT NULL,
    input_tokens integer NOT NULL CHECK (input_tokens >= 0),
    output_tokens integer NOT NULL CHECK (output_tokens >= 0),
    latency_ms integer NOT NULL CHECK (latency_ms >= 0),
    result text NOT NULL,
    error_code text,
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, deployment_id, investigation_id)
        REFERENCES local_state.investigations(tenant_id, deployment_id, investigation_id),
    FOREIGN KEY (tenant_id, deployment_id, alert_id)
        REFERENCES local_state.alerts(tenant_id, deployment_id, alert_id)
);
CREATE INDEX IF NOT EXISTS transmissions_tenant_created
    ON local_state.model_transmissions (tenant_id, deployment_id, created_at DESC);

CREATE TABLE IF NOT EXISTS local_state.cases (
    case_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    title text NOT NULL,
    status text NOT NULL,
    priority text NOT NULL,
    assignee text NOT NULL,
    alert_ids_json jsonb NOT NULL CHECK (jsonb_typeof(alert_ids_json) = 'array'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, case_id)
);
CREATE INDEX IF NOT EXISTS cases_tenant_updated
    ON local_state.cases (tenant_id, deployment_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS local_state.case_comments (
    comment_id text PRIMARY KEY,
    case_id text NOT NULL,
    tenant_id text NOT NULL,
    actor_id text NOT NULL,
    body text NOT NULL CHECK (length(body) BETWEEN 1 AND 10000),
    created_at timestamptz NOT NULL,
    FOREIGN KEY (tenant_id, case_id)
        REFERENCES local_state.cases(tenant_id, case_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS case_comments_tenant_case
    ON local_state.case_comments (tenant_id, case_id, created_at);

CREATE TABLE IF NOT EXISTS local_state.sensors (
    sensor_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    sensor_type text NOT NULL,
    status text NOT NULL,
    events_per_second double precision NOT NULL CHECK (events_per_second >= 0),
    last_seen timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS sensors_tenant_status
    ON local_state.sensors (tenant_id, deployment_id, status, last_seen DESC);

CREATE TABLE IF NOT EXISTS local_state.model_policies (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    policy_id text NOT NULL,
    level text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    region text NOT NULL,
    retention_mode text NOT NULL,
    enabled boolean NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id)
);

CREATE TABLE IF NOT EXISTS local_state.entity_baselines (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    entity_id text NOT NULL,
    baseline_json jsonb NOT NULL CHECK (jsonb_typeof(baseline_json) = 'object'),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, entity_id)
);

CREATE TABLE IF NOT EXISTS local_state.detection_rules (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    rule_id text NOT NULL,
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, rule_id)
);

CREATE TABLE IF NOT EXISTS local_state.detection_suppressions (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    suppression_id text NOT NULL,
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, suppression_id)
);
CREATE INDEX IF NOT EXISTS detection_suppressions_updated
    ON local_state.detection_suppressions (tenant_id, deployment_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS local_state.integrations (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    integration_id text NOT NULL,
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
    secret_json jsonb NOT NULL CHECK (jsonb_typeof(secret_json) = 'object'),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, integration_id)
);

CREATE TABLE IF NOT EXISTS local_state.system_settings (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    settings_json jsonb NOT NULL CHECK (jsonb_typeof(settings_json) = 'object'),
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id)
);

CREATE TABLE IF NOT EXISTS local_state.evidence_exports (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    export_id text NOT NULL,
    status text NOT NULL CHECK (status IN ('pending_approval', 'approved', 'rejected')),
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
    export_json jsonb CHECK (export_json IS NULL OR jsonb_typeof(export_json) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, export_id)
);
CREATE INDEX IF NOT EXISTS evidence_exports_created
    ON local_state.evidence_exports (tenant_id, deployment_id, created_at DESC);

CREATE TABLE IF NOT EXISTS local_state.support_bundles (
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    bundle_id text NOT NULL,
    payload_json jsonb NOT NULL CHECK (jsonb_typeof(payload_json) = 'object'),
    bundle_json jsonb NOT NULL CHECK (jsonb_typeof(bundle_json) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id, bundle_id)
);
CREATE INDEX IF NOT EXISTS support_bundles_created
    ON local_state.support_bundles (tenant_id, deployment_id, created_at DESC);

CREATE TABLE IF NOT EXISTS local_state.audit_events (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    audit_id text NOT NULL UNIQUE,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    actor_id text NOT NULL,
    actor_type text NOT NULL CHECK (actor_type IN ('human', 'service', 'system')),
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    request_id text NOT NULL,
    result text NOT NULL CHECK (result IN ('success', 'failure', 'denied')),
    created_at timestamptz NOT NULL,
    metadata_json jsonb NOT NULL CHECK (jsonb_typeof(metadata_json) = 'object'),
    previous_hash text NOT NULL CHECK (previous_hash ~ '^[0-9a-f]{64}$'),
    record_hash text NOT NULL UNIQUE CHECK (record_hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX IF NOT EXISTS audit_tenant_sequence
    ON local_state.audit_events (tenant_id, deployment_id, sequence DESC);

CREATE OR REPLACE FUNCTION local_state.reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit records are append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_no_update ON local_state.audit_events;
CREATE TRIGGER audit_events_no_update
    BEFORE UPDATE ON local_state.audit_events
    FOR EACH ROW EXECUTE FUNCTION local_state.reject_audit_mutation();

DROP TRIGGER IF EXISTS audit_events_no_delete ON local_state.audit_events;
CREATE TRIGGER audit_events_no_delete
    BEFORE DELETE ON local_state.audit_events
    FOR EACH ROW EXECUTE FUNCTION local_state.reject_audit_mutation();

CREATE TABLE IF NOT EXISTS control_plane.schema_migrations (
    version bigint PRIMARY KEY,
    description text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS control_plane.enrollment_tokens (
    token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    enrollment_id text UNIQUE,
    tenant_id text NOT NULL,
    deployment_name text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    entitlements_json jsonb NOT NULL CHECK (jsonb_typeof(entitlements_json) = 'object'),
    model_policy_json jsonb NOT NULL CHECK (jsonb_typeof(model_policy_json) = 'object'),
    update_channel text NOT NULL,
    created_at timestamptz,
    identity_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(identity_json) = 'object')
);
CREATE INDEX IF NOT EXISTS enrollment_tokens_expiry
    ON control_plane.enrollment_tokens (expires_at) WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS control_plane.deployments (
    deployment_id text PRIMARY KEY,
    tenant_id text NOT NULL,
    deployment_name text NOT NULL,
    status text NOT NULL,
    installed_version text NOT NULL,
    update_channel text NOT NULL,
    certificate_fingerprint text NOT NULL,
    certificate_expires_at timestamptz NOT NULL,
    last_seen timestamptz,
    health_json jsonb NOT NULL CHECK (jsonb_typeof(health_json) = 'object'),
    usage_json jsonb NOT NULL CHECK (jsonb_typeof(usage_json) = 'object'),
    entitlements_json jsonb NOT NULL CHECK (jsonb_typeof(entitlements_json) = 'object'),
    model_policy_json jsonb NOT NULL CHECK (jsonb_typeof(model_policy_json) = 'object'),
    support_json jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(support_json) = 'object'),
    created_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS deployments_tenant
    ON control_plane.deployments (tenant_id, deployment_id);
CREATE INDEX IF NOT EXISTS deployments_last_seen
    ON control_plane.deployments (status, last_seen DESC);

CREATE TABLE IF NOT EXISTS control_plane.organizations (
    tenant_id text PRIMARY KEY,
    organization_id text NOT NULL UNIQUE,
    name text NOT NULL,
    support_json jsonb NOT NULL CHECK (jsonb_typeof(support_json) = 'object'),
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL
);

CREATE TABLE IF NOT EXISTS control_plane.software_releases (
    channel text NOT NULL,
    version text NOT NULL,
    artifact text NOT NULL,
    published_at timestamptz NOT NULL,
    release_notes_url text NOT NULL,
    PRIMARY KEY (channel, version)
);

CREATE TABLE IF NOT EXISTS control_plane.control_audit (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    tenant_id text NOT NULL,
    organization_id text NOT NULL,
    actor_id text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    timestamp timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS control_audit_tenant_sequence
    ON control_plane.control_audit (tenant_id, sequence DESC);

CREATE TABLE IF NOT EXISTS control_plane.idempotency_records (
    operation text NOT NULL,
    idempotency_key text NOT NULL,
    response_json jsonb NOT NULL CHECK (jsonb_typeof(response_json) = 'object'),
    created_at timestamptz NOT NULL,
    PRIMARY KEY (operation, idempotency_key)
);
CREATE INDEX IF NOT EXISTS idempotency_records_created
    ON control_plane.idempotency_records (created_at);

CREATE TABLE IF NOT EXISTS control_plane.gateway_usage (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    request_id text NOT NULL,
    tenant_id text NOT NULL,
    deployment_id text NOT NULL,
    provider text NOT NULL,
    model text NOT NULL,
    status text NOT NULL,
    error_code text,
    input_tokens integer NOT NULL CHECK (input_tokens >= 0),
    output_tokens integer NOT NULL CHECK (output_tokens >= 0),
    latency_ms integer NOT NULL CHECK (latency_ms >= 0),
    timestamp timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS gateway_usage_tenant_timestamp
    ON control_plane.gateway_usage (tenant_id, deployment_id, timestamp DESC);

INSERT INTO local_state.schema_migrations (version, description)
VALUES (1, 'initial durable product state')
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_plane.schema_migrations (version, description)
VALUES (1, 'initial control-plane state')
ON CONFLICT (version) DO NOTHING;

INSERT INTO control_plane.software_releases
    (channel, version, artifact, published_at, release_notes_url)
VALUES (
    'stable',
    '0.1.0',
    'registry.example/hybrid-ndr@sha256:0000000000000000000000000000000000000000000000000000000000000000',
    '2026-08-05T00:00:00Z',
    'https://docs.example.invalid/releases/0.1.0'
)
ON CONFLICT (channel, version) DO NOTHING;

INSERT INTO control_plane.schema_migrations (version, description)
VALUES (2, 'organization-scoped cloud management metadata')
ON CONFLICT (version) DO NOTHING;
