\set ON_ERROR_STOP on

-- Operational state is intentionally separate from product and audit records.
-- It contains only job status, bounded retention settings, and sanitized health
-- snapshots suitable for a customer-generated support bundle.
CREATE TABLE IF NOT EXISTS local_state.retention_settings (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    clickhouse_event_days integer NOT NULL CHECK (clickhouse_event_days BETWEEN 1 AND 3650),
    postgres_event_days integer NOT NULL CHECK (postgres_event_days BETWEEN 1 AND 3650),
    minio_raw_days integer NOT NULL CHECK (minio_raw_days BETWEEN 1 AND 3650),
    minio_case_days integer NOT NULL CHECK (minio_case_days BETWEEN 1 AND 3650),
    minio_export_days integer NOT NULL CHECK (minio_export_days BETWEEN 1 AND 3650),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS local_state.operational_jobs (
    job_name text PRIMARY KEY CHECK (job_name ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
    status text NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
    last_started_at timestamptz NOT NULL,
    last_completed_at timestamptz,
    rows_affected bigint NOT NULL DEFAULT 0 CHECK (rows_affected >= 0),
    detail_code text NOT NULL CHECK (detail_code ~ '^[a-z0-9][a-z0-9_]{1,63}$'),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS local_state.operational_health_snapshots (
    sequence bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    collected_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('healthy', 'degraded')),
    evidence_json jsonb NOT NULL CHECK (jsonb_typeof(evidence_json) = 'object')
);
CREATE INDEX IF NOT EXISTS operational_health_collected
    ON local_state.operational_health_snapshots (collected_at DESC);

INSERT INTO local_state.schema_migrations (version, description)
VALUES (3, 'operational retention jobs and sanitized health evidence')
ON CONFLICT (version) DO NOTHING;
