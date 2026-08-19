CREATE DATABASE IF NOT EXISTS hybrid_ndr;

CREATE TABLE IF NOT EXISTS hybrid_ndr.network_events
(
  tenant_id UUID,
  deployment_id UUID,
  event_id UUID,
  event_time DateTime64(3, 'UTC'),
  ingested_at DateTime64(3, 'UTC'),
  source LowCardinality(String),
  event_type LowCardinality(String),
  sensor_id LowCardinality(String),
  community_id String,
  -- IP columns are String (not IPv6): missing addresses are stored as empty
  -- strings per the NormalizedEvent contract, never the unspecified address
  -- "::" (which would create phantom entities for detection and waste
  -- redaction token slots). Existing IPv6 columns are migrated in code by
  -- ClickHouseEventAdapter._ensure_search_schema.
  src_ip String,
  src_port UInt16,
  dst_ip String,
  dst_port UInt16,
  protocol LowCardinality(String),
  duration_ms UInt64,
  bytes_out UInt64,
  bytes_in UInt64,
  severity UInt8,
  signature String,
  raw_reference String,
  raw_event String CODEC(ZSTD(3)),
  -- Lowercased token stream used for payload/full-text search. The tokenbf_v1
  -- index accelerates multiSearchAnyCaseInsensitive/hasToken lookups so event
  -- search never scans every raw_event blob. Existing deployments can add the
  -- column with:
  --   ALTER TABLE hybrid_ndr.network_events
  --     ADD COLUMN IF NOT EXISTS search_text String,
  --     ADD INDEX IF NOT EXISTS search_text_tokenbf search_text
  --       TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4;
  search_text String,
  INDEX community_id_bloom community_id TYPE bloom_filter(0.01) GRANULARITY 4,
  INDEX source_ip_bloom src_ip TYPE bloom_filter(0.01) GRANULARITY 4,
  INDEX destination_ip_bloom dst_ip TYPE bloom_filter(0.01) GRANULARITY 4,
  INDEX search_text_tokenbf search_text TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree
PARTITION BY (tenant_id, toYYYYMM(event_time))
ORDER BY (tenant_id, deployment_id, event_time, event_type, event_id)
SETTINGS index_granularity = 8192;

CREATE VIEW IF NOT EXISTS hybrid_ndr.sensor_ingestion_health AS
SELECT
  tenant_id,
  deployment_id,
  sensor_id,
  source,
  max(ingested_at) AS last_ingested_at,
  count() AS event_count
FROM hybrid_ndr.network_events
GROUP BY tenant_id, deployment_id, sensor_id, source;
