#!/usr/bin/env bash
set -Eeuo pipefail

: "${POSTGRES_DB:?POSTGRES_DB is required}"
: "${POSTGRES_USER:?POSTGRES_USER is required}"
: "${GRAFANA_POSTGRES_USER:?GRAFANA_POSTGRES_USER is required}"
: "${GRAFANA_POSTGRES_PASSWORD:?GRAFANA_POSTGRES_PASSWORD is required}"
: "${POSTGRES_EXPORTER_USER:?POSTGRES_EXPORTER_USER is required}"
: "${POSTGRES_EXPORTER_PASSWORD:?POSTGRES_EXPORTER_PASSWORD is required}"

for role_name in "$GRAFANA_POSTGRES_USER" "$POSTGRES_EXPORTER_USER"; do
  if ! [[ "$role_name" =~ ^[a-z_][a-z0-9_]{2,62}$ ]]; then
    echo "Invalid PostgreSQL role name: $role_name" >&2
    exit 1
  fi
done

psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set=ON_ERROR_STOP=1 \
  --set=grafana_user="$GRAFANA_POSTGRES_USER" \
  --set=grafana_password="$GRAFANA_POSTGRES_PASSWORD" \
  --set=exporter_user="$POSTGRES_EXPORTER_USER" \
  --set=exporter_password="$POSTGRES_EXPORTER_PASSWORD" <<'SQL'
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'grafana_user', :'grafana_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'grafana_user') \gexec
SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', :'grafana_user', :'grafana_password') \gexec

SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', :'exporter_user', :'exporter_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = :'exporter_user') \gexec
SELECT format('ALTER ROLE %I WITH LOGIN PASSWORD %L NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION', :'exporter_user', :'exporter_password') \gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'grafana_user') \gexec
SELECT format('GRANT USAGE ON SCHEMA local_state TO %I', :'grafana_user') \gexec
SELECT format(
  'GRANT SELECT ON local_state.alerts, local_state.investigations, local_state.model_transmissions, local_state.cases, local_state.sensors TO %I',
  :'grafana_user'
) \gexec

SELECT format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), :'exporter_user') \gexec
SELECT format('GRANT pg_monitor TO %I', :'exporter_user') \gexec
SQL
