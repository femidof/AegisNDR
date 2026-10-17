#!/bin/sh
set -e
# Make the internal TLS material readable by the clickhouse runtime user by
# copying it into the writable data directory, then run the stock entrypoint.
install -d -m 0700 /var/lib/clickhouse/internal-tls
for name in ca-cert.pem clickhouse-cert.pem clickhouse-key.pem; do
  install -m 0600 "/mnt/internal-tls/$name" "/var/lib/clickhouse/internal-tls/$name"
done
exec /entrypoint.sh "$@"
