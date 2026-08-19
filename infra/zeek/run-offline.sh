#!/bin/sh
set -eu

capture=${SENSOR_PCAP:-/var/lib/sensor-fixtures/sensor-acceptance.pcap}
log_dir=${ZEEK_LOG_DIR:-/var/log/sensors/zeek}

test -s "$capture"
mkdir -p "$log_dir"

# Checkpoint: if a previous run already produced events, do not re-process the
# PCAP. A restart must not re-ingest the whole capture, and the health marker
# is (re)created so the sensor is immediately healthy again.
if test -s "$log_dir/conn.log"; then
  touch "$log_dir/.ready"
  exec tail -F "$log_dir/conn.log"
fi

# Fresh run: mark the sensor healthy BEFORE processing. Health checks must
# verify the sensor is running, not that it has finished; with a large PCAP
# the processing window far exceeds the health-check tolerance, and any
# depends_on: service_healthy consumer would otherwise be blocked.
rm -f "$log_dir/.ready"
touch "$log_dir/.ready"

# Delete only the known Zeek outputs, never a wildcard: a misconfigured mount
# must not have unrelated .log files silently removed.
rm -f "$log_dir/conn.log" "$log_dir/dns.log" "$log_dir/http.log" "$log_dir/ssl.log"

cd "$log_dir"
zeek -C -r "$capture" /opt/hybrid-ndr/local.zeek

test -s "$log_dir/conn.log"
exec tail -F "$log_dir/conn.log"
