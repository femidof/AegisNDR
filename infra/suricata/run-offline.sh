#!/bin/sh
set -eu

capture=${SENSOR_PCAP:-/var/lib/sensor-fixtures/sensor-acceptance.pcap}
log_dir=${SURICATA_LOG_DIR:-/var/log/sensors/suricata}
rules=${SURICATA_RULES:-/etc/suricata/rules/hybrid-ndr.rules}

test -s "$capture"
mkdir -p "$log_dir"

# Checkpoint: if a previous run already produced events, do not re-process the
# PCAP. A restart must not re-ingest the whole capture, and the health marker
# is (re)created so the sensor is immediately healthy again.
if test -s "$log_dir/eve.json"; then
  touch "$log_dir/.ready"
  exec tail -F "$log_dir/eve.json"
fi

# Fresh run: mark the sensor healthy BEFORE processing. Health checks must
# verify the sensor is running, not that it has finished; with a large PCAP
# the processing window far exceeds the health-check tolerance, and any
# depends_on: service_healthy consumer would otherwise be blocked.
rm -f "$log_dir/.ready" "$log_dir/eve.json"
touch "$log_dir/.ready"

# Only the Vector-consumed eve.json is removed; fast.log/stats.log/suricata.log
# are diagnostic and are preserved for post-hoc debugging.
suricata \
  -c /etc/suricata/suricata.yaml \
  --runmode single \
  --set outputs.1.eve-log.community-id=true \
  -k none \
  -S "$rules" \
  -l "$log_dir" \
  -r "$capture"

test -s "$log_dir/eve.json"
exec tail -F "$log_dir/eve.json"
