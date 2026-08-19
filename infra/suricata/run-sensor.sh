#!/bin/sh
set -eu

mode=${SENSOR_CAPTURE_MODE:-pcap}
case "$mode" in
  pcap)
    exec /bin/sh /opt/hybrid-ndr/run-offline.sh
    ;;
  live)
    interface=${CAPTURE_INTERFACE:-}
    case "$interface" in
      ""|-*|*[!A-Za-z0-9_.:-]*)
        echo "invalid or missing CAPTURE_INTERFACE" >&2
        exit 2
        ;;
    esac
    test -d "/sys/class/net/$interface" || {
      echo "capture interface is not visible in the sensor namespace: $interface" >&2
      exit 2
    }
    log_dir=${SURICATA_LOG_DIR:-/var/log/sensors/suricata}
    rules=${SURICATA_RULES:-/etc/suricata/rules/hybrid-ndr.rules}
    mkdir -p "$log_dir"
    rm -f "$log_dir/.ready"
    touch "$log_dir/.ready"
    exec suricata \
      -c /etc/suricata/suricata.yaml \
      --runmode workers \
      --set outputs.1.eve-log.community-id=true \
      -k none \
      -S "$rules" \
      -l "$log_dir" \
      -i "$interface"
    ;;
  *)
    echo "SENSOR_CAPTURE_MODE must be 'live' or 'pcap'" >&2
    exit 2
    ;;
esac
