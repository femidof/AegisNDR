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
    log_dir=${ZEEK_LOG_DIR:-/var/log/sensors/zeek}
    mkdir -p "$log_dir"
    rm -f "$log_dir/.ready"
    touch "$log_dir/.ready"
    cd "$log_dir"
    exec zeek -C -i "$interface" /opt/hybrid-ndr/local.zeek
    ;;
  *)
    echo "SENSOR_CAPTURE_MODE must be 'live' or 'pcap'" >&2
    exit 2
    ;;
esac
