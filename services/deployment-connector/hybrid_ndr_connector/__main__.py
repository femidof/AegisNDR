from __future__ import annotations

import os
import signal
import time

from .connector import Connector, ConnectorSettings


def main() -> None:
    enabled = os.environ.get("CONNECTOR_ENABLED", "true").strip().lower()
    if enabled not in {"true", "false"}:
        raise SystemExit("CONNECTOR_ENABLED must be exactly 'true' or 'false'")
    if enabled == "false":
        health_file = os.environ.get("CONNECTOR_HEALTH_FILE", "/tmp/hybrid-ndr-connector-health")
        with open(health_file, "w", encoding="ascii") as stream:
            stream.write(str(int(time.time())))
        while True:
            time.sleep(30)
    connector = Connector(ConnectorSettings.from_env())
    stopped = False

    def stop(_signum, _frame):  # noqa: ANN001
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    health_file = os.environ.get("CONNECTOR_HEALTH_FILE", "/tmp/hybrid-ndr-connector-health")
    while not stopped:
        connector.run_once()
        # Liveness means the connector loop and its local state are operational;
        # control-plane reachability is captured per operation and must not make
        # the customer appliance unhealthy during an upstream outage.
        with open(health_file, "w", encoding="ascii") as stream:
            stream.write(str(int(time.time())))
        deadline = time.monotonic() + min(30.0, connector.seconds_until_due())
        while not stopped and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))


if __name__ == "__main__":
    main()
