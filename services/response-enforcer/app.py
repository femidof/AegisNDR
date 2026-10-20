#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for dependency in ("packages/contracts-python", "packages/audit", "packages/storage",
                   "packages/transport", "packages/auth", "packages/redaction", "packages/observability",
                   "services/model-gateway", "services/agent-runtime"):
    sys.path.insert(0, str(ROOT / dependency))

from hybrid_ndr_agent.response_adapters import document
from hybrid_ndr_agent.response import digest
from hybrid_ndr_transport import make_server
from enforcer import Enforcer, validate_config


def exclusive_state_lock(database):
    """Prevent a second service or recovery CLI racing durable kernel intent."""
    import fcntl
    lock = open(str(database) + ".lock", "a", encoding="ascii")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock.close()
        raise SystemExit("enforcer state is in use; stop the service before local recovery") from None
    return lock


def main():
    parser = argparse.ArgumentParser(description="Run the typed AegisNDR nftables enforcer or device probe.")
    parser.add_argument("--config", required=True)
    parser.add_argument("--database", default="/var/lib/aegisndr-response/enforcer.sqlite3")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--certificate", default="")
    parser.add_argument("--key", default="")
    parser.add_argument("--client-ca", default="")
    parser.add_argument("--print-revision", action="store_true")
    parser.add_argument("--release-action")
    args = parser.parse_args()
    config = document(args.config)
    validate_config(config)
    if args.print_revision:
        print(digest(config))
        return 0
    if config["mode"] != "probe" and sys.platform != "linux":
        raise SystemExit("nftables enforcement is supported on Linux only")
    os.umask(0o077)
    Path(args.database).parent.mkdir(parents=True, exist_ok=True)
    state_lock = exclusive_state_lock(args.database) if config["mode"] != "probe" else None
    enforcer = Enforcer(config, args.database)
    if args.release_action:
        try:
            print(json.dumps(enforcer.release(args.release_action)))
        finally:
            enforcer.connection.close()
            if state_lock is not None:
                state_lock.close()
        return 0
    if not all((args.certificate, args.key, args.client_ca)):
        raise SystemExit("server certificate, private key and client CA are required; plaintext is not supported")
    stop = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_args: stop.set())
    with make_server(args.host, args.port, enforcer.application, certificate_file=args.certificate,
                     private_key_file=args.key, client_ca_file=args.client_ca,
                     require_client_certificate=True) as server:
        enforcer.restore()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        print(json.dumps({"event": "response.enforcer.started", "mode": config["mode"], "revision": enforcer.revision}))
        stop.wait()
        server.shutdown()
        thread.join(timeout=10)
    enforcer.connection.close()
    if state_lock is not None:
        state_lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
