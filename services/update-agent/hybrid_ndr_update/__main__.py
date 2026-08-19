from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from hybrid_ndr_observability import warning as log_warning

from .agent import UpdateAgent, UpdateError, UpdateRejected, UpdateRolledBack, verify_audit_database


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--state-dir", default=os.environ.get("HYBRID_NDR_STATE_DIR", "/var/lib/hybrid-ndr"))
    parser.add_argument("--config-dir", default=os.environ.get("HYBRID_NDR_CONFIG_DIR", "/etc/hybrid-ndr"))
    parser.add_argument("--public-key")


def _monitor(state_dir: Path, health_file: Path, interval: int) -> int:
    stopped = False

    def stop(_signum, _frame):  # noqa: ANN001
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    manifest = state_dir / "updates/available-manifest.json"
    manifest_absent_reported = False
    cycles = 0
    while not stopped:
        cycles += 1
        status, reason = "ok", "audit_chain_valid"
        try:
            verify_audit_database(state_dir)
        except Exception as exc:  # the monitor exposes only a stable class name
            status, reason = "failed", exc.__class__.__name__
        # The agent can only apply manifests the connector has already
        # downloaded (network_mode: none). If no manifest is present, updates
        # are stalled; surface that instead of failing silently.
        if manifest.is_file() and not manifest.is_symlink():
            manifest_absent_reported = False
        elif not manifest_absent_reported or cycles % 30 == 0:
            manifest_absent_reported = True
            log_warning("update.manifest_unavailable", cycles=cycles)
        temporary = health_file.with_name(f".{health_file.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps({"status": status, "reason": reason}, sort_keys=True), encoding="ascii")
        os.chmod(temporary, 0o600)
        os.replace(temporary, health_file)
        deadline = time.monotonic() + interval
        while not stopped and time.monotonic() < deadline:
            time.sleep(min(1.0, deadline - time.monotonic()))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Customer-controlled Hybrid NDR signed update agent")
    commands = parser.add_subparsers(dest="command", required=True)
    apply = commands.add_parser("apply", help="verify, stage, apply, health-check, and automatically roll back")
    _common(apply)
    apply.add_argument("--manifest", help="verified connector manifest (defaults to STATE/updates/available-manifest.json)")
    apply.add_argument("--artifact", required=True, help="local release bundle whose SHA-256 is signed by the manifest")
    apply.add_argument("--approve-downgrade", metavar="EXACT_VERSION")
    apply.add_argument("--operator-id", default="local-operator")
    apply.add_argument("--health-timeout", type=int, default=300)

    audit = commands.add_parser("verify-audit", help="verify the append-only software-update audit chain")
    _common(audit)

    monitor = commands.add_parser("monitor", help="run the unprivileged Compose integrity monitor")
    monitor.add_argument("--state-dir", default=os.environ.get("HYBRID_NDR_STATE_DIR", "/var/lib/hybrid-ndr"))
    monitor.add_argument("--health-file", default=os.environ.get("UPDATE_AGENT_HEALTH_FILE", "/tmp/hybrid-ndr-update-health.json"))
    monitor.add_argument("--interval", type=int, default=int(os.environ.get("UPDATE_AGENT_MONITOR_SECONDS", "30")))

    arguments = parser.parse_args()
    if arguments.command == "monitor":
        if not 1 <= arguments.interval <= 3600:
            parser.error("--interval must be between 1 and 3600 seconds")
        return _monitor(Path(arguments.state_dir), Path(arguments.health_file), arguments.interval)

    agent: UpdateAgent | None = None
    try:
        agent = UpdateAgent(
            state_dir=arguments.state_dir,
            config_dir=arguments.config_dir,
            public_key=arguments.public_key,
        )
        if arguments.command == "verify-audit":
            agent.verify_audit()
            print("software update audit chain verified")
            return 0
        manifest = arguments.manifest or str(Path(arguments.state_dir) / "updates/available-manifest.json")
        staged = agent.apply(
            manifest_path=manifest,
            artifact_path=arguments.artifact,
            approve_downgrade=arguments.approve_downgrade,
            actor_id=arguments.operator_id,
            health_timeout=arguments.health_timeout,
        )
        print(f"release {staged.version} is installed and healthy")
        return 0
    except UpdateRolledBack as exc:
        print(f"update rolled back ({exc.code}): {exc}", file=sys.stderr)
        return 3
    except UpdateRejected as exc:
        print(f"update rejected ({exc.code}): {exc}", file=sys.stderr)
        return 2
    except UpdateError as exc:
        print(f"update failed ({exc.code}): {exc}", file=sys.stderr)
        return 1
    finally:
        if agent is not None:
            agent.close()


if __name__ == "__main__":
    raise SystemExit(main())
