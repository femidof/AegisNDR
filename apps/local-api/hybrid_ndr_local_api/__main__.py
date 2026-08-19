from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
for path in (
    ROOT / "packages" / "contracts-python", ROOT / "packages" / "redaction", ROOT / "packages" / "audit",
    ROOT / "packages" / "auth", ROOT / "packages" / "storage", ROOT / "packages" / "transport",
    ROOT / "packages" / "observability", ROOT / "services" / "model-gateway", ROOT / "services" / "agent-runtime",
    ROOT / "apps" / "local-api",
):
    sys.path.insert(0, str(path))

from hybrid_ndr_local_api.api import create_application  # noqa: E402
from hybrid_ndr_storage import PersistenceSettings, build_persistence, build_store  # noqa: E402
from hybrid_ndr_transport import make_server  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the customer-resident Hybrid NDR local API.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default: private localhost).")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--database", default=os.environ.get("SQLITE_DATABASE", str(ROOT / ".data" / "local-api.sqlite3")))
    parser.add_argument("--seed-demo", action="store_true", help="Seed demo data only when the demo tenant is empty.")
    parser.add_argument("--reset-demo", action="store_true", help="Deterministically replace only the demo tenant data.")
    args = parser.parse_args()
    settings = replace(PersistenceSettings.from_env(), sqlite_path=args.database)
    persistence = build_persistence(settings)
    store = build_store(settings, persistence)
    if settings.profile == "demo":
        if args.reset_demo:
            print(f"Demo data reset: {store.reset_demo()}")
        elif args.seed_demo and not store.list_alerts("demo-tenant"):
            print(f"Demo data seeded: {store.reset_demo()}")
    elif args.reset_demo:
        raise SystemExit("--reset-demo is intentionally unavailable with PERSISTENCE_PROFILE=production")
    elif args.seed_demo:
        print("Production persistence selected; --seed-demo was ignored.")
    application = create_application(store, persistence=persistence)
    print(f"Local API listening at http://{args.host}:{args.port} (health: /healthz)")
    with make_server(args.host, args.port, application) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\nLocal API stopped.")


if __name__ == "__main__":
    main()
