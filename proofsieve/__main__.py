"""Run the local ProofSieve Guard and web applications."""

import argparse
import json
import logging
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit

from .paths import DEFAULT_STATE, ROOT
from .server import SECURITY_AUDIT, serve


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="store_true", help="Show the running API release version and exit")
    parser.add_argument("--port", type=int, default=4180, help="Loopback TCP port or local browser port with --socket")
    parser.add_argument("--socket", type=Path, help="Listen on this private Unix socket instead of TCP")
    parser.add_argument("--auth-config", type=Path, help="Owner-only JSON file with bearer token digests and endpoint grants")
    parser.add_argument("--checks-config", type=Path, help="Owner-only JSON file with configured verification connectors")
    parser.add_argument("--evidence", type=Path, help="Private SQLite file for operation-bound decision evidence")
    parser.add_argument("--evidence-export", action="store_true", help="Enable caller-scoped signed JSON evidence export")
    parser.add_argument("--forwarding-config", type=Path, help="Private JSON map from verification paths to approved HTTPS destinations")
    parser.add_argument("--wallet-config", type=Path, help="Owner-only JSON configuration for wallet presentation endpoints")
    parser.add_argument("--wallet-sessions", type=Path, help="Private SQLite journal for single-use wallet sessions")
    parser.add_argument("--wallet-receipts", action="store_true", help="List pending wallet receipts and exit; status 1 means pending")
    parser.add_argument("--evidence-retention-days", type=int, default=30, help="Retention on subsequent decision writes (1–365 days)")
    parser.add_argument("--proxy-origin", help="Exact HTTPS origin presented by the reverse proxy")
    parser.add_argument("--proxy-socket", type=Path, help="Separate API-only Unix socket for the reverse proxy")
    parser.add_argument("--proxy-gid", type=int, help="Dedicated reverse proxy group allowed to open the Unix socket")
    parser.add_argument("--state", type=Path, default=DEFAULT_STATE)
    args = parser.parse_args()
    try:
        if args.version:
            release = json.loads((ROOT / "openapi.json").read_text(encoding="utf-8"))["info"]["version"]
            print(f"ProofSieve {release}")
            return
        if args.wallet_receipts:
            if args.wallet_sessions is None:
                raise ValueError("--wallet-receipts erfordert --wallet-sessions.")
            from .wallet_sessions import pending_wallet_receipts

            receipts = pending_wallet_receipts(args.wallet_sessions)
            print(json.dumps({"pending": len(receipts), "receipts": receipts}))
            parser.exit(int(bool(receipts)))
        if not 0 <= args.port <= 65535:
            raise ValueError("--port muss zwischen 0 und 65535 liegen.")
        if (args.checks_config or args.evidence) and not args.auth_config:
            raise ValueError("--checks-config und --evidence erfordern --auth-config.")
        if args.evidence_export and not args.evidence:
            raise ValueError("--evidence-export erfordert --evidence und --auth-config.")
        if args.forwarding_config and (not args.evidence or not args.auth_config):
            raise ValueError("--forwarding-config erfordert --evidence und --auth-config.")
        if args.wallet_config or args.wallet_sessions:
            if not (args.wallet_config and args.wallet_sessions and args.evidence and args.auth_config):
                raise ValueError("Wallet-Prüfungen erfordern --wallet-config, --wallet-sessions, --evidence und --auth-config.")
            other_paths = (args.state, args.auth_config, args.evidence, args.checks_config, args.forwarding_config,
                           args.wallet_config)
            if any(path is not None and path.resolve() == args.wallet_sessions.resolve() for path in other_paths):
                raise ValueError("--wallet-sessions braucht eine separate Datenbankdatei.")
        if args.proxy_origin is not None:
            from .guard import validate_result_url

            validate_result_url(args.proxy_origin, "--proxy-origin")
            proxy = urlsplit(args.proxy_origin)
            if not args.socket or not args.proxy_socket or not proxy.netloc or args.proxy_origin != f"https://{proxy.netloc}":
                raise ValueError("--proxy-origin erfordert getrennte Sockets und einen HTTPS-Ursprung ohne Pfad.")
        access_policy = None
        if args.auth_config is not None:
            from .access import AccessPolicy

            access_policy = AccessPolicy.load(args.auth_config)
        registry = None
        if args.checks_config is not None:
            from .checks import load_check_registry

            registry = load_check_registry(args.checks_config)
        evidence = None
        if args.evidence is not None:
            from .evidence import EvidenceStore

            inputs = (args.state, args.auth_config, args.checks_config, args.forwarding_config, args.wallet_config)
            if any(path is not None and path.resolve() == args.evidence.resolve() for path in inputs):
                raise ValueError("--evidence braucht eine separate Datenbankdatei.")
            evidence = EvidenceStore(args.evidence, retention_days=args.evidence_retention_days)
        forwarding = None
        if args.forwarding_config is not None:
            from .forwarding import load_forwarding

            forwarding = load_forwarding(args.forwarding_config)
        wallet = None
        if args.wallet_config is not None:
            from .wallet import load_wallet_verification

            wallet = load_wallet_verification(args.wallet_config, args.wallet_sessions)
        if access_policy is not None:
            if not SECURITY_AUDIT.handlers:
                SECURITY_AUDIT.addHandler(logging.StreamHandler())
            SECURITY_AUDIT.setLevel(logging.INFO)
            SECURITY_AUDIT.propagate = False
        serve(args.port, args.state, socket_path=args.socket, access_policy=access_policy,
              registry=registry, evidence=evidence, forwarding=forwarding, wallet=wallet,
              evidence_export=args.evidence_export, proxy_origin=args.proxy_origin,
              proxy_socket=args.proxy_socket, proxy_gid=args.proxy_gid)
    except (ValueError, OSError, ImportError, sqlite3.Error) as exc:
        parser.exit(1, f"ProofSieve konnte nicht starten: {exc}\n")
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
