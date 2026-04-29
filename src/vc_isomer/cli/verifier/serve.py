"""`isomer verifier serve` command."""

from __future__ import annotations

import argparse
import os

from vc_isomer.service import VerifierServerConfig, setup_verifier_doers
from vc_isomer.verifier_logging import configure_verifier_logging


def handle(args: argparse.Namespace):
    """Return the long-running doers for `isomer verifier serve`."""
    configure_verifier_logging()
    _server, doers = setup_verifier_doers(
        VerifierServerConfig(
            host=args.host,
            port=args.port,
            resolver_url=args.resolver,
            operation_store_root=args.operation_root,
            operation_store_name=args.operation_name,
            webhook_url=args.webhook_url or os.getenv("ISOMER_WEBHOOK_URL"),
            verifier_id=args.verifier_id or os.getenv("ISOMER_VERIFIER_ID", "isomer-python"),
            verifier_label=args.verifier_label or os.getenv("ISOMER_VERIFIER_LABEL"),
        )
    )
    return doers


def add_serve_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `isomer verifier serve`."""
    verifier_serve = subparsers.add_parser("serve", help="Serve the verifier operation HTTP API")
    verifier_serve.add_argument("--host", default="127.0.0.1")
    verifier_serve.add_argument("--port", type=int, default=8788)
    verifier_serve.add_argument("--resolver", required=True)
    verifier_serve.add_argument("--operation-root", required=True)
    verifier_serve.add_argument("--operation-name", default="verifier")
    verifier_serve.add_argument("--webhook-url", help="Optional successful VC/VP webhook target")
    verifier_serve.add_argument("--verifier-id", help="Verifier id included in webhook metadata")
    verifier_serve.add_argument("--verifier-label", help="Verifier label included in webhook metadata")
    verifier_serve.set_defaults(handler=handle)
