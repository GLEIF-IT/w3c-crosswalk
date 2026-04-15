"""`isomer verifier serve` command."""

from __future__ import annotations

import argparse

from vc_isomer.service import VerifierServerConfig, setup_verifier_doers


def handle(args: argparse.Namespace):
    """Return the long-running doers for `isomer verifier serve`."""
    _server, doers = setup_verifier_doers(
        VerifierServerConfig(
            host=args.host,
            port=args.port,
            resolver_url=args.resolver,
            operation_store_root=args.operation_root,
            operation_store_name=args.operation_name,
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
    verifier_serve.set_defaults(handler=handle)
