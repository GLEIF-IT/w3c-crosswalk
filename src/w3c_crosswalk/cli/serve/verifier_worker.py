"""`crosswalk serve verifier-worker` command."""

from __future__ import annotations

import argparse

from w3c_crosswalk.service import VerifierServerConfig, setup_verifier_worker_doers


def handle(args: argparse.Namespace):
    """Return the long-running doers for `crosswalk serve verifier-worker`."""
    return setup_verifier_worker_doers(
        VerifierServerConfig(
            host=args.host,
            port=args.port,
            resolver_url=args.resolver,
            operation_store_root=args.operation_root,
            operation_store_name=args.operation_name,
        )
    )


def add_verifier_worker_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk serve verifier-worker`."""
    verifier_worker = subparsers.add_parser(
        "verifier-worker",
        help="Run background verifier workers against the shared operation store",
    )
    verifier_worker.add_argument("--host", default="127.0.0.1")
    verifier_worker.add_argument("--port", type=int, default=8788)
    verifier_worker.add_argument("--resolver", required=True)
    verifier_worker.add_argument("--operation-root", required=True)
    verifier_worker.add_argument("--operation-name", default="verifier")
    verifier_worker.set_defaults(handler=handle)
