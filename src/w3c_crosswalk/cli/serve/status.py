"""`crosswalk serve status` command."""

from __future__ import annotations

import argparse

from w3c_crosswalk.service import StatusServerConfig, setup_status_doers


def handle(args: argparse.Namespace):
    """Return the long-running doers for `crosswalk serve status`."""
    _server, doers = setup_status_doers(
        StatusServerConfig(host=args.host, port=args.port, store_path=args.store, base_url=args.base_url)
    )
    return doers


def add_status_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk serve status`."""
    status_serve = subparsers.add_parser("status", help="Serve credential status resources")
    status_serve.add_argument("--host", default="127.0.0.1")
    status_serve.add_argument("--port", type=int, default=8787)
    status_serve.add_argument("--store", required=True)
    status_serve.add_argument("--base-url", required=True)
    status_serve.set_defaults(handler=handle)
