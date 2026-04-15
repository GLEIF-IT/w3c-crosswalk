"""`crosswalk serve ...` command family."""

from __future__ import annotations

import argparse

from .status import add_status_command
from .verifier import add_verifier_command
from .verifier_worker import add_verifier_worker_command


def add_serve_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `crosswalk serve ...` command family."""
    serve = subparsers.add_parser("serve", help="Host long-running crosswalk HTTP services")
    serve_subparsers = serve.add_subparsers(dest="serve_command", required=True)

    add_status_command(serve_subparsers)
    add_verifier_command(serve_subparsers)
    add_verifier_worker_command(serve_subparsers)
