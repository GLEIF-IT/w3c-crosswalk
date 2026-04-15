"""`isomer verifier ...` command family."""

from __future__ import annotations

import argparse

from .serve import add_serve_command
from .worker import add_worker_commands


def add_verifier_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `isomer verifier ...` command family."""
    verifier = subparsers.add_parser("verifier", help="Host verifier operation services")
    verifier_subparsers = verifier.add_subparsers(dest="verifier_command", required=True)

    add_serve_command(verifier_subparsers)
    add_worker_commands(verifier_subparsers)
