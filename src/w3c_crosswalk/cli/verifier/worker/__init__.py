"""`crosswalk verifier worker ...` command family."""

from __future__ import annotations

import argparse

from .serve import add_serve_command


def add_worker_commands(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register the `crosswalk verifier worker ...` command family."""
    worker = subparsers.add_parser("worker", help="Run verifier worker processes")
    worker_subparsers = worker.add_subparsers(dest="verifier_worker_command", required=True)

    add_serve_command(worker_subparsers)
