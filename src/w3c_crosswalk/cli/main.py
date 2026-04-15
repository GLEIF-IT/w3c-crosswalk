"""Parser assembly and top-level CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

from w3c_crosswalk.controller import run_controller

from .common import exit_code_for_doers
from .issue import add_issue_commands
from .serve import add_serve_commands
from .status import add_status_commands
from .verify import add_verify_commands


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser and delegate command-family registration."""
    parser = argparse.ArgumentParser(prog="crosswalk", description="W3C VRD crosswalk CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_issue_commands(subparsers)
    add_verify_commands(subparsers)
    add_status_commands(subparsers)
    add_serve_commands(subparsers)

    return parser


def main(argv: list[str] | None = None) -> int:
    """Parse arguments, build doers, and run them under one top-level controller."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.print_help()
        return 1

    try:
        doers = handler(args)
        run_controller(doers)
    except Exception as exc:
        print(f"ERR: {exc}", file=sys.stderr)
        return -1
    return exit_code_for_doers(doers)
