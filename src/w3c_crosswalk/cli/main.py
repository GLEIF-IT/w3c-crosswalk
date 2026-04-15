"""Parser assembly and top-level CLI entrypoint."""

from __future__ import annotations

import argparse
import sys

from w3c_crosswalk.controller import run_controller

from .common import report_failure_for_doers
from .status import add_status_commands
from .vc import add_vc_commands
from .verifier import add_verifier_commands
from .vp import add_vp_commands


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level CLI parser and delegate command-family registration."""
    parser = argparse.ArgumentParser(prog="crosswalk", description="W3C VRD crosswalk CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_vc_commands(subparsers)
    add_vp_commands(subparsers)
    add_status_commands(subparsers)
    add_verifier_commands(subparsers)

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
    exit_code = report_failure_for_doers(doers)
    if exit_code != 0:
        return exit_code
    success_reporter = getattr(args, "success_reporter", None)
    if success_reporter is not None:
        success_reporter(doers)
    return 0
