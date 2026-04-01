"""Launch did:webs artifact or resolver services for the crosswalk harness."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys


def parse_args() -> argparse.Namespace:
    """Parse artifact/resolver mode and the delegated `dws` service options."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("artifact", "resolver"), required=True)
    parser.add_argument("--dws-bin", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--alias")
    parser.add_argument("--base", default="")
    parser.add_argument("--passcode", required=True)
    parser.add_argument("--config-dir")
    parser.add_argument("--config-file")
    parser.add_argument("--http-port", required=True, type=int)
    parser.add_argument("--did-path", default="dws")
    return parser.parse_args()


def main() -> None:
    """Launch a `dws` subprocess and proxy SIGTERM to it."""
    args = parse_args()
    command = [
        args.dws_bin,
        "did",
        "webs",
        "service" if args.mode == "artifact" else "resolver-service",
        "--name",
        args.name,
        "--http",
        str(args.http_port),
        "--did-path",
        args.did_path,
        "--passcode",
        args.passcode,
        "--loglevel",
        "INFO",
    ]
    if args.base:
        command.extend(["--base", args.base])
    if args.alias and args.mode == "artifact":
        command.extend(["--alias", args.alias])
    if args.config_dir:
        command.extend(["--config-dir", args.config_dir])
    if args.config_file:
        command.extend(["--config-file", args.config_file])

    proc = subprocess.Popen(command, env=os.environ.copy())

    def _handle_sigterm(*_args):
        proc.terminate()

    signal.signal(signal.SIGTERM, _handle_sigterm)
    try:
        raise SystemExit(proc.wait())
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
