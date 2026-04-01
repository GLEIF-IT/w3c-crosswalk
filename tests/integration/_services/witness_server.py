"""Launch the crosswalk integration witness-demo topology."""

from __future__ import annotations

import argparse
import signal

import falcon
from hio.base import doing
from keri import help
from keri.app import configing, habbing, indirecting
from keri.core import Salter

WITNESSES = (
    ("wan", b"wann-the-witness"),
    ("wil", b"will-the-witness"),
    ("wes", b"wess-the-witness"),
)


def parse_args() -> argparse.Namespace:
    """Parse ports and config location for the witness demo service."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config-dir", required=True, help="runtime config root")
    parser.add_argument("--wan-port", required=True, type=int)
    parser.add_argument("--wil-port", required=True, type=int)
    parser.add_argument("--wes-port", required=True, type=int)
    return parser.parse_args()


def install_harness_patches() -> None:
    """Patch witness HTTP behavior for the local integration harness.

    The harness binds the witness server to loopback only and disables the
    query endpoint that is not needed by this stack's test flows.
    """
    original_create_http_server = indirecting.createHttpServer

    def create_loopback_http_server(host, port, app, keypath=None, certpath=None, cafilepath=None):
        return original_create_http_server("127.0.0.1", port, app, keypath, certpath, cafilepath)

    indirecting.createHttpServer = create_loopback_http_server


def main() -> None:
    """Launch the three-witness demo topology and block until interrupted."""
    args = parse_args()
    witness_ports = {"wan": args.wan_port, "wil": args.wil_port, "wes": args.wes_port}

    help.ogler.level = 20
    install_harness_patches()

    doers = []
    for name, salt in WITNESSES:
        cf = configing.Configer(name=name, headDirPath=args.config_dir, temp=False, reopen=True, clear=False)
        hby = habbing.Habery(
            name=name,
            salt=Salter(raw=salt).qb64,
            temp=False,
            cf=cf,
            headDirPath=args.config_dir,
        )
        doers.extend(indirecting.setupWitness(alias=name, hby=hby, tcpPort=None, httpPort=witness_ports[name]))

    doist = doing.Doist(limit=0.0, tock=0.03125, real=True)
    doist.doers = doers
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
    try:
        doist.do()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
