"""`crosswalk status revoke` command."""

from __future__ import annotations

import argparse

from hio.base import doing

from w3c_crosswalk.cli.common import add_common_output_args, emit_json
from w3c_crosswalk.services import revoke_status
from w3c_crosswalk.status import JsonFileStatusStore


class RevokeStatusDoer(doing.Doer):
    """Revoke one status record as a single explicit CLI doer."""

    def __init__(self, *, args: argparse.Namespace, **kwa):
        self.args = args
        super().__init__(**kwa)

    def recur(self, tyme):
        result = revoke_status(
            store=JsonFileStatusStore(self.args.store),
            credential_said=self.args.credential_said,
            base_url=self.args.base_url,
            reason=self.args.reason,
        )
        emit_json(result, output=self.args.output)
        return True


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk status revoke`."""
    return [RevokeStatusDoer(args=args)]


def add_revoke_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk status revoke`."""
    status_revoke = subparsers.add_parser("revoke", help="Revoke a projected credential")
    status_revoke.add_argument("--credential-said", required=True)
    status_revoke.add_argument("--store", required=True)
    status_revoke.add_argument("--base-url", required=True)
    status_revoke.add_argument("--reason", default="revoked via crosswalk CLI")
    add_common_output_args(status_revoke)
    status_revoke.set_defaults(handler=handle)
