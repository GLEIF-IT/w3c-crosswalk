"""`isomer vp issue` command."""

from __future__ import annotations

import argparse
from pathlib import Path

from vc_isomer.cli.common import add_common_output_args, add_live_signer_args, emit_json, load_passcode
from vc_isomer.isomer_runtime import IsomerSignerRuntimeDoer
from vc_isomer.services import issue_vp_artifact


class IssueVpDoer(IsomerSignerRuntimeDoer):
    """Issue one VP-JWT artifact as a single explicit CLI doer."""

    def __init__(self, *, args: argparse.Namespace, **kwa):
        self.args = args
        super().__init__(
            name=args.name,
            base=args.base,
            alias=args.alias,
            passcode=load_passcode(args),
            **kwa,
        )

    def recur(self, tyme):
        vc_tokens = [Path(path).read_text(encoding="utf-8").strip() for path in self.args.vc_token]
        result = issue_vp_artifact(
            vc_tokens=vc_tokens,
            holder_did=self.args.holder_did,
            signer=self.signer,
            audience=self.args.audience,
            nonce=self.args.nonce,
        )
        emit_json(result.to_dict(), output=self.args.output)
        return True


def handle(args: argparse.Namespace):
    """Return doers for `isomer vp issue`."""
    return [IssueVpDoer(args=args)]


def add_issue_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `isomer vp issue`."""
    issue_vp = subparsers.add_parser("issue", help="Wrap one or more VC-JWTs in a VP-JWT")
    issue_vp.add_argument("--vc-token", action="append", required=True)
    issue_vp.add_argument("--holder-did", required=True)
    issue_vp.add_argument("--audience")
    issue_vp.add_argument("--nonce")
    add_live_signer_args(issue_vp)
    add_common_output_args(issue_vp)
    issue_vp.set_defaults(handler=handle)
