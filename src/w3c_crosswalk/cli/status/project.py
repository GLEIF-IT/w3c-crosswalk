"""`crosswalk status project` command."""

from __future__ import annotations

import argparse

from w3c_crosswalk.cli.common import add_common_output_args, add_live_signer_args, emit_json, load_passcode
from w3c_crosswalk.isomer_runtime import IsomerRuntimeDoer
from w3c_crosswalk.services import project_status
from w3c_crosswalk.status import JsonFileStatusStore


class ProjectStatusDoer(IsomerRuntimeDoer):
    """Project one ACDC status record as a single explicit CLI doer."""

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
        result = project_status(
            store=JsonFileStatusStore(self.args.store),
            projector=self.projector,
            said=self.args.said,
            issuer_did=self.args.issuer_did,
            base_url=self.args.base_url,
        )
        emit_json(result, output=self.args.output)
        return True


def handle(args: argparse.Namespace):
    """Return doers for `crosswalk status project`."""
    return [ProjectStatusDoer(args=args)]


def add_project_command(subparsers: argparse._SubParsersAction[argparse.ArgumentParser]) -> None:
    """Register `crosswalk status project`."""
    status_project = subparsers.add_parser("project", help="Project accepted KERI TEL state into status")
    status_project.add_argument("--said", required=True, help="Source ACDC credential SAID to project")
    status_project.add_argument("--issuer-did", required=True)
    status_project.add_argument("--store", required=True)
    status_project.add_argument("--base-url", required=True)
    add_live_signer_args(status_project)
    add_common_output_args(status_project)
    status_project.set_defaults(handler=handle)
