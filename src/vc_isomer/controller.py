"""Top-level command controller for running isomer doers.

This module intentionally mirrors the KERIpy CLI mental model:

- command handlers return doers
- one top-level controller owns the process Doist
- individual commands and helper doers never create their own private Doists
"""

from __future__ import annotations

from hio.base import doing


def run_controller(doers: list[doing.Doer], *, expire: float = 0.0, tock: float = 0.03125) -> None:
    """Run one command's doers through the single top-level process Doist."""
    doing.Doist(limit=expire, tock=tock, real=True).do(doers=doers)
