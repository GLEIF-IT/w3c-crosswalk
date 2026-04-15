"""Runtime ownership for projecting W3C isomers from local KERI state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hio.base import doing
from keri.app.cli.common import existing
from keri.vdr import credentialing

from .keri_projection import ACDCProjector
from .signing import HabSigner


class IsomerRuntimeError(RuntimeError):
    """Raised when local KERI state cannot be opened for isomer projection."""


@dataclass
class IsomerSignerRuntime:
    """Own opened KERI state for signer-only isomer operations."""

    hby: Any
    hab: Any
    signer: HabSigner

    def close(self) -> None:
        """Close the owned Habery."""
        self.hby.close()


@dataclass
class IsomerRuntime:
    """Own opened KERI state used to generate W3C isomers of ACDC/TEL state."""

    hby: Any
    hab: Any
    rgy: Any
    projector: ACDCProjector
    signer: HabSigner

    def close(self) -> None:
        """Close owned Regery and Habery resources in dependency order."""
        if hasattr(self.rgy, "close"):
            self.rgy.close()
        self.hby.close()


def open_isomer_runtime(*, name: str, base: str = "", alias: str, passcode: str | None = None) -> IsomerRuntime:
    """Open local KERI state needed to project W3C isomers from accepted ACDC state."""
    hby = existing.setupHby(name=name, base=base, bran=passcode)
    rgy = None
    try:
        hab = hby.habByName(alias)
        if hab is None:
            raise IsomerRuntimeError(f"unable to locate habitat alias '{alias}' in habery '{name}'")
        rgy = credentialing.Regery(hby=hby, name=name, base=base)
        projector = ACDCProjector(hby=hby, hab=hab, rgy=rgy)
        signer = HabSigner(hab=hab)
        return IsomerRuntime(hby=hby, hab=hab, rgy=rgy, projector=projector, signer=signer)
    except Exception:
        if rgy is not None and hasattr(rgy, "close"):
            rgy.close()
        hby.close()
        raise


def open_isomer_signer_runtime(*, name: str, base: str = "", alias: str, passcode: str | None = None) -> IsomerSignerRuntime:
    """Open local KERI state needed for signer-only isomer commands."""
    hby = existing.setupHby(name=name, base=base, bran=passcode)
    try:
        hab = hby.habByName(alias)
        if hab is None:
            raise IsomerRuntimeError(f"unable to locate habitat alias '{alias}' in habery '{name}'")
        return IsomerSignerRuntime(hby=hby, hab=hab, signer=HabSigner(hab=hab))
    except Exception:
        hby.close()
        raise


class _IsomerRuntimeOwner:
    """Shared lifecycle helper for HIO doers that own an IsomerRuntime."""

    def __init__(self, *, name: str, base: str, alias: str, passcode: str | None):
        self.name = name
        self.base = base
        self.alias = alias
        self.passcode = passcode
        self.runtime: IsomerRuntime | None = None

    @property
    def projector(self) -> ACDCProjector:
        """Return the opened projector for subclasses."""
        if self.runtime is None:
            raise IsomerRuntimeError("isomer runtime has not been opened")
        return self.runtime.projector

    @property
    def signer(self) -> HabSigner:
        """Return the opened signer for subclasses."""
        if self.runtime is None:
            raise IsomerRuntimeError("isomer runtime has not been opened")
        return self.runtime.signer

    def open_runtime(self) -> None:
        """Open the owned runtime once."""
        if self.runtime is None:
            self.runtime = open_isomer_runtime(
                name=self.name,
                base=self.base,
                alias=self.alias,
                passcode=self.passcode,
            )

    def close_runtime(self) -> None:
        """Close the owned runtime once."""
        if self.runtime is not None:
            self.runtime.close()
            self.runtime = None


class _IsomerSignerRuntimeOwner:
    """Shared lifecycle helper for HIO doers that only need a HabSigner."""

    def __init__(self, *, name: str, base: str, alias: str, passcode: str | None):
        self.name = name
        self.base = base
        self.alias = alias
        self.passcode = passcode
        self.runtime: IsomerSignerRuntime | None = None

    @property
    def signer(self) -> HabSigner:
        """Return the opened signer for subclasses."""
        if self.runtime is None:
            raise IsomerRuntimeError("isomer signer runtime has not been opened")
        return self.runtime.signer

    def open_runtime(self) -> None:
        """Open the owned signer runtime once."""
        if self.runtime is None:
            self.runtime = open_isomer_signer_runtime(
                name=self.name,
                base=self.base,
                alias=self.alias,
                passcode=self.passcode,
            )

    def close_runtime(self) -> None:
        """Close the owned signer runtime once."""
        if self.runtime is not None:
            self.runtime.close()
            self.runtime = None


class IsomerRuntimeDoer(_IsomerRuntimeOwner, doing.Doer):
    """Doer that opens IsomerRuntime on enter and closes it on exit."""

    def __init__(self, *, name: str, base: str, alias: str, passcode: str | None, **kwa):
        _IsomerRuntimeOwner.__init__(self, name=name, base=base, alias=alias, passcode=passcode)
        doing.Doer.__init__(self, **kwa)

    def enter(self):
        """Open local KERI state when the doer enters the scheduler."""
        self.open_runtime()

    def exit(self):
        """Close local KERI state when the doer leaves the scheduler."""
        self.close_runtime()


class IsomerRuntimeDoDoer(_IsomerRuntimeOwner, doing.DoDoer):
    """DoDoer that owns IsomerRuntime while scheduling child doers."""

    def __init__(self, *, name: str, base: str, alias: str, passcode: str | None, doers=None, always=False, **kwa):
        _IsomerRuntimeOwner.__init__(self, name=name, base=base, alias=alias, passcode=passcode)
        doing.DoDoer.__init__(self, doers=doers, always=always, **kwa)

    def build_doers(self):
        """Return child doers after runtime opens; subclasses may override."""
        return None

    def enter(self, doers=None):
        """Open runtime, allow subclasses to build child doers, then enter children."""
        self.open_runtime()
        if doers is None:
            built = self.build_doers()
            if built is not None:
                self.doers = list(built)
        return doing.DoDoer.enter(self, doers=doers)

    def exit(self, deeds=None):
        """Close children first, then close the owned runtime."""
        try:
            return doing.DoDoer.exit(self, deeds=deeds)
        finally:
            self.close_runtime()


class IsomerSignerRuntimeDoer(_IsomerSignerRuntimeOwner, doing.Doer):
    """Doer that opens signer-only IsomerRuntime state on enter and closes it on exit."""

    def __init__(self, *, name: str, base: str, alias: str, passcode: str | None, **kwa):
        _IsomerSignerRuntimeOwner.__init__(self, name=name, base=base, alias=alias, passcode=passcode)
        doing.Doer.__init__(self, **kwa)

    def enter(self):
        """Open local KERI signer state when the doer enters the scheduler."""
        self.open_runtime()

    def exit(self):
        """Close local KERI signer state when the doer leaves the scheduler."""
        self.close_runtime()
