"""KERI-state backed projection helpers for W3C isomer artifacts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from keri.core import coring

from .common import canonicalize_did_url, canonicalize_did_webs
from .profile import transpose_acdc_to_w3c_vc
from .status import CredentialStatusRecord


ACTIVE_TEL_ILKS = {coring.Ilks.iss, coring.Ilks.bis}
REVOKED_TEL_ILKS = {coring.Ilks.rev, coring.Ilks.brv}


class ProjectorError(RuntimeError):
    """Raised when local KERI state cannot support a W3C projection."""


@dataclass(frozen=True)
class CredState:
    """Accepted TEL state normalized for W3C projection."""

    # TEL event ilk from Tever.vcState(...).et: iss/bis means active, rev/brv means revoked.
    ilk: str
    # Latest TEL event SAID/digest from Tever.vcState(...).d.
    said: str
    # KEL sequence number from the TEL state's anchoring seal, state.a["s"]; this is not TEL sequence state.s.
    sequence: int
    # TEL event timestamp from Tever.vcState(...).dt.
    date: str

    @property
    def revoked(self) -> bool:
        """Return whether the accepted TEL state marks the credential revoked."""
        return self.ilk in REVOKED_TEL_ILKS

    @property
    def active(self) -> bool:
        """Return whether the accepted TEL state marks the credential active."""
        return self.ilk in ACTIVE_TEL_ILKS


@dataclass(frozen=True)
class CredProjection:
    """Source credential plus the TEL state that authorizes its projection."""

    # Expanded ACDC SAD cloned from Regery.reger.cloneCred(said).sad.
    acdc: dict[str, Any]
    # Accepted TEL authority for this ACDC, derived from Tever.vcState(acdc["d"]).
    state: CredState


class ACDCProjector:
    """Project accepted local KEL, TEL, and ACDC credential state into W3C-facing artifacts.

    This adapter receives already-opened KERIpy state. It does not own or close
    Habery, Hab, or Regery resources; that lifecycle belongs to IsomerRuntime.
    """

    def __init__(self, *, hby: Any, hab: Any, rgy: Any):
        self.hby = hby
        self.hab = hab
        self.rgy = rgy

    def clone_credential(self, said: str) -> dict[str, Any]:
        """Clone one accepted ACDC credential from local KERI credential state."""
        return dict(self._clone_creder(said).sad)

    def credential_state(self, said: str) -> CredState:
        """Return accepted TEL state for one locally known ACDC credential."""
        creder = self._clone_creder(said)
        registry_said = getattr(creder, "regi", "") or creder.sad.get("ri")
        if not registry_said:
            raise ProjectorError(f"credential {said} does not reference a registry")

        try:
            tever = self.rgy.reger.tevers[registry_said]
        except (KeyError, TypeError) as exc:
            raise ProjectorError(f"missing TEL registry state for credential {said}: {registry_said}") from exc

        try:
            state = tever.vcState(creder.said)
        except Exception as exc:
            raise ProjectorError(f"unable to read accepted TEL state for credential {said}") from exc
        if state is None:
            raise ProjectorError(f"missing accepted TEL state for credential {said}")

        ilk = getattr(state, "et", "")
        if ilk not in ACTIVE_TEL_ILKS | REVOKED_TEL_ILKS:
            raise ProjectorError(f"unsupported TEL state {ilk!r} for credential {said}")

        return CredState(
            ilk=ilk,
            said=getattr(state, "d", ""),
            sequence=_anchor_sequence(state, said),
            date=getattr(state, "dt", ""),
        )

    def project_credential(self, said: str) -> CredProjection:
        """Return the source credential and its accepted TEL state."""
        return CredProjection(acdc=self.clone_credential(said), state=self.credential_state(said))

    def project_status_record(self, *, said: str, issuer_did: str) -> CredentialStatusRecord:
        """Project one credential into a persisted status-store record."""
        projection = self.project_credential(said)
        return CredentialStatusRecord.from_tel_state(projection.acdc, issuer_did=issuer_did, state=projection.state)

    def project_status(self, *, said: str, issuer_did: str, base_url: str) -> dict[str, Any]:
        """Project one credential into a W3C-facing status resource."""
        return self.project_status_record(said=said, issuer_did=issuer_did).as_status_resource(base_url)

    def project_vc(self, *, said: str, issuer_did: str, verification_method: str, status_base_url: str) -> dict[str, Any]:
        """Project one active source credential into an unsigned W3C VC document."""
        projection = self.project_credential(said)
        if projection.state.revoked:
            raise ProjectorError(f"credential {said} is revoked in accepted TEL state")
        canonical_issuer = canonicalize_did_webs(issuer_did)
        return transpose_acdc_to_w3c_vc(
            projection.acdc,
            issuer_did=canonical_issuer,
            verification_method=canonicalize_did_url(verification_method),
            status_base_url=status_base_url,
        )

    def _clone_creder(self, said: str) -> Any:
        try:
            creder, _prefixer, _seqner, _saider = self.rgy.reger.cloneCred(said)
        except Exception as exc:
            raise ProjectorError(f"unable to clone accepted credential {said}") from exc
        if creder is None:
            raise ProjectorError(f"unable to clone accepted credential {said}")
        return creder


def _hex_or_int(value: Any) -> int:
    """Normalize KERI state sequence values, which are usually hex strings."""
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 16)
    return int(value)


def _anchor_sequence(state: Any, said: str) -> int:
    """Return the KEL sequence number anchoring the latest TEL state."""
    anchor = getattr(state, "a", None)
    if not isinstance(anchor, dict) or "s" not in anchor:
        raise ProjectorError(f"missing KEL anchor sequence for credential {said}")
    # state.s is the TEL sequence number. W3C statusSequence records the KEL anchor sequence instead.
    return _hex_or_int(anchor["s"])
