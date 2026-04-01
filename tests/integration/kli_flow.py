"""In-process KERIpy workflow helpers for crosswalk integration tests."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any

from hio.base import doing
from keri import kering
from keri.app import agenting, configing, connecting, forwarding, grouping, habbing, indirecting, notifying, oobiing, signing as appsigning
from keri.app.cli.commands.delegate.confirm import ConfirmDoer
from keri.app.cli.commands.ipex.admit import AdmitDoer
from keri.app.cli.commands.ipex.grant import GrantDoer
from keri.app.cli.commands.incept import InceptDoer
from keri.app.cli.commands.oobi.resolve import OobiDoer
from keri.app.cli.commands.query import LaunchDoer as QueryDoer
from keri.app.cli.commands.vc.create import CredentialIssuer
from keri.app.cli.commands.vc.registry.incept import RegistryInceptor
from keri.app.cli.common import existing
from keri import core
from keri.core import coring, eventing, parsing, serdering, signing as coresigning
from keri.help import helping
from keri.peer import exchanging
from keri.vc import protocoling
from keri.vdr import credentialing, eventing as teventing, verifying

from w3c_crosswalk.constants import LE_SCHEMA, QVI_SCHEMA, VRD_AUTH_SCHEMA, VRD_SCHEMA

from .helpers import patched_home, poll_until, run_doers_until, write_json


COMMON_CONFIG_FILE = "common-habery-config.json"
WORKFLOW_TOCK = 0.03125


def _close_hby(hby) -> None:
    """Close one habery when it was initialized successfully."""
    if hby is None or not getattr(hby, "inited", False):
        return
    hby.close(clear=hby.temp)


def _close_notifier(notifier) -> None:
    """Close one notifier's backing `Noter` database."""
    if notifier is None:
        return
    notifier.noter.close(clear=notifier.noter.temp)


def _cleanup_incept_doers(doers: list) -> None:
    """Close resources owned by one or more `InceptDoer` instances."""
    for doer in doers:
        _close_hby(doer.hby)


def _cleanup_oobi_doers(doers: list) -> None:
    """Close resources owned by one or more `OobiDoer` instances."""
    for doer in doers:
        _close_hby(doer.hby)


def _cleanup_query_doers(doers: list) -> None:
    """Close resources owned by one or more `QueryDoer` instances."""
    for doer in doers:
        _close_hby(doer.hby)


def _cleanup_mailbox_sync_resources(*, notifier, rgy, hby) -> None:
    """Close resources opened only to poll incoming mailbox traffic."""
    _close_notifier(notifier)
    rgy.close()
    _close_hby(hby)


@dataclass(frozen=True)
class Actor:
    """Identity metadata for one participant in the live single-sig workflow."""

    name: str
    alias: str
    salt: str
    passcode: str


@dataclass
class WorkflowState:
    """Accumulate issued prefixes and credential SAIDs across the live flow."""

    geda: Actor
    qvi: Actor
    le: Actor
    geda_prefix: str = ""
    qvi_prefix: str = ""
    le_prefix: str = ""
    qvi_credential_said: str = ""
    le_credential_said: str = ""
    vrd_auth_said: str = ""
    vrd_said: str = ""


def default_workflow_state() -> WorkflowState:
    """Return the canonical actors and deterministic credentials for the live test."""
    return WorkflowState(
        geda=Actor(name="geda", alias="geda", salt="0AA2-S2YS4KqvlSzO7faIEpH", passcode="18b2c88fd050851c45c67"),
        qvi=Actor(name="qvi", alias="qvi", salt="0ACgCmChLaw_qsLycbqBoxDK", passcode="e6b3402845de8185abe94"),
        le=Actor(name="legal-entity", alias="legal-entity", salt="0AB90ainJghoJa8BzFmGiEWa", passcode="tcc6Yj4JM8MfTDs1IiidP"),
    )


def _default_witness_aid(live_stack: dict) -> str:
    """Return the default witness AID used by the single-sig test topology."""
    return live_stack["witness_aids"][0]


def _single_sig_icp_config(live_stack: dict, *, witness_aid: str | None = None) -> dict[str, Any]:
    """Build the inception config used for standard single-sig participants."""
    witness_aid = witness_aid if witness_aid is not None else _default_witness_aid(live_stack)
    return {
        "transferable": True,
        "wits": [witness_aid],
        "toad": 1,
        "icount": 1,
        "ncount": 1,
        "isith": "1",
        "nsith": "1",
    }


def _delegated_icp_config(live_stack: dict, delegator_prefix: str, *, witness_aid: str | None = None) -> dict[str, Any]:
    """Build the inception config used for the delegated QVI identifier."""
    witness_aid = witness_aid if witness_aid is not None else _default_witness_aid(live_stack)
    return {
        "delpre": delegator_prefix,
        "icount": 1,
        "ncount": 1,
        "transferable": True,
        "wits": [witness_aid],
        "toad": 1,
        "isith": "1",
        "nsith": "1",
    }


def _keystore_path(live_stack: dict, actor: Actor) -> Path:
    """Return the expected keystore path for one actor inside the live stack."""
    return Path(live_stack["home"]) / ".keri" / "ks" / actor.name


def _habery_exists(live_stack: dict, actor: Actor) -> bool:
    """Return whether the actor's KERI keystore already exists."""
    return _keystore_path(live_stack, actor).exists()


@contextmanager
def _common_config(live_stack: dict):
    """Open the shared KERI config used by newly initialized actors."""
    cf = configing.Configer(
        name=COMMON_CONFIG_FILE,
        base="",
        headDirPath=str(live_stack["config_root"]),
        temp=False,
        reopen=True,
        clear=False,
    )
    try:
        yield cf
    finally:
        cf.close()


@contextmanager
def _existing_actor_hby(live_stack: dict, actor: Actor):
    """Open an existing actor habery inside the live stack's HOME sandbox."""
    with patched_home(Path(live_stack["home"])):
        with existing.existingHby(name=actor.name, base="", bran=actor.passcode) as hby:
            yield hby


def _maybe_hab(live_stack: dict, actor: Actor):
    """Return an actor habitat when it exists, otherwise `None`."""
    if not _habery_exists(live_stack, actor):
        return None
    with _existing_actor_hby(live_stack, actor) as hby:
        return hby.habByName(actor.alias)


def _aid_for_actor(live_stack: dict, actor: Actor) -> str:
    """Return the current AID prefix for an actor when available."""
    hab = _maybe_hab(live_stack, actor)
    return hab.pre if hab is not None else ""


def _resolved_oobi_count(live_stack: dict, actor: Actor) -> int:
    """Count resolved OOBIs for one actor."""
    if not _habery_exists(live_stack, actor):
        return 0
    with _existing_actor_hby(live_stack, actor) as hby:
        return hby.db.roobi.cntAll()


def _load_json(path: Path) -> dict[str, Any]:
    """Load one JSON workflow artifact from disk."""
    return json.loads(path.read_text(encoding="utf-8"))


def _credential_saids(live_stack: dict, actor: Actor, *, schema: str, issued: bool) -> list[str]:
    """List credential SAIDs for an actor filtered by schema and direction."""
    if not _habery_exists(live_stack, actor):
        return []

    with _existing_actor_hby(live_stack, actor) as hby:
        hab = hby.habByName(actor.alias)
        if hab is None:
            return []
        rgy = credentialing.Regery(hby=hby, name=actor.name, base=hby.base, temp=hby.temp)
        try:
            saiders = (rgy.reger.issus.get(keys=hab.pre) if issued else rgy.reger.subjs.get(keys=hab.pre)) or []
            scads = rgy.reger.schms.get(keys=schema) or []
            allowed = {saider.qb64 for saider in scads}
            return [saider.qb64 for saider in saiders if saider.qb64 in allowed]
        finally:
            rgy.close()


def _pending_grant_saids(
    live_stack: dict,
    actor: Actor,
    *,
    credential_said: str | None = None,
    sender_prefix: str | None = None,
) -> list[str]:
    """Return unresolved incoming `/ipex/grant` SAIDs filtered by credential context."""
    if not _habery_exists(live_stack, actor):
        return []

    with _existing_actor_hby(live_stack, actor) as hby:
        notifier = notifying.Notifier(hby=hby)
        try:
            saids: list[str] = []
            for _, note in notifier.noter.notes.getItemIter():
                attrs = note.attrs
                said = attrs.get("d")
                if not said:
                    continue
                exn, _ = exchanging.cloneMessage(hby, said)
                if exn is None or exn.ked.get("r") != "/ipex/grant":
                    continue
                sender = exn.ked.get("i")
                if sender in hby.habs:
                    continue
                if sender_prefix is not None and sender != sender_prefix:
                    continue

                acdc = exn.ked.get("e", {}).get("acdc", {})
                if credential_said is not None and acdc.get("d") != credential_said:
                    continue

                if hby.db.erpy.get(keys=(exn.said,)) is not None:
                    continue
                saids.append(exn.said)
            return saids
        finally:
            _close_notifier(notifier)


def _exchange_saids(live_stack: dict, actor: Actor, *, route: str) -> list[str]:
    """Return exchange SAIDs stored for one actor and one exchange route."""
    if not _habery_exists(live_stack, actor):
        return []

    with _existing_actor_hby(live_stack, actor) as hby:
        saids: list[str] = []
        for (said,), _ in hby.db.exns.getItemIter():
            exn, _ = exchanging.cloneMessage(hby, said)
            if exn is None or exn.ked.get("r") != route:
                continue
            saids.append(said)
        return saids


def _exchange_exists(live_stack: dict, actor: Actor, *, said: str) -> bool:
    """Return whether one specific exchange SAID exists in an actor store."""
    if not _habery_exists(live_stack, actor):
        return False

    with _existing_actor_hby(live_stack, actor) as hby:
        exn, _ = exchanging.cloneMessage(hby, said)
        return exn is not None


def _grant_exchange_said(
    live_stack: dict,
    actor: Actor,
    *,
    credential_said: str,
    recipient_prefix: str | None = None,
) -> str:
    """Return the grant exchange SAID matching one issued credential.

    Exchange insertion order is not a safe selector once an actor has sent
    multiple grants. Match on the embedded ACDC SAID and, when present, the
    grant payload recipient instead.
    """
    if not _habery_exists(live_stack, actor):
        return ""

    with _existing_actor_hby(live_stack, actor) as hby:
        matched: list[str] = []
        for (said,), _ in hby.db.exns.getItemIter():
            exn, _ = exchanging.cloneMessage(hby, said)
            if exn is None or exn.ked.get("r") != "/ipex/grant":
                continue

            acdc = exn.ked.get("e", {}).get("acdc", {})
            if acdc.get("d") != credential_said:
                continue

            payload = exn.ked.get("a", {})
            if recipient_prefix is not None and isinstance(payload, dict):
                payload_recp = payload.get("i")
                if payload_recp is not None and payload_recp != recipient_prefix:
                    continue

            matched.append(said)

        return matched[-1] if matched else ""


def init_habery(live_stack: dict, actor: Actor) -> None:
    """Initialize an actor keystore, habery, and configured OOBIs if absent."""
    if _habery_exists(live_stack, actor):
        return

    with patched_home(Path(live_stack["home"])):
        with _common_config(live_stack) as cf:
            hby = habbing.Habery(name=actor.name, base="", temp=False, cf=cf, salt=actor.salt, bran=actor.passcode)
            rgy = credentialing.Regery(hby=hby, name=actor.name, base="", temp=False)
            try:
                configured_oobis = hby.db.oobis.cntAll()
                well_knowns = [oobi for (oobi,), _ in hby.db.woobi.getItemIter()]
                if configured_oobis or well_knowns:
                    obi = oobiing.Oobiery(hby=hby)
                    authn = oobiing.Authenticator(hby=hby)
                    run_doers_until(
                        f"bootstrap configured oobis for {actor.alias}",
                        [habbing.HaberyDoer(habery=hby), *obi.doers, *authn.doers],
                        timeout=90.0,
                        tock=WORKFLOW_TOCK,
                        ready=lambda: (
                            hby.db.roobi.cntAll() >= configured_oobis
                            and (
                                not well_knowns
                                or set(well_knowns).issubset({wk.url for (_,), wk in hby.db.wkas.getItemIter(keys=b"")})
                            )
                        ),
                        observe=lambda: {
                            "actor": actor.alias,
                            "configured_oobis": configured_oobis,
                            "resolved_oobis": hby.db.roobi.cntAll(),
                            "well_knowns": len(well_knowns),
                        },
                    )
            finally:
                rgy.close()
                hby.close(clear=hby.temp)


def init_and_incept_single_sig(
    live_stack: dict,
    actor: Actor,
    *,
    alias: str | None = None,
    witness_aid: str | None = None,
) -> str:
    """Initialize an actor and incept one single-sig identifier."""
    init_habery(live_stack, actor)
    alias = actor.alias if alias is None else alias
    with patched_home(Path(live_stack["home"])):
        incept_doer = InceptDoer(
            name=actor.name,
            base="",
            alias=alias,
            bran=actor.passcode,
            endpoint=False,
            proxy=None,
            cnfg=None,
            **_single_sig_icp_config(live_stack, witness_aid=witness_aid),
        )
        run_doers_until(
            f"incept single-sig aid for {alias}",
            [incept_doer],
            timeout=120.0,
            tock=WORKFLOW_TOCK,
            observe=lambda: {"actor": actor.alias, "alias": alias},
            cleanup=_cleanup_incept_doers,
        )
    return aid(live_stack, Actor(name=actor.name, alias=alias, salt=actor.salt, passcode=actor.passcode))


def aid(live_stack: dict, actor: Actor) -> str:
    """Return the actor's prefix or raise when the AID is missing."""
    prefix = _aid_for_actor(live_stack, actor)
    if not prefix:
        raise RuntimeError(f"unable to find aid prefix for actor {actor.alias}")
    return prefix


def _preferred_oobi_url(hab, *, eid: str) -> str:
    """Return the preferred base endpoint for OOBI generation.

    This follows the same witness/controller URL selection logic used by
    KERIpy's `oobi generate` command.
    """
    urls = hab.fetchUrls(eid=eid, scheme=kering.Schemes.http) or hab.fetchUrls(eid=eid, scheme=kering.Schemes.https)
    if not urls:
        raise kering.ConfigurationError(f"unable to query endpoint {eid}, no http endpoint")
    return urls[kering.Schemes.https] if kering.Schemes.https in urls else urls[kering.Schemes.http]


def _generate_oobi_for_hab(hab, *, role: str, eid: str | None = None) -> str:
    """Generate one OOBI URL for a habitat using KERIpy's role semantics."""
    if role == kering.Roles.witness:
        if not hab.kever.wits:
            raise ValueError(f"{hab.name} identifier {hab.pre} does not have any witnesses")
        target = eid if eid is not None else hab.kever.wits[0]
        url = _preferred_oobi_url(hab, eid=target)
        return f"{url.rstrip('/')}/oobi/{hab.pre}/witness"
    if role == kering.Roles.controller:
        url = _preferred_oobi_url(hab, eid=hab.pre)
        return f"{url.rstrip('/')}/oobi/{hab.pre}/controller"
    raise ValueError(f"unsupported oobi role {role}")


def witness_oobi(live_stack: dict, actor: Actor) -> str:
    """Build the witness OOBI URL for an actor's identifier."""
    with _existing_actor_hby(live_stack, actor) as hby:
        hab = hby.habByName(actor.alias)
        if hab is None:
            raise ValueError(f"unable to locate habitat alias '{actor.alias}' in habery '{actor.name}'")
        return _generate_oobi_for_hab(hab, role=kering.Roles.witness)


def resolve_oobi(live_stack: dict, recipient: Actor, *, alias: str, oobi: str) -> None:
    """Resolve one OOBI into a recipient actor's local KERI state."""
    with patched_home(Path(live_stack["home"])):
        resolve_doer = OobiDoer(name=recipient.name, oobi=oobi, oobiAlias=alias, force=False, bran=recipient.passcode, base="")
        run_doers_until(
            f"resolve oobi {alias} into {recipient.alias}",
            [resolve_doer],
            timeout=90.0,
            tock=WORKFLOW_TOCK,
            observe=lambda: {"actor": recipient.alias, "oobi": oobi},
            cleanup=_cleanup_oobi_doers,
        )


def _query_keystate(live_stack: dict, actor: Actor, *, prefix: str) -> None:
    """Query witness-backed key state for one remote identifier."""
    with patched_home(Path(live_stack["home"])):
        query_doer = QueryDoer(name=actor.name, alias=actor.alias, base="", bran=actor.passcode, pre=prefix, anchor=None)
        run_doers_until(
            f"query keystate for {prefix} from {actor.alias}",
            [query_doer],
            timeout=30.0,
            tock=WORKFLOW_TOCK,
            observe=lambda: {"actor": actor.alias, "prefix": prefix},
            cleanup=_cleanup_query_doers,
        )


def create_delegation_proxy(
    live_stack: dict,
    delegate: Actor,
    *,
    proxy_alias: str = "proxy",
    witness_aid: str | None = None,
) -> str:
    """Create the single-sig proxy identifier used for delegated inception signaling."""
    return init_and_incept_single_sig(
        live_stack,
        delegate,
        alias=proxy_alias,
        witness_aid=witness_aid,
    )


def create_delegated_qvi(
    live_stack: dict,
    delegator: Actor,
    delegate: Actor,
    delegator_prefix: str,
    *,
    proxy_alias: str = "proxy",
    witness_aid: str | None = None,
) -> str:
    """Create the delegated QVI identifier and anchor it from the delegator.

    The delegate keystore/habery and delegation proxy should already exist
    before this helper runs.
    """
    init_habery(live_stack, delegate)
    proxy_actor = Actor(name=delegate.name, alias=proxy_alias, salt=delegate.salt, passcode=delegate.passcode)
    if _maybe_hab(live_stack, proxy_actor) is None:
        raise RuntimeError(f"delegation proxy alias '{proxy_alias}' must exist before creating delegated qvi")

    with patched_home(Path(live_stack["home"])):
        delegated_incept_doer = InceptDoer(
            name=delegate.name,
            base="",
            alias=delegate.alias,
            bran=delegate.passcode,
            endpoint=False,
            proxy=proxy_alias,
            cnfg=None,
            **_delegated_icp_config(live_stack, delegator_prefix, witness_aid=witness_aid),
        )
        confirm_doer = ConfirmDoer(
            name=delegator.name,
            base="",
            alias=delegator.alias,
            bran=delegator.passcode,
            interact=True,
            auto=True,
            authenticate=False,
            codes=[],
            codeTime=None,
        )
        run_doers_until(
            f"delegate {delegate.alias} from {delegator.alias}",
            [delegated_incept_doer, confirm_doer],
            timeout=180.0,
            tock=WORKFLOW_TOCK,
            observe=lambda: {"delegate": delegate.alias, "delegator": delegator.alias},
            cleanup=lambda doers: _cleanup_incept_doers([delegated_incept_doer]),
        )
    _query_keystate(live_stack, delegate, prefix=delegator_prefix)
    return aid(live_stack, delegate)


def resolve_pairwise_oobis(live_stack: dict, actors: list[Actor]) -> dict[str, str]:
    """Resolve each actor's witness OOBI into every other actor."""
    oobis = {actor.alias: witness_oobi(live_stack, actor) for actor in actors}
    for recipient in actors:
        for source in actors:
            if source.alias == recipient.alias:
                continue
            resolve_oobi(live_stack, recipient, alias=source.alias, oobi=oobis[source.alias])
    return oobis


def create_registry(live_stack: dict, actor: Actor, *, registry_name: str, usage: str) -> None:
    """Create a credential registry owned by one actor."""
    with patched_home(Path(live_stack["home"])):
        registry_doer = RegistryInceptor(
            name=actor.name,
            base="",
            alias=actor.alias,
            bran=actor.passcode,
            registryName=registry_name,
            usage=usage,
            nonce=coresigning.Salter().qb64,
            estOnly=False,
            noBackers=True,
            baks=[],
        )
        run_doers_until(
            f"incept registry {registry_name} for {actor.alias}",
            [registry_doer],
            timeout=180.0,
            tock=WORKFLOW_TOCK,
            observe=lambda: {"actor": actor.alias, "registry": registry_name},
        )


def _registry_exists(live_stack: dict, actor: Actor, registry_name: str) -> bool:
    """Return whether a named registry already exists for an actor."""
    if not _habery_exists(live_stack, actor):
        return False
    with _existing_actor_hby(live_stack, actor) as hby:
        rgy = credentialing.Regery(hby=hby, name=actor.name, base=hby.base, temp=hby.temp)
        try:
            return rgy.registryByName(registry_name) is not None
        finally:
            rgy.close()


def wait_for_credential_said(
    live_stack: dict,
    actor: Actor,
    *,
    schema: str,
    issued: bool,
    timeout: float = 90.0,
) -> str:
    """Poll until an actor has a credential SAID matching the requested shape."""
    return poll_until(
        lambda: (_credential_saids(live_stack, actor, schema=schema, issued=issued) or [""])[-1],
        ready=lambda said: bool(said),
        timeout=timeout,
        interval=1.0,
        describe=f"{actor.alias} credential schema={schema} issued={issued}",
    )


def create_credential(
    live_stack: dict,
    issuer: Actor,
    *,
    registry_name: str,
    schema: str,
    recipient_prefix: str,
    data_path: Path,
    rules_path: Path,
    edges_path: Path | None = None,
) -> str:
    """Issue one credential and return its resulting SAID."""
    with patched_home(Path(live_stack["home"])):
        issue_doer = CredentialIssuer(
            name=issuer.name,
            alias=issuer.alias,
            base="",
            bran=issuer.passcode,
            registryName=registry_name,
            schema=schema,
            recipient=recipient_prefix,
            data=_load_json(data_path),
            edges=_load_json(edges_path) if edges_path is not None else None,
            rules=_load_json(rules_path),
            credential=None,
            timestamp=helping.nowIso8601(),
            private=False,
            private_credential_nonce=None,
            private_subject_nonce=None,
        )
        run_doers_until(
            f"issue credential {schema} from {issuer.alias}",
            [issue_doer],
            timeout=180.0,
            tock=WORKFLOW_TOCK,
            observe=lambda: {"issuer": issuer.alias, "schema": schema},
        )
    return wait_for_credential_said(live_stack, issuer, schema=schema, issued=True)


def wait_for_grant(
    live_stack: dict,
    recipient: Actor,
    *,
    credential_said: str,
    sender_prefix: str | None = None,
    timeout: float = 90.0,
) -> str:
    """Poll for the unresolved incoming grant tied to one credential SAID."""
    return poll_until(
        lambda: (
            _pending_grant_saids(
                live_stack,
                recipient,
                credential_said=credential_said,
                sender_prefix=sender_prefix,
            )
            or [""]
        )[-1],
        ready=lambda said: bool(said),
        timeout=timeout,
        interval=1.0,
        describe=f"grant for {recipient.alias} credential={credential_said}",
    )


def wait_for_exchange(
    live_stack: dict,
    actor: Actor,
    *,
    said: str,
    timeout: float = 90.0,
) -> str:
    """Poll until one exact exchange SAID is present in an actor store."""
    return poll_until(
        lambda: said if _exchange_exists(live_stack, actor, said=said) else "",
        ready=lambda value: bool(value),
        timeout=timeout,
        interval=1.0,
        describe=f"{actor.alias} exchange {said}",
    )


def sync_credential_mailbox_until_exchange(
    live_stack: dict,
    recipient: Actor,
    *,
    said: str,
    timeout: float = 90.0,
) -> str:
    """Poll the recipient mailbox until one exact credential exchange is stored.

    `AdmitDoer` expects the referenced grant exn to already exist in the
    recipient's local exchange store. This helper performs the explicit mailbox
    receive/sync phase before admission so the test does not race the incoming
    `/credential` delivery path.
    """
    with patched_home(Path(live_stack["home"])):
        hby = existing.setupHby(name=recipient.name, base="", bran=recipient.passcode)
        notifier = notifying.Notifier(hby=hby)
        rgy = credentialing.Regery(hby=hby, name=recipient.name, base="")
        vry = verifying.Verifier(hby=hby, reger=rgy.reger)
        exc = exchanging.Exchanger(hby=hby, handlers=[])
        protocoling.loadHandlers(hby=hby, exc=exc, notifier=notifier)
        mbx = indirecting.MailboxDirector(
            hby=hby,
            topics=["/replay", "/reply", "/credential"],
            exc=exc,
            verifier=vry,
        )
        try:
            run_doers_until(
                f"sync credential mailbox for {recipient.alias} exchange {said}",
                [mbx],
                timeout=timeout,
                tock=WORKFLOW_TOCK,
                ready=lambda: exchanging.cloneMessage(hby, said)[0] is not None,
                observe=lambda: {
                    "actor": recipient.alias,
                    "exchange_said": said,
                    "credential_mail_seen": str(mbx.times.get("/credential")),
                    "notices": notifier.noter.notes.cntAll(),
                },
            )
        finally:
            _cleanup_mailbox_sync_resources(notifier=notifier, rgy=rgy, hby=hby)
    return said


def grant_credential(live_stack: dict, issuer: Actor, *, recipient_prefix: str, credential_said: str) -> str:
    """Send an IPEX grant for a credential and return the issuer-side exchange SAID."""
    with patched_home(Path(live_stack["home"])):
        grant_doer = GrantDoer(
            name=issuer.name,
            alias=issuer.alias,
            base="",
            bran=issuer.passcode,
            said=credential_said,
            recp=recipient_prefix,
            message="",
            timestamp=helping.nowIso8601(),
        )
        run_doers_until(
            f"grant credential {credential_said} from {issuer.alias}",
            [grant_doer],
            timeout=180.0,
            tock=WORKFLOW_TOCK,
            observe=lambda: {"credential_said": credential_said, "recipient": recipient_prefix},
        )
    return poll_until(
        lambda: _grant_exchange_said(
            live_stack,
            issuer,
            credential_said=credential_said,
            recipient_prefix=recipient_prefix,
        ),
        ready=lambda said: bool(said),
        timeout=30.0,
        interval=1.0,
        describe=f"grant exchange for {issuer.alias} credential={credential_said}",
    )


def admit_grant(
    live_stack: dict,
    recipient: Actor,
    *,
    expected_schema: str,
    grant_said: str,
) -> str:
    """Admit a credential grant and return the saved credential SAID.

    The caller must pass the exact GRANT exchange SAID returned by the grant
    workflow. This helper does not accept credential-based fallback lookup.
    """
    sync_credential_mailbox_until_exchange(live_stack, recipient, said=grant_said)
    with patched_home(Path(live_stack["home"])):
        admit_doer = AdmitDoer(
            name=recipient.name,
            alias=recipient.alias,
            base="",
            bran=recipient.passcode,
            said=grant_said,
            message="",
            timestamp=helping.nowIso8601(),
        )
        run_doers_until(
            f"admit grant {grant_said} for {recipient.alias}",
            [admit_doer],
            timeout=180.0,
            tock=WORKFLOW_TOCK,
            observe=lambda: {"actor": recipient.alias, "grant_said": grant_said},
        )
    return wait_for_credential_said(live_stack, recipient, schema=expected_schema, issued=False)


def saidify_json(live_stack: dict, path: Path) -> Path:
    """Recompute and persist the SAID of a JSON SAD fixture or artifact."""
    sad = _load_json(path)
    _, out = coring.Saider.saidify(sad=sad, label="d")
    path.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return path


def render_template(template_path: Path, output_path: Path, replacements: dict[str, str]) -> Path:
    """Render a small text template into the live stack's temp directory."""
    text = template_path.read_text(encoding="utf-8")
    for key, value in replacements.items():
        text = text.replace(key, value)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(text, encoding="utf-8")
    return output_path


def clone_credential_sad(live_stack: dict, actor: Actor, *, said: str) -> dict[str, Any]:
    """Clone one saved credential SAD from an actor's credential store."""
    with _existing_actor_hby(live_stack, actor) as hby:
        rgy = credentialing.Regery(hby=hby, name=actor.name, base=hby.base, temp=hby.temp)
        try:
            creder, *_ = rgy.reger.cloneCred(said=said)
            return creder.sad
        finally:
            rgy.close()


def validate_chain(
    *,
    qvi_credential: dict[str, Any],
    le_credential: dict[str, Any],
    vrd_auth: dict[str, Any],
    vrd: dict[str, Any],
    qvi_prefix: str,
    le_prefix: str,
) -> None:
    """Assert that the live-issued credential chain has the expected linkage."""
    assert qvi_credential["s"] == QVI_SCHEMA
    assert le_credential["s"] == LE_SCHEMA
    assert vrd_auth["s"] == VRD_AUTH_SCHEMA
    assert vrd["s"] == VRD_SCHEMA
    assert le_credential["e"]["qvi"]["n"] == qvi_credential["d"]
    assert vrd_auth["e"]["le"]["n"] == le_credential["d"]
    assert vrd["e"]["le"]["n"] == le_credential["d"]
    assert vrd_auth["a"]["i"] == qvi_prefix
    assert vrd["a"]["AID"] == le_prefix
