#!/usr/bin/env python
"""Build a real Signify/KERIA GEDA -> LE VRD chain for W3C presentation E2E.

This script is intentionally a workflow harness, not a shortcut. It talks to a
running KERIA instance through SignifyPy, creates managed AIDs, resolves OOBIs,
creates registries, issues the vLEI chain, admits each grant, waits for the QVI
and LE did:webs DIDs to become ready, and writes a manifest that live
holder-presentation acceptance tests can consume. W3C VC-JWT and VP-JWT
artifacts are assembled later by edge wallet helpers.
"""

from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests
from keri.app import signing as app_signing
from keri.core import coring, eventing
from keri.core import signing as csigning
from keri.core.coring import Tiers
from keri.help import helping
from requests import HTTPError

from signify.app.clienting import SignifyClient
from signifypy_did_webs import ensure_didwebs_setup

QVI_SCHEMA = "EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao"
LE_SCHEMA = "ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY"
VRD_AUTH_SCHEMA = "EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc"
VRD_SCHEMA = "EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP"

DEFAULT_WITNESS_AIDS = [
    "BBilc4-L3tFUnfM_wJr4S4OJanAv_VmF_dJNN6vkf2Ha",
]

LEI = "254900OPPU84GM83MG36"
LEGAL_NAME = "Example Legal Entity LLC"
LEGAL_ADDRESS = "1 Market St, San Francisco, CA, US"
LE_USAGE_DISCLAIMER = (
    "Usage of a valid, unexpired, and non-revoked vLEI Credential, as defined "
    "in the associated Ecosystem Governance Framework, does not assert that "
    "the Legal Entity is trustworthy, honest, reputable in its business "
    "dealings, safe to do business with, or compliant with any laws or that "
    "an implied or expressly intended purpose will be fulfilled."
)
LE_ISSUANCE_DISCLAIMER = (
    "All information in a valid, unexpired, and non-revoked vLEI Credential, "
    "as defined in the associated Ecosystem Governance Framework, is accurate "
    "as of the date the validation process was complete. The vLEI Credential "
    "has been issued to the legal entity or person named in the vLEI "
    "Credential as the subject; and the qualified vLEI Issuer exercised "
    "reasonable care to perform the validation process set forth in the vLEI "
    "Ecosystem Governance Framework."
)


@dataclass
class Actor:
    """One Signify client and the managed identifier it owns."""

    label: str
    client: SignifyClient
    name: str
    passcode: str
    aid: str | None = None


def main() -> None:
    args = parser().parse_args()
    suffix = args.suffix or secrets.token_hex(4)
    validate_schema_oobi_base(args.schema_base_url)

    log("booting Signify clients")
    geda = connect_actor("geda", args, f"{args.alias_prefix}-geda-{suffix}")
    qvi = connect_actor("qvi", args, f"{args.alias_prefix}-qvi-{suffix}")
    le = connect_actor("le", args, f"{args.alias_prefix}-le-{suffix}")
    actors = [geda, qvi, le]

    log("resolving vLEI and VRD schemas")
    for actor in actors:
        resolve_schema_oobis(actor.client, args.schema_base_url)

    log("creating managed AIDs")
    create_actor_aid(geda, args)
    create_actor_aid(qvi, args)
    create_actor_aid(le, args)
    log("resolving actor witness OOBIs")
    exchange_witness_oobis(actors, timeout=args.operation_timeout)
    log("exchanging agent OOBIs")
    exchange_agent_oobis(actors)

    log("publishing QVI did:webs DID")
    qvi_setup = ensure_didwebs_setup(qvi.client, qvi.name, timeout_seconds=args.didwebs_timeout)
    qvi_did = didwebs_did(qvi_setup, qvi.name)

    log("creating credential registries")
    registries = {
        "geda": create_registry(geda.client, geda.name, "geda-vlei"),
        "qvi": create_registry(qvi.client, qvi.name, "qvi-vlei"),
        "le": create_registry(le.client, le.name, "le-vlei"),
    }

    log("issuing QVI credential from GEDA to QVI")
    qvi_cred = issue_and_admit(
        issuer=geda,
        holder=qvi,
        registry_name="geda-vlei",
        schema=QVI_SCHEMA,
        data={"LEI": LEI},
    )
    log("issuing LE credential from QVI to LE")
    le_cred = issue_and_admit(
        issuer=qvi,
        holder=le,
        registry_name="qvi-vlei",
        schema=LE_SCHEMA,
        data={"LEI": LEI},
        edges=source_edges("qvi", qvi_cred["received"]),
        rules=le_rules(),
    )
    le_setup = ensure_didwebs_setup(le.client, le.name, timeout_seconds=args.didwebs_timeout)
    le_did = didwebs_did(le_setup, le.name)

    log("issuing VRD Auth credential from LE to QVI")
    vrd_auth = issue_and_admit(
        issuer=le,
        holder=qvi,
        registry_name="le-vlei",
        schema=VRD_AUTH_SCHEMA,
        data={
            "i": qvi.aid,
            "AID": le.aid,
            "DID": le_did,
            "HeadquartersAddress": LEGAL_ADDRESS,
            "LegalName": LEGAL_NAME,
        },
        edges=source_edges("le", le_cred["received"]),
        rules=blank_privacy_rules(),
    )
    log("issuing final VRD credential from QVI to LE")
    vrd_cred = issue_and_admit(
        issuer=qvi,
        holder=le,
        registry_name="qvi-vlei",
        schema=VRD_SCHEMA,
        data={
            "i": le.aid,
            "AID": le.aid,
            "DID": le_did,
            "HeadquartersAddress": LEGAL_ADDRESS,
            "LegalName": LEGAL_NAME,
        },
        edges=source_edges("le", le_cred["received"], operator="NI2I"),
        rules=blank_privacy_rules(),
    )

    manifest = {
        "actors": {
            actor.label: {
                "name": actor.name,
                "aid": actor.aid,
                "passcode": actor.passcode,
            }
            for actor in actors
        },
        "registries": registries,
        "credentials": {
            "qvi": qvi_cred["said"],
            "legalEntity": le_cred["said"],
            "vrdAuth": vrd_auth["said"],
            "vrd": vrd_cred["said"],
        },
        "didwebs": {
            "qvi": qvi_did,
            "le": le_did,
        },
        "qviWallet": {
            "name": qvi.name,
            "aid": qvi.aid,
            "passcode": qvi.passcode,
        },
        "holderWallet": {
            "name": le.name,
            "aid": le.aid,
            "passcode": le.passcode,
        },
        "sourceCredentialSaid": vrd_cred["said"],
        "holderPresentation": {
            "issuerName": qvi.name,
            "holderName": le.name,
            "sourceCredentialSaid": vrd_cred["said"],
        },
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"LE wallet alias: {le.name}", file=sys.stderr)
    print(f"LE wallet passcode: {le.passcode}", file=sys.stderr)
    print(f"W3C issuer/QVI wallet alias: {qvi.name}", file=sys.stderr)
    print(f"Holder presentation source VRD credential SAID: {vrd_cred['said']}", file=sys.stderr)
    print(json.dumps(manifest, indent=2, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--admin-url", default="http://127.0.0.1:3901", help="KERIA admin URL")
    p.add_argument("--boot-url", default="http://127.0.0.1:3903", help="KERIA boot URL")
    p.add_argument("--schema-base-url", default="http://127.0.0.1:7723", help="vLEI schema/OOBI base URL")
    p.add_argument("--alias-prefix", default="w3c-vrd", help="alias prefix for created AIDs")
    p.add_argument("--suffix", help="stable suffix for repeatable local debugging")
    p.add_argument("--output", default=".tmp/w3c-vrd-chain-manifest.json", help="manifest output path")
    p.add_argument("--unwitnessed", action="store_true", help="create non-witnessed AIDs")
    p.add_argument("--witness", action="append", default=None, help="witness AID to use; repeatable")
    p.add_argument("--operation-timeout", type=float, default=180.0)
    p.add_argument("--didwebs-timeout", type=float, default=180.0)
    return p


def validate_schema_oobi_base(schema_base_url: str) -> None:
    """Fail before asking KERIA to resolve a schema server with empty OOBIs."""
    for said in (QVI_SCHEMA, LE_SCHEMA, VRD_AUTH_SCHEMA, VRD_SCHEMA):
        url = f"{schema_base_url.rstrip('/')}/oobi/{said}"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        if not response.content:
            raise RuntimeError(
                f"schema OOBI {url} returned an empty body; use the "
                "w3c-crosswalk integration vLEI assets for VRD schemas"
            )


def log(message: str) -> None:
    print(f"[setup-vrd-holder-presentation] {message}", file=sys.stderr, flush=True)


def connect_actor(label: str, args, name: str) -> Actor:
    passcode = random_passcode()
    client = SignifyClient(
        passcode=passcode,
        tier=Tiers.low,
        url=args.admin_url,
        boot_url=args.boot_url,
    )
    client.boot()
    client.connect()
    return Actor(label=label, client=client, name=name, passcode=passcode)


def create_actor_aid(actor: Actor, args) -> None:
    wits = [] if args.unwitnessed else (args.witness or DEFAULT_WITNESS_AIDS)

    _, _, operation = actor.client.identifiers().create(
        actor.name,
        wits=wits,
        toad=str(len(wits)) if wits else "0",
    )
    wait_for_operation(actor.client, operation, timeout=args.operation_timeout)
    hab = actor.client.identifiers().get(actor.name)
    actor.aid = hab["prefix"]

    _, _, endrole_op = actor.client.identifiers().addEndRole(actor.name)
    wait_for_operation(actor.client, endrole_op, timeout=args.operation_timeout)
    wait_for_oobi(actor.client, actor.name, role="agent", timeout=args.operation_timeout)


def resolve_schema_oobis(client: SignifyClient, schema_base_url: str) -> None:
    for said in (QVI_SCHEMA, LE_SCHEMA, VRD_AUTH_SCHEMA, VRD_SCHEMA):
        wait_for_operation(
            client,
            client.oobis().resolve(f"{schema_base_url.rstrip('/')}/oobi/{said}", alias=f"schema-{said[:8]}"),
        )


def exchange_agent_oobis(actors: list[Actor]) -> None:
    for source in actors:
        for target in actors:
            if source is target:
                continue
            oobi = wait_for_oobi(source.client, source.name, role="agent")[0]
            wait_for_operation(target.client, target.client.oobis().resolve(oobi, alias=source.name))


def exchange_witness_oobis(actors: list[Actor], *, timeout: float) -> None:
    """Resolve each actor's generated witness-role OOBIs into every actor."""
    actor_oobis = {
        source.name: wait_for_oobi(source.client, source.name, role="witness", timeout=timeout)
        for source in actors
    }
    for source in actors:
        for target in actors:
            for oobi in actor_oobis[source.name]:
                wait_for_operation(
                    target.client,
                    target.client.oobis().resolve(oobi, alias=source.name),
                    timeout=timeout,
                )


def create_registry(client: SignifyClient, name: str, registry_name: str) -> dict:
    result = client.registries().create(name, registry_name)
    wait_for_operation(client, result.op())
    registry = client.registries().get(name, registry_name)
    return {"name": registry_name, "regk": registry["regk"]}


def issue_and_admit(
    *,
    issuer: Actor,
    holder: Actor,
    registry_name: str,
    schema: str,
    data: dict[str, Any],
    edges: dict[str, Any] | None = None,
    rules: dict[str, Any] | None = None,
) -> dict[str, Any]:
    result = issuer.client.credentials().issue(
        issuer.name,
        registry_name,
        data=data,
        schema=schema,
        recipient=holder.aid,
        edges=edges,
        rules=rules,
        timestamp=helping.nowIso8601(),
    )
    wait_for_operation(issuer.client, result.op())
    wait_for_issued_credential(issuer.client, issuer.aid, result.acdc.said)
    log(
        f"issued credential schema={schema} said={result.acdc.said} "
        f"issuer={issuer.name} holder={holder.name}"
    )

    send_grant(
        issuer.client,
        issuer_name=issuer.name,
        recipient=holder.aid,
        creder=result.acdc,
        iserder=result.iss,
        anc=result.anc,
        sigs=result.sigs,
    )
    log(f"sent IPEX grant said={result.acdc.said} to holder={holder.name}")

    notification = wait_for_grant_notification(holder.client, result.acdc.said)
    log(f"holder={holder.name} received grant notification {notification['a']['d']}")
    admit_op = submit_admit(
        holder.client,
        holder_name=holder.name,
        issuer_prefix=issuer.aid,
        grant_said=notification["a"]["d"],
    )
    if isinstance(admit_op, dict) and "done" in admit_op:
        log(f"waiting for admit operation {admit_op['name']}")
        wait_for_operation(holder.client, admit_op, timeout=120.0)
    received = wait_for_credential(holder.client, result.acdc.said)
    log(f"holder={holder.name} stored credential said={result.acdc.said}")
    return {"said": result.acdc.said, "received": received}


def send_grant(
    client: SignifyClient,
    *,
    issuer_name: str,
    recipient: str,
    creder,
    iserder,
    anc,
    sigs: list[str],
) -> dict | None:
    issuer_hab = client.identifiers().get(issuer_name)
    prefixer = coring.Prefixer(qb64=iserder.pre)
    seqner = coring.Seqner(sn=iserder.sn)
    acdc = app_signing.serialize(creder, prefixer, seqner, coring.Saider(qb64=iserder.said))
    iss = client.registries().serialize(iserder, anc)
    grant, grant_sigs, atc = client.ipex().grant(
        issuer_hab,
        recp=recipient,
        message="",
        acdc=acdc,
        iss=iss,
        anc=eventing.messagize(
            serder=anc,
            sigers=[csigning.Siger(qb64=sig) for sig in sigs],
        ),
        dt=helping.nowIso8601(),
    )
    return client.ipex().submitGrant(issuer_name, exn=grant, sigs=grant_sigs, atc=atc, recp=[recipient])


def submit_admit(client: SignifyClient, *, holder_name: str, issuer_prefix: str, grant_said: str) -> dict | None:
    holder_hab = client.identifiers().get(holder_name)
    admit, sigs, atc = client.ipex().admit(
        holder_hab,
        "",
        grant_said,
        issuer_prefix,
        helping.nowIso8601(),
    )
    return client.ipex().submitAdmit(holder_name, exn=admit, sigs=sigs, atc=atc, recp=[issuer_prefix])


def didwebs_did(setup: dict[str, Any], name: str) -> str:
    """Return a ready did:webs DID from a setup descriptor."""
    did = setup.get("dws")
    if not isinstance(did, str) or not did.startswith("did:webs:"):
        raise RuntimeError(f"did:webs setup for {name} did not return a ready DID: {setup!r}")
    return did


def wait_for_operation(client: SignifyClient, operation: dict, *, timeout: float = 180.0) -> dict:
    if operation.get("done"):
        return operation
    return client.operations().wait(
        operation,
        timeout=timeout,
        interval=0.5,
        max_interval=0.5,
        backoff=1.0,
    )


def wait_for_oobi(client: SignifyClient, name: str, *, role: str, timeout: float = 120.0) -> list[str]:
    return poll_until(
        lambda: client.oobis().get(name, role=role)["oobis"],
        ready=bool,
        timeout=timeout,
        interval=0.5,
        describe=f"{role} OOBI for {name}",
        retry_exceptions=(HTTPError,),
    )


def wait_for_grant_notification(client: SignifyClient, credential_said: str, timeout: float = 180.0) -> dict:
    """Wait for the IPEX grant that actually carries the expected credential."""
    inspected: set[str] = set()

    def _fetch():
        for note in reversed(client.notifications().list()["notes"]):
            if note["a"].get("r") != "/exn/ipex/grant" or note.get("r") is not False:
                continue
            note_id = note["i"]
            if note_id in inspected:
                continue
            exchange_said = note["a"]["d"]
            try:
                exchange = client.exchanges().get(exchange_said)
            except HTTPError:
                inspected.add(note_id)
                continue

            if credential_said in json.dumps(exchange):
                return note

            inspected.add(note_id)
            client.notifications().mark(note_id)
        return None

    note = poll_until(
        _fetch,
        ready=lambda value: value is not None,
        timeout=timeout,
        interval=0.5,
        describe=f"IPEX grant notification for credential {credential_said}",
    )
    client.notifications().mark(note["i"])
    return note


def wait_for_notification(client: SignifyClient, route: str, timeout: float = 180.0) -> dict:
    def _fetch():
        for note in reversed(client.notifications().list()["notes"]):
            if note["a"].get("r") == route and note.get("r") is False:
                return note
        return None

    note = poll_until(
        _fetch,
        ready=lambda value: value is not None,
        timeout=timeout,
        interval=0.5,
        describe=f"notification {route}",
    )
    client.notifications().mark(note["i"])
    return note


def wait_for_issued_credential(client: SignifyClient, issuer_aid: str, said: str) -> dict:
    return poll_until(
        lambda: next(
            (
                credential
                for credential in client.credentials().list(filter={"-i": issuer_aid})
                if credential["sad"]["d"] == said
            ),
            None,
        ),
        ready=lambda credential: credential is not None,
        timeout=180.0,
        interval=0.75,
        describe=f"issued credential {said}",
    )


def wait_for_credential(client: SignifyClient, said: str) -> dict:
    return poll_until(
        lambda: next(
            (
                credential
                for credential in client.credentials().list()
                if credential["sad"]["d"] == said
            ),
            None,
        ),
        ready=lambda credential: credential is not None,
        timeout=180.0,
        interval=0.75,
        describe=f"received credential {said}",
    )


def poll_until(fetch, *, ready, timeout: float, interval: float, describe: str, retry_exceptions=()):
    deadline = time.monotonic() + timeout
    last_value = None
    last_error = None
    while time.monotonic() < deadline:
        try:
            last_value = fetch()
        except retry_exceptions as ex:
            last_error = str(ex)
        else:
            if ready(last_value):
                return last_value
        time.sleep(interval)
    raise TimeoutError(f"timed out waiting for {describe}; last_value={last_value!r}; last_error={last_error!r}")


def source_edges(label: str, credential: dict, *, operator: str | None = None) -> dict:
    sad = credential["sad"]
    edge = {"n": sad["d"], "s": sad["s"]}
    if operator is not None:
        edge["o"] = operator
    return coring.Saider.saidify(sad={"d": "", label: edge})[1]


def le_rules() -> dict:
    return coring.Saider.saidify(
        sad={
            "d": "",
            "usageDisclaimer": {"l": LE_USAGE_DISCLAIMER},
            "issuanceDisclaimer": {"l": LE_ISSUANCE_DISCLAIMER},
        }
    )[1]


def blank_privacy_rules() -> dict:
    return coring.Saider.saidify(
        sad={
            "d": "",
            "usageDisclaimer": {"l": ""},
            "issuanceDisclaimer": {"l": ""},
            "privacyDisclaimer": {"l": ""},
        }
    )[1]


def random_passcode() -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(21))


if __name__ == "__main__":
    main()
