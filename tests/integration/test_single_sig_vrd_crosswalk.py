"""End-to-end live test for the single-sig ACDC-to-W3C VRD workflow.

This test is the flagship integration path for the repository. It launches the
local service stack, creates real KERI identifiers and credentials, derives a
W3C twin from the live VRD ACDC, and verifies the result through did:webs and
projected status.
"""

from __future__ import annotations

from pathlib import Path

from w3c_crosswalk.jwt import KeriHabSigner, issue_vc_jwt
from w3c_crosswalk.status import JsonFileStatusStore
from w3c_crosswalk.verifier import CrosswalkVerifier
from w3c_crosswalk.didwebs import DidWebsClient
from .conftest import INTEGRATION_ROOT, W3C_CROSSWALK_ROOT

from .kli_flow import (
    Actor,
    admit_grant,
    clone_credential_sad,
    create_credential,
    create_delegation_proxy,
    create_delegated_qvi,
    create_registry,
    default_workflow_state,
    grant_credential,
    init_habery,
    init_and_incept_single_sig,
    render_template,
    resolve_oobi,
    resolve_pairwise_oobis,
    saidify_json,
    validate_chain,
    witness_oobi,
)
from .helpers import patched_home, write_json


ASSETS = Path(__file__).resolve().parent / "assets"
QVI_RULES = Path("/Users/kbull/code/gleif-it/qvi-software/qvi-workflow/kli_only/acdc-info/rules/qvi-cred-rules.json")


def _did_for(stack: dict, aid: str) -> str:
    """Build the did:webs DID for a local AID in the active stack."""
    return stack["topology"].did_webs_did(aid)


def _write_vrd_auth_data(stack: dict, state) -> Path:
    """Write subject data for the VRD Auth credential under test."""
    return write_json(
        Path(stack["temp_root"]) / "vrd-auth-data.json",
        {
            "i": state.qvi_prefix,
            "AID": state.le_prefix,
            "DID": _did_for(stack, state.le_prefix),
            "HeadquartersAddress": "1 Market St, San Francisco, CA, US",
            "LegalName": "Example Legal Entity LLC",
        },
    )


def _write_vrd_data(stack: dict, state, issuer_did) -> Path:
    """Write subject data for the VRD credential under test."""
    return write_json(
        Path(stack["temp_root"]) / "vrd-data.json",
        {
            "i": state.le_prefix,
            "AID": state.le_prefix,
            "DID": issuer_did,
            "HeadquartersAddress": "1 Market St, San Francisco, CA, US",
            "LegalName": "Example Legal Entity LLC",
        },
    )


def _edge_from_template(stack: dict, template_name: str, output_name: str, replacements: dict[str, str]) -> Path:
    """Render and SAIDify an edge template for live credential issuance."""
    rendered = render_template(ASSETS / template_name, Path(stack["temp_root"]) / output_name, replacements)
    return saidify_json(stack, rendered)


def _rules_path(stack: dict, filename: str) -> Path:
    """Return a SAIDified rules file for live issuance."""
    return saidify_json(stack, Path(ASSETS) / filename)


def test_single_sig_vrd_crosswalk_live(live_stack):
    """Exercise the full single-sig GEDA -> QVI -> LE -> VRD crosswalk flow.

    Phase model:

    1. stand up the live stack and deterministic actor sandboxes
    2. complete the KERI/ACDC issuance chain through grant/admit flow
    3. validate source ACDC chain state directly from local stores
    4. project the final VRD into W3C VC-JWT form
    5. verify the W3C artifact through did:webs resolution and projected status
    """
    state = default_workflow_state()
    print(f"{INTEGRATION_ROOT}")
    print(f"{W3C_CROSSWALK_ROOT}")

    state.geda_prefix = init_and_incept_single_sig(live_stack, state.geda)
    init_habery(live_stack, state.qvi)
    resolve_oobi(live_stack, state.qvi, alias=state.geda.alias, oobi=witness_oobi(live_stack, state.geda))
    create_delegation_proxy(live_stack, state.qvi)

    # QVI stays delegated from GEDA even in the simplified single-sig flow.
    state.qvi_prefix = create_delegated_qvi(live_stack, state.geda, state.qvi, state.geda_prefix)
    state.le_prefix = init_and_incept_single_sig(live_stack, state.le)

    resolve_pairwise_oobis(live_stack, [state.geda, state.qvi, state.le])

    create_registry(live_stack, state.geda, registry_name="geda-registry", usage="QVI Credential Registry for GEDA")
    create_registry(live_stack, state.qvi, registry_name="qvi-registry", usage="LE and VRD Credential Registry for QVI")
    create_registry(live_stack, state.le, registry_name="le-registry", usage="VRD Authorization Registry for LE")

    print("Creating QVI credential")
    qvi_cred_data = write_json(Path(live_stack["temp_root"]) / "qvi-data.json", {"LEI": "254900OPPU84GM83MG36"})
    state.qvi_credential_said = create_credential(
        live_stack,
        state.geda,
        registry_name="geda-registry",
        schema="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        recipient_prefix=state.qvi_prefix,
        data_path=qvi_cred_data,
        rules_path=QVI_RULES,
    )
    print("Granting QVI credential")
    qvi_grant_said = grant_credential(
        live_stack,
        state.geda,
        recipient_prefix=state.qvi_prefix,
        credential_said=state.qvi_credential_said,
    )
    print("Admitting QVI credential")
    assert (
        admit_grant(
            live_stack,
            state.qvi,
            expected_schema="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
            grant_said=qvi_grant_said,
        )
        == state.qvi_credential_said
    )

    print("Creating LE credential")
    le_cred_data = write_json(Path(live_stack["temp_root"]) / "le-data.json", {"LEI": "254900OPPU84GM83MG36"})
    le_edge = _edge_from_template(
        live_stack,
        "le-edge-template.json",
        "le-edge.json",
        {"__QVI_CREDENTIAL_SAID__": state.qvi_credential_said},
    )
    state.le_credential_said = create_credential(
        live_stack,
        state.qvi,
        registry_name="qvi-registry",
        schema="ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
        recipient_prefix=state.le_prefix,
        data_path=le_cred_data,
        rules_path=QVI_RULES,
        edges_path=le_edge,
    )
    print("Granting LE credential from QVI")
    le_grant_said = grant_credential(
        live_stack,
        state.qvi,
        recipient_prefix=state.le_prefix,
        credential_said=state.le_credential_said,
    )
    print("Admitting LE credential as LE")
    assert (
        admit_grant(
            live_stack,
            state.le,
            expected_schema="ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
            grant_said=le_grant_said,
        )
        == state.le_credential_said
    )

    print("Creating VRD Auth credential")
    vrd_auth_data = _write_vrd_auth_data(live_stack, state)
    vrd_auth_rules = _rules_path(live_stack, "vrd-auth-rules.json")
    vrd_auth_edge = _edge_from_template(
        live_stack,
        "vrd-auth-edge-template.json",
        "vrd-auth-edge.json",
        {"__LE_CREDENTIAL_SAID__": state.le_credential_said},
    )
    state.vrd_auth_said = create_credential(
        live_stack,
        state.le,
        registry_name="le-registry",
        schema="EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc",
        recipient_prefix=state.qvi_prefix,
        data_path=vrd_auth_data,
        rules_path=vrd_auth_rules,
        edges_path=vrd_auth_edge,
    )
    print("Granting VRD Auth credential from LE to QVI")
    vrd_auth_grant_said = grant_credential(
        live_stack,
        state.le,
        recipient_prefix=state.qvi_prefix,
        credential_said=state.vrd_auth_said,
    )
    print("Admitting VRD Auth credential as QVI")
    assert (
        admit_grant(
            live_stack,
            state.qvi,
            expected_schema="EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc",
            grant_said=vrd_auth_grant_said,
        )
        == state.vrd_auth_said
    )

    print("Creating VRD credential as QVI")
    print("creating did:webs DID")
    live_stack["launch_did_webs"](live_stack, name=state.qvi.name, alias=state.qvi.alias,
                                  passcode=state.qvi.passcode)
    issuer_did = _did_for(live_stack, state.qvi_prefix)

    vrd_data = _write_vrd_data(live_stack, state, issuer_did)
    vrd_rules = _rules_path(live_stack, "vrd-rules.json")
    vrd_edge = _edge_from_template(
        live_stack,
        "vrd-edge-template.json",
        "vrd-edge.json",
        {"__LE_CREDENTIAL_SAID__": state.le_credential_said},
    )
    state.vrd_said = create_credential(
        live_stack,
        state.qvi,
        registry_name="qvi-registry",
        schema="EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP",
        recipient_prefix=state.le_prefix,
        data_path=vrd_data,
        rules_path=vrd_rules,
        edges_path=vrd_edge,
    )
    print("Granting VRD credential as QVI to LE")
    vrd_grant_said = grant_credential(
        live_stack,
        state.qvi,
        recipient_prefix=state.le_prefix,
        credential_said=state.vrd_said,
    )
    print("Admitting VRD credential as LE")
    assert (
        admit_grant(
            live_stack,
            state.le,
            expected_schema="EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP",
            grant_said=vrd_grant_said,
        )
        == state.vrd_said
    )

    print("Validating Credential Chain")
    qvi_credential = clone_credential_sad(live_stack, state.qvi, said=state.qvi_credential_said)
    le_credential = clone_credential_sad(live_stack, state.le, said=state.le_credential_said)
    vrd_auth = clone_credential_sad(live_stack, state.qvi, said=state.vrd_auth_said)
    vrd = clone_credential_sad(live_stack, state.le, said=state.vrd_said)

    validate_chain(
        qvi_credential=qvi_credential,
        le_credential=le_credential,
        vrd_auth=vrd_auth,
        vrd=vrd,
        qvi_prefix=state.qvi_prefix,
        le_prefix=state.le_prefix,
    )


    JsonFileStatusStore(live_stack["status_store"]).project_acdc(vrd, issuer_did)

    print("issuing VC JWT")
    with patched_home(Path(live_stack["home"])):
        signer = KeriHabSigner.open(name=state.qvi.name, base="", alias=state.qvi.alias, passcode=state.qvi.passcode)
        try:
            token, vc = issue_vc_jwt(vrd, issuer_did=issuer_did, status_base_url=live_stack["status_base_url"], signer=signer)
        finally:
            signer.close()

    print("Verifying VC JWT")
    verifier = CrosswalkVerifier(
        resolver=DidWebsClient(live_stack["dws_resolver_url"]),
    )
    vc_result = verifier.verify_vc_jwt(token)
    pair_result = verifier.verify_crosswalk_pair(vrd, token)

    assert vc["crosswalk"]["sourceCredentialSaid"] == state.vrd_said
    assert vc_result.ok is True
    assert vc_result.checks["issuerResolved"] is True
    assert vc_result.checks["signatureValid"] is True
    assert vc_result.checks["statusActive"] is True
    assert pair_result.ok is True
