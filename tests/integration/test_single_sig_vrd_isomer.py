"""End-to-end live test for the single-sig ACDC-to-W3C VRD workflow.

This test is the flagship integration path for the repository. It launches the
local service stack, creates real KERI identifiers and credentials, derives a
W3C twin from the live VRD ACDC, and verifies the result through did:webs and
projected status.
"""

from __future__ import annotations

import json
from pathlib import Path

from vc_isomer.interop.external_verifiers import (
    ExternalVerifierConfig,
    ExternalVerifierProcess,
    assert_external_result_ok,
    requested_external_verifiers,
)
from vc_isomer.jwt import issue_vc_jwt, issue_vp_jwt
from vc_isomer.isomer_runtime import open_isomer_runtime
from vc_isomer.status import JsonFileStatusStore
from vc_isomer.verifier_client import verify_pair_doer, verify_vc_doer, verify_vp_doer
from .conftest import INTEGRATION_ROOT, W3C_ISOMER_ROOT

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
from .helpers import patched_home, run_doers_until, write_json


ASSETS = Path(__file__).resolve().parent / "assets"


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


def _write_vrd_data(stack: dict, state, subject_did: str) -> Path:
    """Write subject data for the VRD credential under test."""
    return write_json(
        Path(stack["temp_root"]) / "vrd-data.json",
        {
            "i": state.le_prefix,
            "AID": state.le_prefix,
            "DID": subject_did,
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


def _bootstrap_workflow_actors(live_stack: dict, state) -> None:
    """Initialize actors, delegation plumbing, and pairwise witness OOBIs."""
    state.geda_prefix = init_and_incept_single_sig(live_stack, state.geda)

    init_habery(live_stack, state.qvi)
    geda_oobi = witness_oobi(live_stack, state.geda)
    resolve_oobi(live_stack, state.qvi, alias=state.geda.alias, oobi=geda_oobi)
    create_delegation_proxy(live_stack, state.qvi)

    # QVI stays delegated from GEDA even in the simplified single-sig flow.
    state.qvi_prefix = create_delegated_qvi(live_stack, state.geda, state.qvi, state.geda_prefix)
    state.le_prefix = init_and_incept_single_sig(live_stack, state.le)

    resolve_pairwise_oobis(live_stack, [state.geda, state.qvi, state.le])


def _create_registries(live_stack: dict, state) -> None:
    """Create one TEL registry per actor for the live credential chain."""
    create_registry(live_stack, state.geda, registry_name="geda-registry", usage="QVI Credential Registry for GEDA")
    create_registry(live_stack, state.qvi, registry_name="qvi-registry", usage="LE and VRD Credential Registry for QVI")
    create_registry(live_stack, state.le, registry_name="le-registry", usage="VRD Authorization Registry for LE")


def _issue_qvi_chain_credentials(live_stack: dict, state) -> None:
    """Issue and admit the QVI and LE credentials that anchor the chain."""
    qvi_rules = _rules_path(live_stack, "qvi-rules.json")
    qvi_data = write_json(Path(live_stack["temp_root"]) / "qvi-data.json", {"LEI": "254900OPPU84GM83MG36"})
    state.qvi_credential_said = create_credential(
        live_stack,
        state.geda,
        registry_name="geda-registry",
        schema="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
        recipient_prefix=state.qvi_prefix,
        data_path=qvi_data,
        rules_path=qvi_rules,
    )
    qvi_grant_said = grant_credential(
        live_stack,
        state.geda,
        recipient_prefix=state.qvi_prefix,
        credential_said=state.qvi_credential_said,
    )
    assert (
        admit_grant(
            live_stack,
            state.qvi,
            expected_schema="EBfdlu8R27Fbx-ehrqwImnK-8Cm79sqbAQ4MmvEAYqao",
            grant_said=qvi_grant_said,
        )
        == state.qvi_credential_said
    )

    le_data = write_json(Path(live_stack["temp_root"]) / "le-data.json", {"LEI": "254900OPPU84GM83MG36"})
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
        data_path=le_data,
        rules_path=qvi_rules,
        edges_path=le_edge,
    )
    le_grant_said = grant_credential(
        live_stack,
        state.qvi,
        recipient_prefix=state.le_prefix,
        credential_said=state.le_credential_said,
    )
    assert (
        admit_grant(
            live_stack,
            state.le,
            expected_schema="ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY",
            grant_said=le_grant_said,
        )
        == state.le_credential_said
    )


def _issue_vrd_credentials(live_stack: dict, state) -> str:
    """Issue the VRD Auth and VRD credentials and return the QVI did:webs DID."""
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
    vrd_auth_grant_said = grant_credential(
        live_stack,
        state.le,
        recipient_prefix=state.qvi_prefix,
        credential_said=state.vrd_auth_said,
    )
    assert (
        admit_grant(
            live_stack,
            state.qvi,
            expected_schema="EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc",
            grant_said=vrd_auth_grant_said,
        )
        == state.vrd_auth_said
    )

    live_stack["launch_did_webs"](
        live_stack,
        name=state.qvi.name,
        alias=state.qvi.alias,
        passcode=state.qvi.passcode,
    )
    issuer_did = _did_for(live_stack, state.qvi_prefix)
    subject_did = _did_for(live_stack, state.le_prefix)

    vrd_data = _write_vrd_data(live_stack, state, subject_did)
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
    vrd_grant_said = grant_credential(
        live_stack,
        state.qvi,
        recipient_prefix=state.le_prefix,
        credential_said=state.vrd_said,
    )
    assert (
        admit_grant(
            live_stack,
            state.le,
            expected_schema="EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP",
            grant_said=vrd_grant_said,
        )
        == state.vrd_said
    )
    return issuer_did


def _validate_and_project_status(live_stack: dict, state, issuer_did: str) -> dict:
    """Validate the live ACDC chain and project VRD status for W3C consumers."""
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

    with patched_home(Path(live_stack["home"])):
        runtime = open_isomer_runtime(
            name=state.qvi.name,
            base="",
            alias=state.qvi.alias,
            passcode=state.qvi.passcode,
        )
        try:
            projection = runtime.projector.project_credential(state.vrd_said)
        finally:
            runtime.close()

    JsonFileStatusStore(live_stack["status_store"]).project_credential(projection.acdc, issuer_did, projection.state)
    return vrd


def _issue_and_verify_w3c_twin(live_stack: dict, state, *, issuer_did: str, vrd: dict) -> None:
    """Issue VC/VP JWT twins and verify them through Python and external sidecars."""
    def _verifier_context(doer) -> dict:
        return {
            "error": str(doer.error) if getattr(doer, "error", None) else None,
            "operation": getattr(doer, "operation", None),
        }

    def _assert_verifier_ok(doer, *, label: str) -> None:
        diagnostics = _verifier_context(doer)
        rendered = json.dumps(diagnostics, indent=2, sort_keys=True)
        assert doer.error is None, f"{label} failed\n{rendered}"
        assert doer.operation is not None, f"{label} missing operation\n{rendered}"
        assert doer.operation.get("done") is True, f"{label} never reached terminal state\n{rendered}"
        return rendered

    vp_audience = "https://verifier.example/isomer-e2e"
    vp_nonce = "isomer-e2e-nonce"

    with patched_home(Path(live_stack["home"])):
        runtime = open_isomer_runtime(name=state.qvi.name, base="", alias=state.qvi.alias, passcode=state.qvi.passcode)
        try:
            signer = runtime.signer
            verification_method = f"{issuer_did}#{signer.kid}"
            vc = runtime.projector.project_vc(
                said=state.vrd_said,
                issuer_did=issuer_did,
                status_base_url=live_stack["status_base_url"],
            )
            token, vc = issue_vc_jwt(vc, signer=signer, verification_method=verification_method)
            vp_token, _vp = issue_vp_jwt(
                [token],
                holder_did=issuer_did,
                signer=signer,
                audience=vp_audience,
                nonce=vp_nonce,
            )
        finally:
            runtime.close()

    vc_doer = verify_vc_doer(
        base_url=live_stack["verifier_base_url"],
        token=token,
        timeout=45.0,
        poll_interval=0.1,
    )
    run_doers_until(
        "verify VC-JWT twin",
        [vc_doer],
        ready=lambda: vc_doer.done,
        observe=lambda: {
            "vc_done": vc_doer.done,
            "vc_operation": vc_doer.operation,
            "vc_error": str(vc_doer.error) if vc_doer.error else None,
        },
    )

    assert vc["isomer"]["sourceCredentialSaid"] == state.vrd_said
    vc_rendered = _assert_verifier_ok(vc_doer, label="verify VC-JWT twin")
    assert vc_doer.operation["response"]["ok"] is True, vc_rendered
    assert vc_doer.operation["response"]["checks"]["issuerResolved"] is True, vc_rendered
    assert vc_doer.operation["response"]["checks"]["signatureValid"] is True, vc_rendered
    assert vc_doer.operation["response"]["checks"]["statusActive"] is True, vc_rendered

    pair_doer = verify_pair_doer(
        base_url=live_stack["verifier_base_url"],
        token=token,
        acdc=vrd,
        timeout=45.0,
        poll_interval=0.1,
    )
    run_doers_until(
        "verify isomer pair",
        [pair_doer],
        ready=lambda: pair_doer.done,
        observe=lambda: {
            "pair_done": pair_doer.done,
            "pair_operation": pair_doer.operation,
            "pair_error": str(pair_doer.error) if pair_doer.error else None,
        },
    )
    pair_rendered = _assert_verifier_ok(pair_doer, label="verify isomer pair")
    assert pair_doer.operation["response"]["ok"] is True, pair_rendered

    vp_doer = verify_vp_doer(
        base_url=live_stack["verifier_base_url"],
        token=vp_token,
        timeout=45.0,
        poll_interval=0.1,
    )
    run_doers_until(
        "verify VP-JWT presentation",
        [vp_doer],
        ready=lambda: vp_doer.done,
        observe=lambda: {
            "vp_done": vp_doer.done,
            "vp_operation": vp_doer.operation,
            "vp_error": str(vp_doer.error) if vp_doer.error else None,
        },
    )
    vp_rendered = _assert_verifier_ok(vp_doer, label="verify VP-JWT presentation")
    assert vp_doer.operation["response"]["ok"] is True, vp_rendered

    _verify_external_sidecars(
        live_stack,
        vc_token=token,
        vp_token=vp_token,
        audience=vp_audience,
        nonce=vp_nonce,
    )


def _verify_external_sidecars(
    live_stack: dict,
    *,
    vc_token: str,
    vp_token: str,
    audience: str,
    nonce: str,
) -> None:
    """Optionally verify live artifacts through external Node/Go sidecars."""
    for kind in requested_external_verifiers():
        config = ExternalVerifierConfig(
            kind=kind,
            repo_root=W3C_ISOMER_ROOT,
            resolver_url=live_stack["dws_resolver_url"],
            log_dir=Path(live_stack["log_root"]),
            host=live_stack["host"],
        )
        with ExternalVerifierProcess(config) as verifier:
            vc_result = verifier.verify_vc(vc_token)
            assert_external_result_ok(kind, "VC-JWT", vc_result, verifier.log_path)
            assert vc_result["checks"]["statusActive"] is True

            vp_result = verifier.verify_vp(vp_token, audience=audience, nonce=nonce)
            assert_external_result_ok(kind, "VP-JWT", vp_result, verifier.log_path)
            assert vp_result["checks"]["embeddedCredentialsVerified"] == 1


def test_single_sig_vrd_isomer_live(live_stack):
    """Exercise the full single-sig GEDA -> QVI -> LE -> VRD isomer flow.

    Phase model:
      1. stand up the live stack and deterministic actor sandboxes
      2. complete the KERI/ACDC issuance chain through grant/admit flow
      3. validate source ACDC chain state directly from local stores
      4. project the final VRD into W3C VC-JWT form
      5. submit long-running verifier operations and poll them to completion
    """
    state = default_workflow_state()
    _bootstrap_workflow_actors(live_stack, state)
    _create_registries(live_stack, state)
    _issue_qvi_chain_credentials(live_stack, state)
    issuer_did = _issue_vrd_credentials(live_stack, state)
    vrd = _validate_and_project_status(live_stack, state, issuer_did)
    _issue_and_verify_w3c_twin(live_stack, state, issuer_did=issuer_did, vrd=vrd)
