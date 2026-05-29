# W3C VRD Isomer Roadmap

## Summary

Isomer already has the core live path:

- KERI-habitat-backed GEDA -> QVI -> LE -> VRD Auth -> VRD issuance
- VRD ACDC projection into a VCDM 1.1 W3C VC
- VC-JWT/VP-JWT issuance with embedded KERI-backed Data Integrity proofs
- Python verification with TEL and ACDC/W3C pair semantics
- Node and Go W3C acceptance sidecars

The remaining roadmap is key rotation, revocation, OpenID4VP, and demo UI
surfaces. `did-webs-resolver` remains the mandatory key-state dependency.

## Current Baseline

Completed:

1. Foundation, profile, and fixtures.
2. Live ACDC issuance spine.
3. VRD W3C projection.
4. `did:webs` resolution and verifier bridge.
5. Python, Node, and Go verifier acceptance baseline.

Baseline invariants:

- Isomer owns W3C projection, Python verification, status projection, CLI
  orchestration, and verifier-facing demo surfaces.
- `did-webs-resolver` owns DID and latest-key-state resolution.
- Python remains authoritative for TEL-aware verification and ACDC/W3C pair
  equivalence.
- Node and Go remain external W3C acceptance gates.

## Next Phases

### 6. Key Rotation

Add issuer and presenter key-rotation acceptance while preserving the same
VRD ACDC -> W3C verification story.

Acceptance:

- Python, Node, and Go resolve and validate against latest key state.
- Artifacts checked against superseded or stale keys fail.
- The verifier contract in `docs/verifier-contract.md` remains stable.

### 7. TEL-Backed Revocation

Project TEL revocation state into the W3C `credentialStatus` surface and
reject revoked credentials across all verifier implementations.

Acceptance:

- Source VRD ACDC is revoked in TEL.
- W3C status projection updates.
- Python, Node, and Go reject the same revoked artifact.
- W3C status remains a projection, not a separate authority.

### 8. OpenID4VP

Implement the verifier-initiated OpenID4VP flow described in
`plans/verifier-initiated-openid4vp-cli-parity.md`.

Acceptance:

- Python reference backend creates standards-shaped request objects.
- Wallet-facing `request_uri` and `response_uri` exist.
- `direct_post`, `state`, `aud`, and `nonce` semantics are enforced.
- CLI/client code hides backend-specific async differences.

### 9. Demo UI Surfaces

Build the minimal holder/presenter and verifier UI surfaces after the Python
OpenID4VP reference backend is stable.

Acceptance:

- Verifier UI creates requests, renders QR/deep-link material, and shows
  presentation status.
- Mobile/holder app loads one or more VC-JWTs and responds to OpenID4VP
  requests.
- UI work targets Python first, then Node and Go after backend parity lands.

## Deferred

- KF Wallet and other wallet integrations.
- Production status architecture beyond the current projection service.
- Production admin authorization.
- General-purpose ecosystem-grade W3C verifier behavior.

## Test Plan

- Current baseline: live single-sig integration with Python, Node, and Go.
- Phase 6: latest-key success and stale-key failure across all verifiers.
- Phase 7: TEL revoke, status reproject, and rejection across all verifiers.
- Phase 8: standards-shaped request/session tests, wrong-state/aud/nonce
  rejections, and backend-tolerant CLI tests.
- Phase 9: Python-first UI tests before cross-backend UI tests.

## Assumptions

- The active verifier set is Python, Node, and Go.
- VCDM 1.1 VC-JWT/VP-JWT remains the primary W3C artifact format for this
  roadmap.
- Real runtime and integration signing continues to use live KERI habitats.
