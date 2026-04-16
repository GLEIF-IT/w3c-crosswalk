# Fixes

This file records important correctness fixes made while moving from the legacy
`w3c-signer` prototype to `w3c-crosswalk`.

`w3c-signer` remains useful as historical reference material, but it is not the
production contract. The entries below are the places where `w3c-crosswalk`
intentionally corrected or tightened behavior instead of preserving legacy
behavior.

## Data Integrity And JSON-LD

- `create_verify_data(...)` now returns `proofConfigHash + transformedDocumentHash`,
  which matches the `eddsa-rdfc-2022` cryptosuite. Legacy `w3c-signer` returned
  the reverse order (`credential_hash + proof_config_hash`), which was
  self-consistent locally but not spec-aligned.
- Proof-option canonicalization now injects the VC `@context` into the proof
  configuration before URDNA2015 normalization. This is required for reliable
  JSON-LD to RDF expansion and canonicalization: without an active `@context`,
  proof fields such as `created`, `verificationMethod`, `proofPurpose`, and
  `cryptosuite` do not expand into the intended RDF terms.
- Without that `@context`, different proof configurations can collapse to the
  same empty RDF dataset and stop binding proof metadata into the signature at
  all. That is both a correctness bug and a security bug.
- JSON-LD canonicalization now fails closed with
  `JsonLdCanonicalizationError` and carries phase-specific labels such as
  `unsecured document` and `proof configuration`.
- Signing and verification use a strict local context loader. We do not fetch
  remote contexts live during proof generation or verification.
- Unknown contexts are fatal. We do not fall back to an empty or minimal
  context document.

## Context And Vocabulary

- Isomer uses `https://www.gleif.org/contexts/isomer-v1.jsonld` as the active
  profile vocabulary instead of depending on legacy
  `https://www.gleif.org/contexts/vlei-v1.jsonld`.
- The allowed JSON-LD contexts are intentionally fixed to the current Isomer
  profile contract rather than discovered dynamically at verification time.

## JSON-LD Identifier Safety

- W3C `id` fields that carry ACDC SAIDs are emitted as `urn:said:<SAID>`, not
  as bare SAID strings. Bare SAIDs are not absolute IRIs and can break or drift
  during JSON-LD to RDF processing and URDNA2015 canonicalization.
- This applies to both top-level VC identifiers and nested identifiers such as
  `credentialSubject.legalEntityCredential.id`.

## VCDM Profile Corrections

- The current Isomer target is VCDM 1.1, so projected credentials use
  `issuanceDate` instead of `validFrom`.
- The W3C projection step is separated from proof attachment. The unsigned VC
  transposition no longer pretends to consume `verification_method`; that input
  belongs to the proof and JWT issuance layers.
- `did:webs` issuer and `kid` values are canonicalized before they become wire
  artifacts so raw host-port forms do not drift into emitted VC-JWT and proof
  material.

## Subject Mapping And Schema Discipline

- `credentialSubject.AID` now comes from source `AID` only. The legacy fallback
  to `LE` was stale for the currently supported schemas and hid schema drift.
- Schema and context semantics are treated as vetted protocol contracts, not as
  artifacts to discover and trust dynamically at verification time.

## Verification Material Interop

- Verification accepts both `publicKeyJwk` and `publicKeyMultibase` when
  resolving DID verification methods for Data Integrity proofs.
- This keeps Isomer aligned with W3C Data Integrity and Multikey-oriented DID
  tooling without changing the proof model itself: `proof.verificationMethod`
  remains a DID URL pointer, and the actual key material still comes from DID
  dereferencing.
