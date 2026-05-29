# W3C VRD Isomer Profile

This is the current Isomer profile for projecting authoritative VRD ACDC
credentials into VCDM 1.1 JSON-LD credentials, adding KERI-backed Data
Integrity proofs, and enveloping the result as VC-JWT or VP-JWT artifacts.

For verifier boundaries, see `verifier-contract.md`. For live-stack
orchestration, see `integration-maintainer-guide.md`.

## Core Rules

- KEL state is authoritative for identifier state.
- TEL/registry state is authoritative for credential issuance and revocation.
- W3C credentials and presentations are interoperability projections, not new
  sources of authority.
- Runtime and integration signing must use live KERI habitat signers.
- Deterministic demo signers are not allowed.
- Signature verification must resolve key state through `did-webs-resolver`.
- Unknown JSON-LD contexts fail closed; verification must not fetch arbitrary
  remote contexts at runtime.

## Supported Source Schemas

- `VRDAuthorizationCredential`:
  `EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc`
- `VRDCredential`:
  `EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP`
- Referenced LE credential schema:
  `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY`

## Credential Shape

- `@context`: W3C 2018 credentials context, Isomer context, and Data Integrity
  context.
- `type`: VCDM 1.1 credential type plus the Isomer VRD type.
- `issuer`: canonical `did:webs` of the signer producing the W3C twin.
- `id`: `urn:said:${source_said}`.
- `issuanceDate`: VCDM 1.1 issuance timestamp.
- `credentialSubject.id`: subject DID from the source attributes block.
- `credentialSubject.AID`: subject KERI AID from source `AID`.
- `credentialSubject.legalName`: source `LegalName`.
- `credentialSubject.address`: structured `PostalAddress` parsed from
  `HeadquartersAddress`.
- `credentialSubject.legalEntityCredential`: source LE edge as `{ id, type,
  schema }`, with `id` represented as `urn:said:${source_le_said}`.
- `credentialSchema.id`:
  `https://www.gleif.org/schemas/isomer/v1/vrd-credential.json`.
- `credentialSchema.type`: `JsonSchemaValidator2018`.
- `credentialStatus.id`: `${status_base_url}/status/${source_said}`.
- `credentialStatus.type`: `KERICredentialStatus`.
- `credentialStatus.statusRegistryId`: source TEL registry SAID.
- `termsOfUse`: mapped from ACDC rule text.
- `isomer`: signed provenance metadata for source credential, schema, issuer,
  registry, legal-entity edge, and profile version.

## JWT Shape

- VC-JWT uses VCDM 1.1 `vc` claim.
- VP-JWT uses VCDM 1.1 `vp` claim.
- JOSE header `alg` must be `EdDSA`.
- JOSE header `typ` must be `JWT`; `vc+jwt` and `vp+jwt` are result families,
  not JOSE header values.
- `iss`, `sub`, `jti`, `iat`, and `nbf` must mirror the embedded VC where
  applicable.
- VP `aud` and `nonce` bind to verifier request values when present.

## Data Integrity Rules

- The embedded VC proof is `DataIntegrityProof` with `eddsa-rdfc-2022`.
- Verify data is `proofConfigHash + transformedDocumentHash`.
- Proof-option canonicalization injects the VC `@context` before URDNA2015
  normalization so proof metadata expands into RDF terms.
- JSON-LD `id` values derived from ACDC SAIDs use `urn:said:<SAID>`, not bare
  SAID strings.
- The active profile context is
  `https://www.gleif.org/contexts/isomer-v1.jsonld`.
- DID verification methods may expose `publicKeyJwk` or `publicKeyMultibase`.
  Both are accepted when they resolve to Ed25519 key material.

## Validation Rules

- Issuer and holder DIDs resolve through `did-webs-resolver`.
- `kid` resolves to an Ed25519 verification method.
- VC-JWT and VP-JWT signatures verify against resolved key material.
- Embedded VC Data Integrity proof verifies after strict local
  canonicalization.
- `credentialStatus` resolves to an active record.
- Pair verification confirms source ACDC equivalence for subject, status,
  schema, type, and Isomer provenance fields.
