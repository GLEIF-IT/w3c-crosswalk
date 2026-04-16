# W3C VRD Isomer Profile

This document defines the current Isomer profile for projecting authoritative
VRD ACDC credentials into VCDM 1.1 JSON-LD credentials, signing them with
KERI-backed Data Integrity proofs, and enveloping them as VC-JWTs.

For the live-stack runtime and integration mental model behind this profile, see
[`integration-maintainer-guide.md`](integration-maintainer-guide.md).

## Core Rules

- ACDC, KEL, and TEL state remain the source of truth.
- The W3C credential is an interoperability projection, not a new authority.
- The projected VC uses VCDM 1.1: `https://www.w3.org/2018/credentials/v1`
  and `issuanceDate`.
- The JSON-LD VC includes the Isomer context and the Data Integrity context.
- VC-JWT uses VCDM 1.1 registered claims: `iss`, `sub`, `jti`, `iat`, `nbf`,
  and `vc`.
- VP-JWT uses `iss`, `jti`, `iat`, optional `aud`/`nonce`, and `vp`.
- The embedded VC proof is `DataIntegrityProof` with `eddsa-rdfc-2022`.
- The compact JWT signature and embedded proof are both backed by the live KERI
  habitat signer.
- Signature verification must resolve key state through `did-webs-resolver`.
- Revocation is projected through an Isomer `credentialStatus` resource backed
  by KERI TEL state.
- Deterministic demo signers are not allowed.

## Supported Source Schemas

- `VRDAuthorizationCredential`:
  `EFiYsVADHXcn1BZirDRH301Rm12301povihg5UMIYkfc`
- `VRDCredential`:
  `EAyv2DLocYxJlPrWAfYBuHWDpjCStdQBzNLg0-3qQ-KP`
- Referenced LE credential schema:
  `ENPXp1vQzRF6JwIuS-mp2U8Uf1MoADoP_GqQ62VsDZWY`

## Credential Shape

- `issuer`: canonical `did:webs` of the LE signer producing the W3C twin.
- `id`: `urn:said:${source_said}`.
- `credentialSubject.id`: subject DID from the source attributes block.
- `credentialSubject.AID`: subject KERI AID from source `AID`.
- `credentialSubject.legalName`: source `LegalName`.
- `credentialSubject.address`: structured `PostalAddress` parsed from
  `HeadquartersAddress`.
- `credentialSubject.legalEntityCredential`: source LE edge as `{ id, type,
  schema }`, with `id` represented as `urn:said:${source_le_said}` for JSON-LD.
- `credentialSchema.id`: `https://www.gleif.org/schemas/isomer/v1/vrd-credential.json`.
- `credentialSchema.type`: `JsonSchemaValidator2018`.
- `credentialStatus.id`: `${status_base_url}/status/${source_said}`.
- `credentialStatus.type`: `KERICredentialStatus`.
- `credentialStatus.statusRegistryId`: source TEL registry SAID.
- `termsOfUse`: mapped from ACDC rule text.
- `isomer`: signed provenance metadata for source credential, schema, issuer,
  registry, legal-entity edge, and profile version.

## Validation Rules

- JOSE header `alg` must be `EdDSA`.
- JOSE header `typ` must be `JWT`.
- JWT registered claims must match the embedded VC or VP.
- `issuer` and `holder` must resolve through `did-webs-resolver`.
- `kid` must resolve to an Ed25519 verification method.
- VC-JWT signature must verify against the resolved JWK.
- Embedded Data Integrity proof must verify after URDNA2015/RDFC
  canonicalization with the strict local context loader.
- `credentialStatus` must resolve to an active record.
- Pair verification must confirm source ACDC equivalence for subject, status,
  schema, type, and Isomer provenance fields.
