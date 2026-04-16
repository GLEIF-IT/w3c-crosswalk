# ADR-002 - Use `publicKeyMultibase` for Data Integrity Verification Interoperability

## Status

Implemented

## Context

Isomer verifies `DataIntegrityProof` signatures by reading the proof's
`verificationMethod` DID URL, resolving the corresponding DID document, finding
the referenced verification method, and extracting usable public-key material.
The proof does not embed the public key bytes directly.

The W3C Data Integrity specification defines `verificationMethod` located in a 
proof as a URL that points to the location of the public-key data used to verify 
the proof, and states that this data is stored in a controlled identifier 
document that contains the full verification-method description.

This means verification depends on DID dereferencing before cryptographic proof
verification can even begin:

```json
{
  "type": "DataIntegrityProof",
  "cryptosuite": "eddsa-rdfc-2022",
  "verificationMethod": "did:webs:example.com:dws:issuer#key-1",
  "proofPurpose": "assertionMethod",
  "proofValue": "z..."
}
```

The dereferenced DID document may express the same Ed25519 verification key in
more than one standards-recognized form. Two relevant examples are:

```json
{
  "id": "did:webs:example.com:dws:issuer#key-1",
  "type": "JsonWebKey",
  "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." }
}
```

```json
{
  "id": "did:webs:example.com:dws:issuer#key-1",
  "type": "Multikey",
  "publicKeyMultibase": "z..."
}
```

The practical verification flow is therefore:

```python
method_id = vc["proof"]["verificationMethod"]
did_doc = resolver.resolve(controller_did(method_id))
method = find_verification_method(did_doc, method_id)
public_key = method["publicKeyJwk"] or method["publicKeyMultibase"]
verify_data_integrity_proof(vc, public_key)
```

This example illustrates four facts that matter to Isomer:

1. The proof does not embed the public key.
2. The `verificationMethod` value is only a pointer.
3. DID dereferencing is required before verification can start.
4. The verifier must be able to consume the verification-material format that
   the DID/W3C tooling actually returns.

`publicKeyJwk` is a normal, standards-recognized verification-material format,
and Isomer supports it. However, JWK alone is insufficient as the only assumed
format.

The reasons are concrete:

- [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/) identifies
  both `JsonWebKey` and `Multikey` as verification-method types and explicitly
  treats them as verification-material formats.
- [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/) also says a
  verification method must not carry multiple verification-material properties
  for the same key material, such as `publicKeyJwk` and
  `publicKeyMultibase` at the same time.
- [W3C DID Document Property Extensions](https://www.w3.org/TR/did-extensions-properties/)
  registers `publicKeyMultibase` and deprecates older properties like
  `publicKeyBase58` in favor of `publicKeyMultibase` or `publicKeyJwk`.
- The [did:key Method Specification](https://w3c-ccg.github.io/did-key-spec/)
  allows implementations to choose `JsonWebKey` or `Multikey` as the
  public-key output format and shows `Multikey`/`publicKeyMultibase` as a
  normal emitted verification-method shape.
- The TypeScript `did-jwt` tooling used by Isomer's Node sidecar accepts
  `publicKeyMultibase` and `Multikey` directly in
  [`../apps/isomer-node/node_modules/did-jwt/src/util.ts`](../apps/isomer-node/node_modules/did-jwt/src/util.ts).

These standards and tooling behaviors mean a verifier that assumes JWK-only
verification material would fail whenever the resolved DID method is
Multikey-native or whenever a standards-compliant implementation chooses
`publicKeyMultibase` as its public representation.

Isomer's current code already reflects this interoperability requirement:

- Python verification prefers `publicKeyJwk` but falls back to
  `publicKeyMultibase` in
  [`../src/vc_isomer/data_integrity.py`](../src/vc_isomer/data_integrity.py).
- DID normalization synthesizes `publicKeyMultibase` from a JWK when needed in
  [`../src/vc_isomer/didwebs.py`](../src/vc_isomer/didwebs.py).
- The Node sidecar normalizes JWK and Multikey verification methods in
  [`../apps/isomer-node/src/did-resolver.ts`](../apps/isomer-node/src/did-resolver.ts).
- The vendored `did-jwt` library consumes `publicKeyMultibase` in
  [`../apps/isomer-node/node_modules/did-jwt/src/util.ts`](../apps/isomer-node/node_modules/did-jwt/src/util.ts).

References:

- [W3C Verifiable Credential Data Integrity 1.0](https://www.w3.org/TR/vc-data-integrity/)
- [W3C Controlled Identifiers v1.0](https://www.w3.org/TR/cid-1.0/)
- [W3C DID Document Property Extensions](https://www.w3.org/TR/did-extensions-properties/)
- [did:key Method Specification](https://w3c-ccg.github.io/did-key-spec/)
- [decentralized-identity/did-jwt](https://github.com/decentralized-identity/did-jwt)

## Decision

Treat `publicKeyMultibase` as a first-class verification-material format for
Data Integrity proof verification.

Specifically:

- Isomer must continue accepting either `publicKeyJwk` or
  `publicKeyMultibase` when verifying a resolved verification method.
- `publicKeyJwk` remains supported, but it must not be treated as the only
  representation the verifier can rely on.
- `publicKeyMultibase` is used for verification interoperability, not because
  JWK is invalid.
- Isomer may convert between key formats internally when interfacing with local
  signers or cryptographic libraries, but external semantics stay tied to the
  verification-method representation returned by DID/W3C tooling.
- `publicKeyMultibase` is not part of the proof payload itself; it is part of
  the dereferenced verification method that the proof points to.

## Consequences

Isomer can verify proofs against DID documents that expose verification
material as `JsonWebKey` or `Multikey`.

Python and Node verification paths stay aligned on the same interoperability
goal instead of assuming a single key-material representation.

The verifier remains compatible with DID tooling that emits Multikey-first
verification methods, including `did:key`-style documents and libraries that
consume `publicKeyMultibase` directly.

Local signer exports continue exposing a verifier-friendly Ed25519 Multikey
form so the runtime can interoperate cleanly with non-JWK-first tooling.

This ADR does not change the proof shape, JWT handling, issuer DID policy, or
the requirement to dereference DID documents for verification.

## Other Options Considered

Assume `publicKeyJwk` is always present and treat `publicKeyMultibase` as
unnecessary.

That option was rejected because the relevant W3C/DID ecosystem does not
guarantee JWK-only verification material, and controlled identifier documents
must not express the same key material using both `publicKeyJwk` and
`publicKeyMultibase` at the same time just to satisfy a verifier's preference.
