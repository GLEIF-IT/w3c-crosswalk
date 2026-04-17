# isomer-node

Minimal TypeScript verifier sidecar for external W3C acceptance.

This app verifies Isomer VCDM 1.1 VC-JWT and VP-JWT artifacts without importing
the Python verifier. It exists to answer one maintainer question quickly:

Can an independent Node verifier stack understand the same live Isomer
artifacts that the Python verifier emits and accepts?

The sidecar is intentionally narrow. It is not a production replacement for the
Python Isomer verifier, and it does not attempt TEL-aware ACDC/W3C pair
equivalence checks. Its job is external W3C-side acceptance.

## Purpose And Non-Goals

Purpose:

- verify VC-JWT and VP-JWT artifacts emitted by Isomer,
- use the same `did:webs` and status HTTP seams that the live Isomer stack
  exposes,
- prove external W3C acceptance without importing Python verifier code.

Non-goals:

- replace the Python verifier as the authoritative Isomer verifier,
- perform source ACDC equivalence checks,
- own issuer workflow, long-running operation storage, or broader wallet logic,
- fetch arbitrary remote JSON-LD contexts at runtime.

## Architecture

The sidecar is intentionally small:

- `src/main.ts`
  Effection entrypoint for the CLI process.
- `src/commands/serve.ts`
  CLI argument parsing and handoff into the server runtime.
- `src/server.ts`
  Hono HTTP app with `/healthz`, `/verify/vc`, and `/verify/vp`.
- `src/verifier.ts`
  Main verification pipeline and result shaping.
- `src/did-jwt-vc.ts`
  Thin wrappers around `did-jwt-vc` for VC-JWT and VP-JWT envelope validation.
- `src/did-resolver.ts`
  Adapter from Isomer `did:webs` resolver responses into the JWK-oriented shape
  expected by the Node JWT stack.
- `src/data-integrity.ts`
  Explicit embedded Data Integrity proof verification.
- `src/status.ts`
  W3C credential status fetch and revocation check.
- `src/local-contexts.ts`
  Local JSON-LD context pinning for deterministic canonicalization.
- `src/types.ts`
  HTTP request, config, and verifier result contracts.

## Verification Model

Verification proceeds in layers:

1. `did-jwt-vc` verifies the VC-JWT or VP-JWT envelope and JWT signature.
2. `src/did-resolver.ts` resolves issuer or presenter key state through the
   Isomer `did:webs` HTTP resolver and adapts KERI-style verification methods
   into JWK-shaped material when the Node stack requires it.
3. `src/data-integrity.ts` verifies the embedded
   `DataIntegrityProof` / `eddsa-rdfc-2022` block explicitly, because a valid
   VC-JWT envelope does not by itself prove the embedded proof block is intact.
4. `src/status.ts` checks W3C credential status separately from cryptographic
   verification, because revocation is lifecycle state, not a signature
   property.
5. VP verification recursively verifies each nested VC-JWT with the same VC
   pipeline.

This means the Node sidecar validates the W3C-facing story, while the Python
verifier remains the place for Isomer-specific TEL-aware and pair-verification
semantics.

## Dependency Boundaries

- `did-jwt-vc`
  Owns VC-JWT and VP-JWT envelope validation and JWT signature verification.
- `did-resolver`
  Defines the resolver interface used by `did-jwt-vc`.
- local `DidWebsResolver`
  Adapts Isomer resolver HTTP responses into that interface.
- local `LocalContextLoader`
  Pins the JSON-LD contexts used by Isomer artifacts so canonicalization stays
  deterministic and offline.
- local status fetch/check helpers
  Treat revocation as a separate projection check layered on top of crypto
  validation.

## CLI

Setup:

```bash
make external-node-sync
make external-node-check
```

Run manually:

```bash
npm --prefix apps/isomer-node run serve -- \
  --host 127.0.0.1 \
  --port 8787 \
  --resolver-url http://127.0.0.1:7678/1.0/identifiers \
  --resource-root "$PWD"
```

Flags:

- `--resolver-url` required; base URL of the Isomer `did:webs` resolver
- `--host` optional; defaults to `127.0.0.1`
- `--port` optional; defaults to `8787`
- `--resource-root` optional; defaults to the current working directory and is
  used to locate Isomer JSON-LD context resources under
  `src/vc_isomer/resources/contexts`

## HTTP API

Routes:

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `POST /verify/vp` with
  `{ "token": "<vp-jwt>", "audience"?: "...", "nonce"?: "..." }`

The response shape mirrors Isomer verifier results:

- `ok`
- `kind`
- `errors`
- `warnings`
- `checks`
- `payload`
- optional `nested`

`checks` are semantic progress markers, not just logging detail:

- VC checks report envelope validity, signature validity, embedded Data
  Integrity proof validity, and active status.
- VP checks report envelope validity, signature validity, and how many embedded
  credentials verified successfully.

## Relationship To Python Isomer Verifier

The Python verifier remains authoritative for:

- TEL-aware verification semantics,
- Isomer-specific ACDC/W3C pair equivalence,
- broader runtime orchestration in the Python stack.

The Node sidecar is intentionally narrower:

- it verifies W3C artifacts through independent Node libraries,
- it consumes `did:webs` and status HTTP seams exposed by the live Isomer
  stack,
- it proves external acceptance but does not replace Python-side source-truth
  checks.

## Maintainer Notes

### `did:webs` normalization

The Node JWT stack is JWK-oriented. Isomer resolver output can include
`publicKeyMultibase` and KERI-style method forms, so `src/did-resolver.ts`
normalizes those methods into JWK-shaped verification material when needed.
This is one of the highest-risk interop seams in the sidecar.

### Local JSON-LD contexts

The sidecar intentionally loads only a pinned local set of JSON-LD contexts:

- `https://www.w3.org/2018/credentials/v1`
- `https://w3id.org/security/data-integrity/v2`
- `https://www.gleif.org/contexts/isomer-v1.jsonld`

This avoids remote context fetches during verification and keeps
canonicalization reproducible for Isomer artifacts.

### Embedded Data Integrity proof verification

`did-jwt-vc` validates the JWT envelope. It does not validate the embedded
proof block that Isomer carries inside the VC payload. The sidecar therefore
verifies the `DataIntegrityProof` explicitly using local canonicalization and
the verification method resolved from `did:webs`.

### Status checks

Status checks are deliberately separate from cryptographic checks. The status
endpoint is an Isomer-owned projection of TEL truth, so revocation is handled
as a lifecycle decision after JWT and embedded-proof verification succeed.
