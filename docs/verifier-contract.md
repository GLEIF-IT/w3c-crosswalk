# Isomer Verifier Contract

This document defines the shared verifier contract across the Python verifier
and the Node and Go verifier sidecars.

## Authority Split

- Python Isomer is authoritative for TEL-aware verification and ACDC/W3C pair
  equivalence.
- Node and Go are external W3C acceptance gates. They prove that Isomer
  VC-JWT/VP-JWT artifacts are understandable by independent verifier stacks.
- No sidecar replaces KERI/TEL source-of-truth checks.

## Shared HTTP Surface

All verifier implementations expose:

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`

Node and Go also expose:

- `POST /verify/vp` with
  `{ "token": "<vp-jwt>", "audience"?: "...", "nonce"?: "..." }`

Python may use long-running operations internally. Node and Go may return
terminal results directly. CLI/client code must tolerate both result styles
instead of forcing one runtime model across all implementations.

## Shared Result Shape

Verifier responses use the Isomer result family:

- `ok`
- `kind`
- `errors`
- `warnings`
- `checks`
- `payload`
- optional `nested`

`checks` are semantic progress markers. They should describe meaningful
verification outcomes, not arbitrary logging detail.

## Required VC Checks

Each backend verifies the W3C-facing credential story:

- compact JWT shape and JOSE header
- registered JWT claims
- issuer DID resolution through `did-webs-resolver`
- JWT signature against resolved Ed25519 key material
- embedded `DataIntegrityProof` where the backend supports it
- projected `credentialStatus` where present

Python additionally verifies:

- source ACDC equivalence
- TEL-backed status semantics
- Isomer provenance linkage

## Required VP Checks

Each backend verifies:

- compact JWT shape and JOSE header
- holder DID resolution through `did-webs-resolver`
- VP JWT signature against resolved holder key material
- optional `audience` and `nonce` binding
- each nested VC-JWT through the backend's VC path

Go currently validates the VP JOSE signature and nested VC acceptance while VP
JSON-LD checks remain an active interop gap. See
`plans/isomer-go-vp-vc-go-jsonld-fix.md`.

## Webhook Contract

Successful top-level VC or VP verification may emit the dashboard webhook
event `isomer.presentation.verified.v1`.

Webhook payloads must not include raw JWTs. Verifier debug logs may include raw
JWTs only as local demo/debug observability, not as production posture.

## Dependency Contract

- Python consumes `keri`, `did-webs-resolver`, and `vlei` through package or
  pinned Git metadata.
- Node consumes `did-jwt-vc` through a pinned Git dependency and uses the
  in-repo `packages/webs-did-resolver` package.
- Go consumes `vc-go` through a pinned non-local Go module replacement.
- Default scripts, Dockerfiles, and compose files must not require sibling
  source checkouts.

## Non-Goals

- Do not implement TEL or ACDC pair verification in Node or Go.
- Do not make sidecars own issuer workflow, wallet workflow, or operation
  storage.
- Do not fetch arbitrary remote JSON-LD contexts during verification.
- Do not treat W3C status as a separate source of truth from KERI registry
  state.
