# isomer-node

Minimal TypeScript verifier sidecar for external W3C acceptance.

This app verifies Isomer VCDM 1.1 VC-JWT and VP-JWT artifacts without importing
the Python verifier. It proves that an independent Node verifier stack can
understand the same artifacts emitted and accepted by Isomer.

For shared verifier semantics, see `../../docs/verifier-contract.md`.

## Scope

Owns:

- VC-JWT and VP-JWT envelope verification through `did-jwt-vc`
- `did:webs` resolution through `packages/webs-did-resolver`
- embedded `DataIntegrityProof` verification
- projected `credentialStatus` fetch/check
- optional dashboard webhook emission for successful top-level verification

Does not own:

- source ACDC equivalence checks
- TEL-aware verification
- issuer, holder, or wallet workflow
- long-running operation storage
- arbitrary remote JSON-LD context fetching

## Source Map

- `src/main.ts` - Effection entrypoint.
- `src/commands/serve.ts` - CLI argument parsing.
- `src/server.ts` - Hono HTTP app.
- `src/verifier.ts` - main verification pipeline.
- `src/did-jwt-vc.ts` - `did-jwt-vc` wrappers.
- `src/data-integrity.ts` - embedded proof verification.
- `src/status.ts` - W3C status fetch/check.
- `src/local-contexts.ts` - pinned JSON-LD context loader.
- `src/webhook.ts` - dashboard webhook events.

## Setup

```bash
cd apps/isomer-node
make sync
make check
make test
```

From the repo root, `make external-node-sync` and `make external-node-check`
delegate to these app-local targets.

`make sync` installs sidecar dependencies, builds the pinned `did-jwt-vc` Git
dependency, and builds the in-repo `webs-did-resolver` package. The local
`webs-did-resolver` dependency should eventually be replaced by an NPM package.

## Manual Run

```bash
cd apps/isomer-node
make serve
```

Override defaults with `ISOMER_HOST`, `ISOMER_PORT`, `ISOMER_RESOLVER_URL`, or
`ISOMER_RESOURCE_ROOT`.

Build the local container image:

```bash
cd apps/isomer-node
make image
```

The image target keeps the repo root as Docker context so the current local
`packages/webs-did-resolver` dependency is available.

Optional webhook settings:

- `--webhook-url` / `ISOMER_WEBHOOK_URL`
- `--verifier-id` / `ISOMER_VERIFIER_ID`, default `isomer-node`
- `--verifier-label` / `ISOMER_VERIFIER_LABEL`

## API

- `GET /healthz`
- `POST /verify/vc` with `{ "token": "<vc-jwt>" }`
- `POST /verify/vp` with
  `{ "token": "<vp-jwt>", "audience"?: "...", "nonce"?: "..." }`
- `GET /operations`
- `GET /operations/{name}`

Verify submissions return `202` operation stubs. Poll the operation resource
for the shared Isomer verifier result shape. This live operation surface is
what KERIA and the headless holder E2E harness validate.
